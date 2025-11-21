import boto3
import time
import traceback
import json
from typing import List, Dict, Optional, Tuple, Any
from loguru import logger
from botocore.exceptions import ClientError

def internal_create_rds_client(region:str, with_express_configuration:bool):
    if with_express_configuration:
        region = 'us-east-2'
        endpoint_url = f'https://rds-preview.{region}.amazonaws.com'
        return boto3.client('rds', region_name=region, endpoint_url=endpoint_url)
    else:
        return boto3.client('rds', region_name=region)


def internal_get_cluster_properties(
    cluster_identifier: str,
    region: str,
    with_express_configuration: bool = False
) -> Dict[str, Any]:
    """
    Retrieve RDS cluster properties from AWS.
    
    Args:
        cluster_identifier: RDS cluster identifier
        region: AWS region (e.g., 'us-east-1')
        with_express_configuration: Use express RDS client config (default: False)
    
    Returns:
        Dict[str, Any]: Cluster properties from AWS RDS API
    
    Raises:
        ValueError: If cluster_identifier or region is empty
        ClientError: If AWS API call fails (cluster not found, access denied, etc.)
        NoCredentialsError: If AWS credentials not configured
    
    Example:
        >>> props = internal_get_cluster_properties('my-cluster', 'us-east-1')
        >>> print(props['Status'])
    """
    # Input validation
    if not cluster_identifier or not region:
        raise ValueError("cluster_identifier and region are required")
    
    logger.info(f"Fetching properties for cluster '{cluster_identifier}' in '{region}' "
                f"with_express_configuration:{with_express_configuration}")
    
    try:
        rds_client = internal_create_rds_client(region, with_express_configuration)
        response = rds_client.describe_db_clusters(
            DBClusterIdentifier=cluster_identifier
        )
        
        # Safely extract cluster properties
        clusters = response.get('DBClusters', [])
        if not clusters:
            raise ValueError(
                f"Cluster '{cluster_identifier}' not found in region '{region}'"
            )
        
        cluster_properties = clusters[0]
        
        # Log summary only
        logger.info(
            f"Retrieved cluster '{cluster_identifier}': "
            f"Status={cluster_properties.get('Status')}, "
            f"Engine={cluster_properties.get('Engine')}"
        )
        
        # Full properties at debug level
        logger.debug(
            f"Cluster properties: {json.dumps(cluster_properties, indent=2, default=str)}"
        )
        
        return cluster_properties
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(
            f"AWS error fetching cluster '{cluster_identifier}': "
            f"{error_code} - {e.response['Error']['Message']}"
        )
        raise
    except Exception as e:
        logger.error(f"Error fetching cluster properties: {type(e).__name__}: {e}")
        raise


def internal_create_express_cluster(cluster_identifier: str) -> Dict[str, Any]:

    """
    Create an Aurora PostgreSQL Express cluster.
    
    Args:
        cluster_identifier: Unique name for the cluster
    
    Returns:
        Dict[str, Any]: Cluster properties
    
    Raises:
        ValueError: If cluster_identifier is invalid
        ClientError: If AWS API call fails
    """

    rds_client = internal_create_rds_client(region='us-east-2', with_express_configuration=True) 

    # Add default tags
    tags = []
    tags.append({'Key': 'CreatedBy', 'Value': 'MCP'})

    logger.info(f'Create express clsuter with cluster_identifier:{cluster_identifier}')

    try:
        cluster_create_start_time = time.time()
        rds_client.create_db_cluster(
            DBClusterIdentifier=cluster_identifier,
            Engine='aurora-postgresql',
            Tags=tags,
            WithExpressConfiguration=True)

        result = rds_client.describe_db_clusters(
            DBClusterIdentifier=cluster_identifier
        )['DBClusters'][0]
        
        logger.info("Waiting for cluster to become available...")
        waiter = rds_client.get_waiter('db_cluster_available')
        waiter.wait(
            DBClusterIdentifier=cluster_identifier,
            WaiterConfig={
                'Delay': 1,
                'MaxAttempts': 1800
            }
        )
        
        cluster_create_stop_time = time.time()
        elapsed_time = cluster_create_stop_time - cluster_create_start_time
        logger.info(f"Express Cluster {cluster_identifier} created successfully and took {elapsed_time:.2f} seconds")
        return result
    
    except ClientError as e:
        logger.error(
            f"AWS error creating express cluster '{cluster_identifier}': "
            f"{e.response['Error']['Code']} - {e.response['Error']['Message']}"
        )
        raise
    except Exception as e:
        logger.error(f"Error creating cluster '{cluster_identifier}': {type(e).__name__}: {e}")
        raise


def internal_create_serverless_cluster(
    region: str,
    cluster_identifier: str,
    engine_version: str,
    database_name: str,
    master_username: str = 'postgres',
    min_capacity: float = 0.5,
    max_capacity: float = 4,
    enable_cloudwatch_logs: bool = True
) -> Dict[str, Any]:
    """
    Create an Aurora PostgreSQL cluster with a single writer instance.
    Credentials are automatically managed by AWS Secrets Manager.
    
    Args:
        region: region of the cluster
        cluster_identifier: Name of the Aurora cluster
        engine_version: PostgreSQL engine version (e.g., '15.3', '14.7')
        database_name: Name of the default database
        master_username: Master username for the database
        min_capacity: minimum ACU capacity
        max_capacity: maximum ACU capacity
        enable_cloudwatch_logs: Enable CloudWatch logs export
        
    Returns:
        Dictionary containing cluster information and secret ARN
    """

    if not region:
        raise ValueError('region is required')
    if not cluster_identifier:
        raise ValueError('cluster_identifier is required')
    if not engine_version:
        raise ValueError('engine_version is required')
    if not database_name:
        raise ValueError('database_name is required')
    
    rds_client = internal_create_rds_client(region=region, with_express_configuration=False)

    
    # Add default tags
    tags = []
    tags.append({'Key': 'CreatedBy', 'Value': 'MCP'})
    
    # Prepare CloudWatch logs
    enable_cloudwatch_logs_exports = []
    if enable_cloudwatch_logs:
        enable_cloudwatch_logs_exports = ['postgresql']
    
    try:
        # Create the Aurora cluster
        logger.info(f"Creating Aurora PostgreSQL cluster:{cluster_identifier} "
                    f"region:{region} engine_version:{engine_version} database_name:{database_name} "
                    f"master_username:{master_username}")
        
        cluster_params = {
            'DBClusterIdentifier': cluster_identifier,
            'Engine': 'aurora-postgresql',
            'EngineVersion': engine_version,
            'MasterUsername': master_username,
            'DatabaseName': database_name,
            'ManageMasterUserPassword': True,  # Enable Secrets Manager integration
            'Tags': tags,
            'DeletionProtection': False,  # Set to True for production
            'CopyTagsToSnapshot': True,
            'EnableHttpEndpoint': True,  # Enable for Data API if needed
            'EnableCloudwatchLogsExports': enable_cloudwatch_logs_exports
        }

        cluster_params['ServerlessV2ScalingConfiguration'] = {
            'MinCapacity': min_capacity,
            'MaxCapacity': max_capacity
        }

        # Create the cluster
        cluster_create_start_time = time.time()
        cluster_response = rds_client.create_db_cluster(**cluster_params)
        
        cluster_info = cluster_response['DBCluster']
        logger.info(f"Cluster {cluster_identifier} creation call started successfully. Status: {cluster_info['Status']}")
        
        # Wait for cluster to be available
        logger.info("Waiting for cluster to become available...")
        waiter = rds_client.get_waiter('db_cluster_available')
        waiter.wait(
            DBClusterIdentifier=cluster_identifier,
            WaiterConfig={
                'Delay': 5,
                'MaxAttempts': 120
            }
        )

        logger.info(f"Cluster {cluster_identifier} is now available")
        cluster_create_stop_time = time.time()
        elapsed_time = cluster_create_stop_time - cluster_create_start_time
        logger.info(f"Cluster creation {cluster_identifier} took {elapsed_time:.2f} seconds")
        
        # Create the writer instance
        instance_identifier = f"{cluster_identifier}-instance-1"
        logger.info(f"Creating writer instance: {instance_identifier}")
        
        instance_params = {
            'DBInstanceIdentifier': instance_identifier,
            'DBInstanceClass': 'db.serverless',
            'Engine': 'aurora-postgresql',
            'DBClusterIdentifier': cluster_identifier,
            'PubliclyAccessible': False,  # Set to True if needed
            'Tags': tags,
            'CopyTagsToSnapshot': True
        }
        
        instance_create_start_time = time.time()
        instance_response = rds_client.create_db_instance(**instance_params)
        
        logger.info(f"Writer instance {instance_identifier} created successfully")
        
        # Wait for instance to be available
        logger.info(f"Waiting for instance {instance_identifier} to become available...")
        instance_waiter = rds_client.get_waiter('db_instance_available')
        instance_waiter.wait(
            DBInstanceIdentifier=instance_identifier,
            WaiterConfig={
                'Delay': 1, # check every  seconds
                'MaxAttempts': 1800 # Try up to 1800 time = 30 mins
            }
        )

        logger.info(f"Instance {instance_identifier} is now available")
        instance_create_stop_time = time.time()
        elapsed_time = instance_create_stop_time - instance_create_start_time
        logger.info(f"Instance creation {instance_identifier} took {elapsed_time:.2f} seconds")
        
        # Get the final cluster details including the secret ARN
        final_cluster = rds_client.describe_db_clusters(
            DBClusterIdentifier=cluster_identifier
        )['DBClusters'][0]
          
        return final_cluster
        
    except ClientError as e:
        logger.error(
            f"AWS error creating serverless cluster '{cluster_identifier}': "
            f"{e.response['Error']['Code']} - {e.response['Error']['Message']}"
        )
        raise
    except Exception as e:
        logger.error(f"Error creating serverless cluster '{cluster_identifier}': {type(e).__name__}: {e}")
        raise


def setup_aurora_iam_policy_for_current_user(
    db_user: str,
    cluster_resource_id: str,
    cluster_region: str
) -> Optional[str]:
    """
    Create or update IAM policy for Aurora access.
    Maintains one policy per user, adding new clusters as they're created.
    
    Args:
        db_user: PostgreSQL username (must have rds_iam role granted in database)
        cluster_resource_id: The DBI resource ID (e.g., 'cluster-ABCD123XYZ')
        cluster_region: AWS region where the Aurora cluster is located
    
    Returns:
        Policy ARN if successful, None otherwise
    
    Raises:
        ValueError: If running as assumed role or invalid identity
        boto3 exceptions: For AWS API errors
    """
    
    # Validate inputs
    if not db_user or not isinstance(db_user, str):
        raise ValueError("db_user must be a non-empty string")
    if not cluster_resource_id or not isinstance(cluster_resource_id, str):
        raise ValueError("cluster_resource_id must be a non-empty string")
    if not cluster_region or not isinstance(cluster_region, str):
        raise ValueError("cluster_region must be a non-empty string")
    
    # Initialize clients
    sts = boto3.client('sts')
    iam = boto3.client('iam')
    
    # 1. Get current IAM user identity
    try:
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        arn = identity['Arn']
        user_id = identity['UserId']
        
        logger.info(f"Current Identity:")
        logger.info(f"  ARN: {arn}")
        logger.info(f"  Account: {account_id}")
        logger.info(f"  UserID: {user_id}")
        
    except Exception as e:
        logger.error(f"❌ Error getting caller identity: {e}")
        raise
    
    # 2. Extract username from ARN
    current_user = None
    
    if ':user/' in arn:
        # Standard IAM user: arn:aws:iam::123456789012:user/username
        current_user = arn.split(':user/')[-1].split('/')[-1]  # Handle paths like user/path/username
        logger.info(f"  Type: IAM User")
        logger.info(f"  Username: {current_user}")
        
    elif ':assumed-role/' in arn:
        # Assumed role: arn:aws:sts::123456789012:assumed-role/role-name/session-name
        role_name = arn.split(':assumed-role/')[-1].split('/')[0]
        logger.info(f"  Type: Assumed Role")
        logger.info(f"  Role Name: {role_name}")
        raise ValueError(
            f"Cannot attach policy to assumed role session.\n"
            f"You are running as assumed role '{role_name}'.\n"
            f"Please attach the policy directly to the role '{role_name}' instead:\n"
            f"  iam.attach_role_policy(RoleName='{role_name}', PolicyArn=policy_arn)"
        )
        
    elif ':federated-user/' in arn:
        # Federated user
        logger.error(f"  Type: Federated User")
        raise ValueError(
            "Cannot attach policies to federated users.\n"
            "Please use the parent IAM user or role instead."
        )
        
    elif ':root' in arn:
        # Root user
        logger.error(f"  Type: Root User")
        raise ValueError(
            "Cannot (and should not) attach policies to root user.\n"
            "Please use an IAM user instead."
        )
        
    else:
        raise ValueError(f"Unexpected ARN format: {arn}")
    
    # 3. Prepare new resource ARN
    # Policy name is per user only (not per region or cluster)
    policy_name = f'AuroraIAMAuth-{db_user}'
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    
    new_resource_arn = f"arn:aws:rds-db:{cluster_region}:{account_id}:dbuser:{cluster_resource_id}/{db_user}"
    
    logger.info(f"\nPolicy Configuration:")
    logger.info(f"  Policy Name: {policy_name}")
    logger.info(f"  New Resource: {new_resource_arn}")
    logger.info(f"  Cluster Region: {cluster_region}")
    logger.info(f"  Cluster Resource ID: {cluster_resource_id}")
    
    # 4. Create or update policy
    policy_created = False
    
    try:
        # Try to get existing policy
        existing_policy = iam.get_policy(PolicyArn=policy_arn)
        logger.info(f"\n✓ Policy already exists: {policy_name}")
        
        # Get current policy document
        policy_version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=existing_policy['Policy']['DefaultVersionId']
        )
        
        current_doc = policy_version['PolicyVersion']['Document']
        current_resources = current_doc['Statement'][0]['Resource']
        
        # Normalize to list (could be string or list)
        if isinstance(current_resources, str):
            current_resources = [current_resources]
        
        logger.info(f"  Current resources in policy: {len(current_resources)}")
        for idx, res in enumerate(current_resources, 1):
            logger.info(f"    {idx}. {res}")
        
        # Check if new resource already exists
        if new_resource_arn in current_resources:
            logger.info(f"\n✓ Cluster already included in policy - no update needed")
        else:
            # Add new resource to the list
            current_resources.append(new_resource_arn)
            logger.info(f"\n→ Adding new cluster to policy...")
            
            # Create updated policy document
            updated_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "rds-db:connect",
                        "Resource": current_resources
                    }
                ]
            }
            
            # Handle AWS policy version limits (max 5 versions per policy)
            versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
            logger.info(f"  Current policy versions: {len(versions)}/5")
            
            if len(versions) >= 5:
                # Find oldest non-default version to delete
                non_default_versions = [v for v in versions if not v['IsDefaultVersion']]
                if non_default_versions:
                    oldest_version = sorted(non_default_versions, key=lambda v: v['CreateDate'])[0]
                    logger.info(f"  Deleting oldest version: {oldest_version['VersionId']} (created {oldest_version['CreateDate']})")
                    iam.delete_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=oldest_version['VersionId']
                    )
            
            # Create new policy version
            new_version = iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(updated_doc, indent=2),
                SetAsDefault=True
            )
            
            logger.info(f"✓ Successfully updated policy")
            logger.info(f"  New version: {new_version['PolicyVersion']['VersionId']}")
            logger.info(f"  Total resources now: {len(current_resources)}")
            
    except iam.exceptions.NoSuchEntityException:
        # Policy doesn't exist - create new one
        logger.info(f"\nPolicy doesn't exist, creating new policy...")
        
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "rds-db:connect",
                    "Resource": [new_resource_arn]  # Start with single resource in array
                }
            ]
        }
        
        try:
            policy_response = iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document, indent=2),
                Description=f'IAM authentication for Aurora PostgreSQL user {db_user} across all clusters'
            )
            policy_arn = policy_response['Policy']['Arn']
            policy_created = True
            logger.info(f"✓ Successfully created new policy: {policy_name}")
            logger.info(f"  Policy ARN: {policy_arn}")
            
        except iam.exceptions.EntityAlreadyExistsException:
            # Race condition: policy was created between our check and create
            logger.info(f"✓ Policy was just created by another process")
            
        except Exception as e:
            logger.error(f"\n❌ Error creating policy: {e}")
            raise
    
    except Exception as e:
        logger.error(f"\n❌ Error checking/updating policy: {e}")
        trace_msg = traceback.format_exc()
        logger.error(f"Traceback: {trace_msg}")
        raise
    
    # 5. Attach policy to current user (if not already attached)
    try:
        # Check if policy is already attached
        attached_policies = iam.list_attached_user_policies(UserName=current_user)
        already_attached = any(
            p['PolicyArn'] == policy_arn 
            for p in attached_policies['AttachedPolicies']
        )
        
        if already_attached:
            logger.info(f"\n✓ Policy already attached to user: {current_user}")
        else:
            iam.attach_user_policy(
                UserName=current_user,
                PolicyArn=policy_arn
            )
            logger.info(f"\n✓ Successfully attached policy to user: {current_user}")
        
        # Display summary of all attached policies
        logger.info(f"\nAttached policies for user {current_user}:")
        attached_policies = iam.list_attached_user_policies(UserName=current_user)
        for policy in attached_policies['AttachedPolicies']:
            marker = "  → " if policy['PolicyArn'] == policy_arn else "    "
            logger.info(f"{marker}{policy['PolicyName']}")
        
        return policy_arn
        
    except iam.exceptions.NoSuchEntityException:
        logger.error(f"\n❌ Error: User '{current_user}' not found")
        raise
        
    except iam.exceptions.LimitExceededException:
        logger.error(f"\n❌ Error: Managed policy limit exceeded for user '{current_user}'")
        logger.error("Maximum 10 managed policies can be attached to a user")
        logger.error("Consider using inline policies or consolidating existing policies")
        raise
        
    except Exception as e:
        logger.error(f"\n❌ Error attaching policy to user: {e}")
        trace_msg = traceback.format_exc()
        logger.error(f"Traceback: {trace_msg}")
        raise