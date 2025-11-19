import boto3
import time
import traceback
import json
from typing import List, Dict, Optional, Tuple
from loguru import logger
from botocore.exceptions import ClientError

def internal_get_cluster_properties(cluster_identifier: str, region: str, 
        with_express_configuration: bool = False) -> Dict:
    
    rds_client = None
    if with_express_configuration:
        region = 'us-east-2'
        endpoint_url = f'https://rds-preview.{region}.amazonaws.com'
        rds_client = boto3.client('rds', region_name=region, endpoint_url=endpoint_url)
    else:
        rds_client = boto3.client('rds', region_name=region)        

    response = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_identifier)
    cluster_properties= response['DBClusters'][0]
    
    logger.info(
        f"Cluster properties for {cluster_identifier}:\n"
        f"{json.dumps(cluster_properties, indent=2, default=str)}"
    )
    
    return cluster_properties


def internal_delete_express_cluster(cluster_identifier: str) -> None:

    region = 'us-east-2'
    endpoint_url = f'https://rds-preview.{region}.amazonaws.com'
    rds_client = boto3.client('rds', region_name=region, endpoint_url=endpoint_url)

    CREATED_BY_TAG = 'CreatedBy'
    CREATED_BY_VALUE = 'MCP'

    logger.info(f'Entered internal_delete_express_cluster with cluster_identifier:{cluster_identifier}')

    try:
        resp = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_identifier)
        cluster = resp["DBClusters"][0]
        status = resp["DBClusters"][0]["Status"]
        arn = cluster["DBClusterArn"]

        tag_resp = rds_client.list_tags_for_resource(ResourceName=arn)
        tags = tag_resp.get("TagList", [])
        created_by_mcp = False
        if tags:
            for tag in tags:
                if tag['Key'] == CREATED_BY_TAG and tag['Value'] == CREATED_BY_VALUE:
                    created_by_mcp = True
        logger.info(f"Found express cluster '{cluster_identifier}' (status={status})")

        if not created_by_mcp:
            logger.error('can only delete cluster created by MCP tool')
            raise PermissionError('You can only delete cluster created by MCP tool. cluster_id:{cluster_id}')
        

        params = {
            "DBClusterIdentifier": cluster_identifier,
            "SkipFinalSnapshot": True,
        }

        rds_client.delete_db_cluster(**params)
    except Exception as e:
        logger.error(f"Error deleting express cluster '{cluster_identifier}': {e}")
        raise

    logger.info(f"Express cluster {cluster_identifier} deleted")


def internal_create_express_cluster(cluster_identifier: str) -> Dict:

    region = 'us-east-2'
    endpoint_url = f'https://rds-preview.{region}.amazonaws.com'
    rds_client = boto3.client('rds', region_name=region, endpoint_url=endpoint_url)

    # Add default tags
    tags = []
    tags.append({'Key': 'CreatedBy', 'Value': 'MCP'})

    logger.info(f'Entered internal_create_express_cluster with cluster_identifier:{cluster_identifier}')

    try:
        cluster_create_start_time = time.time()
        rds_client.create_db_cluster(
            DBClusterIdentifier=cluster_identifier,
            Engine='aurora-postgresql',
            Tags=tags,
            WithExpressConfiguration=True)

        # Get the final cluster details including the secret ARN
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
        logger.info(f"Express Cluster {cluster_identifier} created successfully")
        logger.info(f"Express Cluster creation {cluster_identifier} took {elapsed_time:.2f} seconds")
        return result
    
    except Exception as e:
        logger.error(f"internal_create_express_cluster failed with error: {str(e)}")
        trace_msg = traceback.format_exc()
        logger.error(f"Trace:{trace_msg}")
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
) -> Dict:
    """
    Create an Aurora PostgreSQL cluster with a single writer instance.
    Credentials are automatically managed by AWS Secrets Manager.
    
    Args:
        region: region of the cluster
        cluster_identifier: Name of the Aurora cluster
        engine_version: PostgreSQL engine version (e.g., '15.3', '14.7')
        with_express_configuration: Create the cluster with express configuration
        database_name: Name of the default database
        master_username: Master username for the database
        min_capacity: minimum ACU capacity
        max_capacity: maximum ACU capacity
        enable_cloudwatch_logs: Enable CloudWatch logs export
        
    Returns:
        Dictionary containing cluster information and secret ARN
    """

    rds_client = boto3.client('rds', region_name=region)
    
    # Add default tags
    tags = []
    tags.append({'Key': 'CreatedBy', 'Value': 'MCP'})
    
    # Prepare CloudWatch logs
    enable_cloudwatch_logs_exports = []
    if enable_cloudwatch_logs:
        enable_cloudwatch_logs_exports = ['postgresql']
    
    try:
        # Create the Aurora cluster
        logger.info(f"Creating Aurora PostgreSQL cluster: {cluster_identifier}")
        
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
                'Delay': 1,
                'MaxAttempts': 1800
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

        resource_id = final_cluster['DbClusterResourceId']
        setup_aurora_iam_policy_for_current_user(db_user=master_username, cluster_resource_id=resource_id, cluster_region=region)
          
        return final_cluster
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"Error creating Aurora cluster: {error_code} - {error_message}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        trace_msg = traceback.format_exc()
        logger.error(f"Trace:{trace_msg}")
        raise

def internal_delete_cluster(
    region: str,
    cluster_id: str) -> None:
    
    """
    Delete an existing Amazon RDS (Aurora) cluster.

    Args:
        cluster_id: The DB cluster identifier.

    Raises:
        ClientError: If deletion fails or the cluster is not found.
        ValueError: If final snapshot identifier is missing when required.
    """

    CREATED_BY_TAG = 'CreatedBy'
    CREATED_BY_VALUE = 'MCP'

    rds = boto3.client("rds", region_name=region)

    # Check cluster exists
    try:
        resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        cluster = resp["DBClusters"][0]
        status = resp["DBClusters"][0]["Status"]
        arn = cluster["DBClusterArn"]

        tag_resp = rds.list_tags_for_resource(ResourceName=arn)
        tags = tag_resp.get("TagList", [])
        created_by_mcp = False
        if tags:
            for tag in tags:
                if tag['Key'] == CREATED_BY_TAG and tag['Value'] == CREATED_BY_VALUE:
                    created_by_mcp = True
        logger.info(f"Found cluster '{cluster_id}' (status={status})")

        if not created_by_mcp:
            logger.error('can only delete cluster created by MCP tool')
            raise PermissionError('You can only delete cluster created by MCP tool. cluster_id:{cluster_id}')
        
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBClusterNotFoundFault":
            logger.error(f"Cluster '{cluster_id}' does not exist.")
            return
        raise

    # Delete all DB instances in the cluster ---
    # Aurora clusters list members in DBClusterMembers
    members = cluster.get("DBClusterMembers", [])
    instance_ids = [m["DBInstanceIdentifier"] for m in members]

    if instance_ids:
        logger.info("Deleting %d instance(s): %s", len(instance_ids), ", ".join(instance_ids))

    for inst_id in instance_ids:
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=inst_id,
                SkipFinalSnapshot=True,            # change to False + FinalDBSnapshotIdentifier if you require snapshots
                DeleteAutomatedBackups=True
            )
            logger.info("Deletion of instance '%s' initiated.", inst_id)
        except ClientError as e:
            # If instance already gone, continue; otherwise re-raise
            code = e.response["Error"]["Code"]
            if code in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
                logger.info("Instance '%s' already deleted.", inst_id)
            else:
                logger.error("Error deleting instance '%s': %s", inst_id, e)
                raise

    # Wait for all instances to be fully deleted ---
    if instance_ids:
        logger.info("Waiting for instances to be deleted...")
    remaining = set(instance_ids)

    while remaining:
        done = []
        for inst_id in list(remaining):
            try:
                rds.describe_db_instances(DBInstanceIdentifier=inst_id)
                # still exists
            except ClientError as e:
                if e.response["Error"]["Code"] in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
                    logger.info("Instance '%s' deleted.", inst_id)
                    done.append(inst_id)
                else:
                    raise
        for d in done:
            remaining.discard(d)
        if remaining:
            time.sleep(5)

    # Delete cluster
    try:
        params = {
            "DBClusterIdentifier": cluster_id,
            "SkipFinalSnapshot": True,
        }

        rds.delete_db_cluster(**params)
        logger.info(f"Deletion of cluster '{cluster_id}' initiated.")
    except ClientError as e:
        logger.error(f"Error deleting cluster '{cluster_id}': {e}")
        raise

    # Poll for deletion

    logger.info("Waiting for cluster to be deleted...")
    while True:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
            time.sleep(5)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBClusterNotFoundFault":
                logger.info("\nCluster deleted successfully.")
                break
            else:
                raise

def get_rds_cluster_and_secret_arn(cluster_id: str, region: str) -> Tuple[str, Optional[str]]:
    """Return the Cluster ARN and the associated Secrets Manager ARN (if any)."""
    rds = boto3.client("rds", region_name=region)
    resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)

    if not resp["DBClusters"]:
        raise ValueError(f"No cluster found for identifier: {cluster_id}")

    cluster = resp["DBClusters"][0]

    # Cluster ARN
    cluster_arn = cluster["DBClusterArn"]

    # Secret ARN (if cluster is managed with Secrets Manager)
    secret_arn = None
    if "MasterUserSecret" in cluster and cluster["MasterUserSecret"]:
        secret_arn = cluster["MasterUserSecret"].get("SecretArn")

    return cluster_arn, secret_arn

def setup_aurora_iam_policy_for_current_user(
    db_user: str,
    cluster_resource_id: str,
    cluster_region
) -> Optional[str]:
    """
    Create IAM policy for Aurora access and attach it to the current IAM user.
    
    Args:
        db_user: PostgreSQL username (must have rds_iam role granted in database)
        cluster_resource_id: The DBI resource ID (e.g., 'cluster-ABCD123XYZ')
        region: AWS region where the Aurora cluster is located
    
    Returns:
        Policy ARN if successful, None otherwise
    
    Raises:
        ValueError: If running as assumed role or invalid identity
        boto3 exceptions: For AWS API errors
    """
    
    # Validate inputs
    if not db_user or not isinstance(db_user, str):
        raise ValueError("db_user must be a non-empty string")
    
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
    
    # 3. Create IAM policy document
    policy_name = f'AuroraIAMAuth-{db_user}'
    resource_arn = f"arn:aws:rds-db:{cluster_region}:{account_id}:dbuser:{cluster_resource_id}/{db_user}"
    
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds-db:connect",
                "Resource": resource_arn
            }
        ]
    }
    
    logger.info(f"\nPolicy Details:")
    logger.info(f"  Name: {policy_name}")
    logger.info(f"  Resource: {resource_arn}")
    
    # 4. Create or get existing policy
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    
    try:
        # Check if policy exists
        existing_policy = iam.get_policy(PolicyArn=policy_arn)
        logger.info(f"\n✓ Policy already exists")
        
        # Optional: Check if policy document matches
        policy_version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=existing_policy['Policy']['DefaultVersionId']
        )
        existing_doc = policy_version['PolicyVersion']['Document']
        
        if existing_doc != policy_document:
            logger.info(f"⚠️  Warning: Existing policy document differs from expected")
            
    except iam.exceptions.NoSuchEntityException:
        # Create new policy
        try:
            policy_response = iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document, indent=2),
                Description=f'Allow IAM authentication to Aurora PostgreSQL as user {db_user}'
            )
            policy_arn = policy_response['Policy']['Arn']
            logger.info(f"\n✓ Created new policy: {policy_name}")
            
        except iam.exceptions.EntityAlreadyExistsException:
            # Race condition: policy was created between check and create
            logger.info(f"\n✓ Policy was just created: {policy_name}")
            
        except Exception as e:
            logger.error(f"\n❌ Error creating policy: {e}")
            raise
    
    except Exception as e:
        logger.error(f"\n❌ Error checking policy: {e}")
        raise
    
    # 5. Attach policy to current user
    try:
        # Check if already attached
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
        
        # Display all attached policies
        logger.info(f"\nAll attached policies for {current_user}:")
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
        logger.error("Consider using inline policies or consolidating existing policies")
        raise
        
    except Exception as e:
        logger.error(f"\n❌ Error attaching policy to user: {e}")
        raise