import boto3
import time
from typing import List, Dict, Optional, Tuple
from loguru import logger
from botocore.exceptions import ClientError

def internal_create_cluster(
    region: str,
    cluster_identifier: str,
    engine_version: str,
    database_name: str = 'postgres',
    master_username: str = 'postgres',
    enable_cloudwatch_logs: bool = True
) -> tuple[str, str]:
    """
    Create an Aurora PostgreSQL cluster with a single writer instance.
    Credentials are automatically managed by AWS Secrets Manager.
    
    Args:
        cluster_identifier: Name of the Aurora cluster
        engine_version: PostgreSQL engine version (e.g., '15.3', '14.7')
        tags: List of tags as dictionaries with 'Key' and 'Value'
        database_name: Name of the default database
        master_username: Master username for the database
        instance_class: DB instance class
        db_subnet_group_name: DB subnet group name (uses default if None)
        vpc_security_group_ids: List of VPC security group IDs
        backup_retention_period: Number of days to retain backups
        preferred_backup_window: Preferred backup window
        preferred_maintenance_window: Preferred maintenance window
        storage_encrypted: Enable storage encryption
        kms_key_id: KMS key ID for encryption (uses default if None)
        enable_cloudwatch_logs: Enable CloudWatch logs export
        
    Returns:
        Dictionary containing cluster information and secret ARN
    """
    
    print(f"Enginever: {engine_version}")

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
            'EnableCloudwatchLogsExports': enable_cloudwatch_logs_exports,
            'DeletionProtection': False,  # Set to True for production
            'CopyTagsToSnapshot': True,
            'EnableHttpEndpoint': True,  # Enable for Data API if needed
        }

        min_capacity = 0.5
        max_capacity = 4

        cluster_params['ServerlessV2ScalingConfiguration'] = {
            'MinCapacity': min_capacity,
            'MaxCapacity': max_capacity
        }

        # Create the cluster
        cluster_response = rds_client.create_db_cluster(**cluster_params)
        
        cluster_info = cluster_response['DBCluster']
        logger.info(f"Cluster created successfully. Status: {cluster_info['Status']}")
        
        # Wait for cluster to be available
        logger.info("Waiting for cluster to become available...")
        waiter = rds_client.get_waiter('db_cluster_available')
        waiter.wait(
            DBClusterIdentifier=cluster_identifier,
            WaiterConfig={
                'Delay': 30,
                'MaxAttempts': 60
            }
        )
        logger.info("Cluster is now available")
        
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
        
        instance_response = rds_client.create_db_instance(**instance_params)
        
        logger.info(f"Writer instance created successfully")
        
        # Wait for instance to be available
        logger.info("Waiting for instance to become available...")
        instance_waiter = rds_client.get_waiter('db_instance_available')
        instance_waiter.wait(
            DBInstanceIdentifier=instance_identifier,
            WaiterConfig={
                'Delay': 30, # check every 30 seconds
                'MaxAttempts': 60 # Try up to 60 time = 30 mins
            }
        )
        logger.info("Instance is now available")
        
        # Get the final cluster details including the secret ARN
        final_cluster = rds_client.describe_db_clusters(
            DBClusterIdentifier=cluster_identifier
        )['DBClusters'][0]
        
        # Extract secret ARN
        secret_arn = final_cluster.get('MasterUserSecret', {}).get('SecretArn', '')
        
        # Prepare response
        result = {
            'ClusterIdentifier': cluster_identifier,
            'ClusterArn': final_cluster['DBClusterArn'],
            'Endpoint': final_cluster['Endpoint'],
            'ReaderEndpoint': final_cluster['ReaderEndpoint'],
            'Port': final_cluster['Port'],
            'Status': final_cluster['Status'],
            'Engine': final_cluster['Engine'],
            'EngineVersion': final_cluster['EngineVersion'],
            'DatabaseName': database_name,
            'MasterUsername': final_cluster['MasterUsername'],
            'SecretArn': secret_arn,
            'InstanceIdentifier': instance_identifier
        }
        
        logger.info("\n" + "="*50)
        logger.info("Aurora PostgreSQL Cluster Created Successfully!")
        logger.info("="*50)
        logger.info(f"Cluster Endpoint: {result['Endpoint']}")
        logger.info(f"Reader Endpoint: {result['ReaderEndpoint']}")
        logger.info(f"Port: {result['Port']}")
        logger.info(f"Secret ARN: {result['SecretArn']}")
        logger.info("="*50 + "\n")
        
        return (final_cluster['DBClusterArn'], secret_arn)
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"Error creating Aurora cluster: {error_code} - {error_message}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise

def internal_delete_cluster(
    region: str,
    cluster_id: str):
    
    """
    Delete an existing Amazon RDS (Aurora) cluster.

    Args:
        cluster_id: The DB cluster identifier.

    Raises:
        ClientError: If deletion fails or the cluster is not found.
        ValueError: If final snapshot identifier is missing when required.
    """
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
                if tag['Key'] == 'CreatedBy' and tag['Value'] == 'MCP':
                    created_by_mcp = True
        logger.info(f"Found cluster '{cluster_id}' (status={status})")

        if not created_by_mcp:
            logger.error('can only delete cluster created by MCP tool')
            raise Exception('can only delete cluster created by MCP tool')
        
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBClusterNotFoundFault":
            print(f"Cluster '{cluster_id}' does not exist.")
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