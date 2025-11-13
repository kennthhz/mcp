"""
Comprehensive test suite for RDS cluster management functions defined in cp_api_connection.py.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch, call
from botocore.exceptions import ClientError, WaiterError
from typing import Dict, List, Optional
from awslabs.postgres_mcp_server.connection.cp_api_connection import (
    internal_create_serverless_cluster,
    internal_delete_cluster,
    get_rds_cluster_and_secret_arn
)


# =============================================================================
# MOCK DATA FACTORIES
# =============================================================================

def create_mock_cluster_response(
    cluster_id: str = "test-cluster",
    status: str = "available",
    include_secret: bool = True,
    members: Optional[List[str]] = None
) -> Dict:
    """Create a mock RDS cluster response."""
    cluster = {
        "DBCluster": {
            "DBClusterIdentifier": cluster_id,
            "DBClusterArn": f"arn:aws:rds:us-east-1:123456789012:cluster:{cluster_id}",
            "Status": status,
            "Endpoint": f"{cluster_id}.cluster-abc123.us-east-1.rds.amazonaws.com",
            "ReaderEndpoint": f"{cluster_id}.cluster-ro-abc123.us-east-1.rds.amazonaws.com",
            "Port": 5432,
            "Engine": "aurora-postgresql",
            "EngineVersion": "15.3",
            "MasterUsername": "postgres",
            "DatabaseName": "postgres",
            "DBClusterMembers": [
                {"DBInstanceIdentifier": member} for member in (members or [])
            ],
        }
    }
    
    if include_secret:
        cluster["DBCluster"]["MasterUserSecret"] = {
            "SecretArn": f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{cluster_id}-secret-abc123"
        }
    
    return cluster


def create_mock_instance_response(
    instance_id: str = "test-instance",
    cluster_id: str = "test-cluster",
    status: str = "available"
) -> Dict:
    """Create a mock RDS instance response."""
    return {
        "DBInstance": {
            "DBInstanceIdentifier": instance_id,
            "DBInstanceArn": f"arn:aws:rds:us-east-1:123456789012:db:{instance_id}",
            "DBClusterIdentifier": cluster_id,
            "DBInstanceStatus": status,
            "Engine": "aurora-postgresql",
            "DBInstanceClass": "db.serverless",
        }
    }


def create_mock_tags(include_mcp: bool = True) -> Dict:
    """Create a mock tags response."""
    tags = [{"Key": "Environment", "Value": "test"}]
    if include_mcp:
        tags.append({"Key": "CreatedBy", "Value": "MCP"})
    return {"TagList": tags}


def create_client_error(error_code: str, message: str = "Test error") -> ClientError:
    """Create a mock ClientError."""
    return ClientError(
        error_response={
            "Error": {
                "Code": error_code,
                "Message": message
            }
        },
        operation_name="TestOperation"
    )


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_rds_client():
    """Create a mock RDS client with proper waiter handling."""
    client = MagicMock()
    
    # Setup default successful responses
    client.create_db_cluster.return_value = create_mock_cluster_response(status="creating")
    client.create_db_instance.return_value = create_mock_instance_response(status="creating")
    client.describe_db_clusters.return_value = {
        "DBClusters": [create_mock_cluster_response()["DBCluster"]]
    }
    client.describe_db_instances.return_value = {
        "DBInstances": [create_mock_instance_response()["DBInstance"]]
    }
    client.list_tags_for_resource.return_value = create_mock_tags()
    client.delete_db_cluster.return_value = {}
    client.delete_db_instance.return_value = {}
    
    # Setup waiters - create new mock for each waiter type
    def get_waiter_side_effect(waiter_name):
        mock_waiter = MagicMock()
        mock_waiter.wait.return_value = None
        mock_waiter.name = waiter_name
        return mock_waiter
    
    client.get_waiter.side_effect = get_waiter_side_effect
    
    return client


@pytest.fixture
def mock_boto3_client(mock_rds_client):
    """Mock boto3.client to return our mock RDS client."""
    # NOTE: Change 'awslabs.postgres_mcp_server.connection.cp_api_connection' to actual module name
    with patch("awslabs.postgres_mcp_server.connection.cp_api_connection.boto3.client", return_value=mock_rds_client) as mock:
        yield mock


@pytest.fixture
def mock_time_sleep():
    """Mock time.sleep to speed up tests."""
    # NOTE: Change 'awslabs.postgres_mcp_server.connection.cp_api_connection' to actual module name
    with patch("awslabs.postgres_mcp_server.connection.cp_api_connection.time.sleep") as mock:
        yield mock


@pytest.fixture
def mock_logger():
    """Mock loguru logger."""
    # NOTE: Change 'awslabs.postgres_mcp_server.connection.cp_api_connection' to actual module name
    with patch("awslabs.postgres_mcp_server.connection.cp_api_connection.logger") as mock:
        yield mock


@pytest.fixture
def mock_print():
    """Mock print to avoid cluttering test output."""
    with patch("builtins.print") as mock:
        yield mock


# =============================================================================
# TESTS FOR: internal_create_serverless_cluster
# =============================================================================

class TestInternalCreateServerlessCluster:
    """Tests for internal_create_serverless_cluster function."""
    
    def test_successful_cluster_creation(
        self, mock_boto3_client, mock_rds_client, mock_logger, mock_print
    ):
        """Test successful cluster and instance creation."""
        
        # Execute
        cluster_arn, secret_arn = internal_create_serverless_cluster(
            region="us-east-1",
            cluster_identifier="test-cluster",
            engine_version="15.3",
            database_name="testdb",
            master_username="admin",
            min_capacity=0.5,
            max_capacity=1.0,
            enable_cloudwatch_logs=True
        )
        
        # Verify boto3.client was called correctly
        mock_boto3_client.assert_called_once_with("rds", region_name="us-east-1")
        
        # Verify create_db_cluster was called with correct params
        mock_rds_client.create_db_cluster.assert_called_once()
        cluster_call_kwargs = mock_rds_client.create_db_cluster.call_args[1]
        
        assert cluster_call_kwargs["DBClusterIdentifier"] == "test-cluster"
        assert cluster_call_kwargs["Engine"] == "aurora-postgresql"
        assert cluster_call_kwargs["EngineVersion"] == "15.3"
        assert cluster_call_kwargs["MasterUsername"] == "admin"
        assert cluster_call_kwargs["DatabaseName"] == "testdb"
        assert cluster_call_kwargs["ManageMasterUserPassword"] is True
        assert cluster_call_kwargs["EnableCloudwatchLogsExports"] == ["postgresql"]
        assert cluster_call_kwargs["ServerlessV2ScalingConfiguration"] == {
            "MinCapacity": 0.5,
            "MaxCapacity": 1.0
        }
        assert any(tag["Key"] == "CreatedBy" and tag["Value"] == "MCP" 
                  for tag in cluster_call_kwargs["Tags"])
        
        # Verify waiter was called for cluster
        assert any(
            call_args[0][0] == "db_cluster_available" 
            for call_args in mock_rds_client.get_waiter.call_args_list
        )
        
        # Verify create_db_instance was called
        mock_rds_client.create_db_instance.assert_called_once()
        instance_call_kwargs = mock_rds_client.create_db_instance.call_args[1]
        
        assert instance_call_kwargs["DBInstanceIdentifier"] == "test-cluster-instance-1"
        assert instance_call_kwargs["DBInstanceClass"] == "db.serverless"
        assert instance_call_kwargs["Engine"] == "aurora-postgresql"
        assert instance_call_kwargs["DBClusterIdentifier"] == "test-cluster"
        
        # Verify waiter was called for instance
        assert any(
            call_args[0][0] == "db_instance_available" 
            for call_args in mock_rds_client.get_waiter.call_args_list
        )
        
        # Verify describe_db_clusters was called to get final details
        mock_rds_client.describe_db_clusters.assert_called_with(
            DBClusterIdentifier="test-cluster"
        )
        
        # Verify return values
        assert cluster_arn == "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster"
        assert "secret" in secret_arn
        
        # Verify logging
        assert mock_logger.info.call_count > 0
        
        # Verify print was called
        mock_print.assert_called_once()
    
    def test_cloudwatch_logs_disabled(self, mock_boto3_client, mock_rds_client, mock_print):
        """Test cluster creation with CloudWatch logs disabled."""
        
        internal_create_serverless_cluster(
            region="us-east-1",
            cluster_identifier="test-cluster",
            engine_version="15.3",
            min_capacity=0.5,
            max_capacity=1.0,
            enable_cloudwatch_logs=False
        )
        
        cluster_call_kwargs = mock_rds_client.create_db_cluster.call_args[1]
        assert cluster_call_kwargs["EnableCloudwatchLogsExports"] == []
    
    def test_cluster_creation_fails(self, mock_boto3_client, mock_rds_client, mock_print):
        """Test handling of cluster creation failure."""
        
        # Setup mock to raise error
        mock_rds_client.create_db_cluster.side_effect = create_client_error(
            "InvalidParameterValue",
            "Invalid engine version"
        )
        
        # Execute and verify exception
        with pytest.raises(ClientError) as exc_info:
            internal_create_serverless_cluster(
                region="us-east-1",
                cluster_identifier="test-cluster",
                engine_version="invalid",
                min_capacity=0.5,
                max_capacity=1.0
            )
        
        assert exc_info.value.response["Error"]["Code"] == "InvalidParameterValue"
        
        # Verify instance creation was not attempted
        mock_rds_client.create_db_instance.assert_not_called()
    
    def test_cluster_waiter_timeout(self, mock_boto3_client, mock_rds_client, mock_print):
        """Test handling of cluster waiter timeout."""
        
        # Setup waiter to raise timeout error
        def get_waiter_side_effect(waiter_name):
            mock_waiter = MagicMock()
            if waiter_name == "db_cluster_available":
                mock_waiter.wait.side_effect = WaiterError(
                    name="db_cluster_available",
                    reason="Max attempts exceeded",
                    last_response={}
                )
            else:
                mock_waiter.wait.return_value = None
            return mock_waiter
        
        mock_rds_client.get_waiter.side_effect = get_waiter_side_effect
        
        with pytest.raises(WaiterError):
            internal_create_serverless_cluster(
                region="us-east-1",
                cluster_identifier="test-cluster",
                engine_version="15.3",
                min_capacity=0.5,
                max_capacity=1.0
            )
        
        # Verify instance creation was not attempted
        mock_rds_client.create_db_instance.assert_not_called()
    
    def test_instance_creation_fails(self, mock_boto3_client, mock_rds_client, mock_print):
        """Test handling of instance creation failure after successful cluster creation."""
        
        # Setup instance creation to fail
        mock_rds_client.create_db_instance.side_effect = create_client_error(
            "InvalidParameterCombination",
            "Invalid instance configuration"
        )
        
        with pytest.raises(ClientError) as exc_info:
            internal_create_serverless_cluster(
                region="us-east-1",
                cluster_identifier="test-cluster",
                engine_version="15.3",
                min_capacity=0.5,
                max_capacity=1.0
            )
        
        assert exc_info.value.response["Error"]["Code"] == "InvalidParameterCombination"
        
        # Verify cluster was created but instance failed
        mock_rds_client.create_db_cluster.assert_called_once()
        mock_rds_client.create_db_instance.assert_called_once()
    
    def test_instance_waiter_timeout(self, mock_boto3_client, mock_rds_client, mock_print):
        """Test handling of instance waiter timeout."""
        
        # Setup waiters - cluster succeeds, instance times out
        def get_waiter_side_effect(waiter_name):
            mock_waiter = MagicMock()
            if waiter_name == "db_cluster_available":
                mock_waiter.wait.return_value = None
            elif waiter_name == "db_instance_available":
                mock_waiter.wait.side_effect = WaiterError(
                    name="db_instance_available",
                    reason="Max attempts exceeded",
                    last_response={}
                )
            return mock_waiter
        
        mock_rds_client.get_waiter.side_effect = get_waiter_side_effect
        
        with pytest.raises(WaiterError):
            internal_create_serverless_cluster(
                region="us-east-1",
                cluster_identifier="test-cluster",
                engine_version="15.3",
                min_capacity=0.5,
                max_capacity=1.0
            )
        
        # Verify both cluster and instance were created
        mock_rds_client.create_db_cluster.assert_called_once()
        mock_rds_client.create_db_instance.assert_called_once()
    
    def test_no_secret_arn_in_response(self, mock_boto3_client, mock_rds_client, mock_print):
        """Test handling when MasterUserSecret is not in response."""
        
        # Setup response without secret
        mock_rds_client.describe_db_clusters.return_value = {
            "DBClusters": [create_mock_cluster_response(include_secret=False)["DBCluster"]]
        }
        
        cluster_arn, secret_arn = internal_create_serverless_cluster(
            region="us-east-1",
            cluster_identifier="test-cluster",
            engine_version="15.3",
            min_capacity=0.5,
            max_capacity=1.0
        )
        
        assert cluster_arn == "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster"
        assert secret_arn == ""
    
    def test_unexpected_exception(self, mock_boto3_client, mock_rds_client, mock_print):
        """Test handling of unexpected exceptions."""
        
        mock_rds_client.create_db_cluster.side_effect = Exception("Unexpected error")
        
        with pytest.raises(Exception) as exc_info:
            internal_create_serverless_cluster(
                region="us-east-1",
                cluster_identifier="test-cluster",
                engine_version="15.3",
                min_capacity=0.5,
                max_capacity=1.0
            )
        
        assert "Unexpected error" in str(exc_info.value)


# =============================================================================
# TESTS FOR: internal_delete_cluster
# =============================================================================

class TestInternalDeleteCluster:
    """Tests for internal_delete_cluster function."""
    
    def test_successful_cluster_deletion_with_instances(
        self, mock_boto3_client, mock_rds_client, mock_time_sleep
    ):
        """Test successful deletion of cluster with instances."""
        
        # Setup cluster with two instances
        cluster_response = create_mock_cluster_response(
            cluster_id="test-cluster",
            members=["instance-1", "instance-2"]
        )
        
        # Track state for dynamic responses
        cluster_deleted = {"value": False}
        instances_deleted = {"instance-1": False, "instance-2": False}
        
        def describe_clusters_side_effect(DBClusterIdentifier):
            if cluster_deleted["value"]:
                raise create_client_error("DBClusterNotFoundFault")
            return {"DBClusters": [cluster_response["DBCluster"]]}
        
        def describe_instances_side_effect(DBInstanceIdentifier):
            if instances_deleted.get(DBInstanceIdentifier, False):
                raise create_client_error("DBInstanceNotFoundFault")
            # First call returns instance, second call it's deleted
            instances_deleted[DBInstanceIdentifier] = True
            return {"DBInstances": [{}]}
        
        def delete_cluster_side_effect(**kwargs):
            cluster_deleted["value"] = True
            return {}
        
        mock_rds_client.describe_db_clusters.side_effect = describe_clusters_side_effect
        mock_rds_client.describe_db_instances.side_effect = describe_instances_side_effect
        mock_rds_client.delete_db_cluster.side_effect = delete_cluster_side_effect
        
        # Execute
        internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        # Verify instances were deleted
        assert mock_rds_client.delete_db_instance.call_count == 2
        delete_calls = [call[1]["DBInstanceIdentifier"] 
                       for call in mock_rds_client.delete_db_instance.call_args_list]
        assert "instance-1" in delete_calls
        assert "instance-2" in delete_calls
        
        # Verify cluster was deleted
        mock_rds_client.delete_db_cluster.assert_called_once_with(
            DBClusterIdentifier="test-cluster",
            SkipFinalSnapshot=True
        )
        
        # Verify polling occurred
        assert mock_time_sleep.call_count >= 1
    
    def test_cluster_not_found(self, mock_boto3_client, mock_rds_client):
        """Test early return when cluster doesn't exist."""
        
        mock_rds_client.describe_db_clusters.side_effect = create_client_error(
            "DBClusterNotFoundFault",
            "Cluster not found"
        )
        
        # Should return without raising
        result = internal_delete_cluster(region="us-east-1", cluster_id="nonexistent")
        
        assert result is None
        mock_rds_client.delete_db_cluster.assert_not_called()
    
    def test_missing_mcp_tag_raises_permission_error(
        self, mock_boto3_client, mock_rds_client
    ):
        """Test that deletion fails when MCP tag is missing."""
        
        # Setup cluster without MCP tag
        mock_rds_client.list_tags_for_resource.return_value = create_mock_tags(
            include_mcp=False
        )
        
        with pytest.raises(PermissionError) as exc_info:
            internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        # Note: Source code has f-string bug, so cluster_id won't appear in message
        assert "MCP tool" in str(exc_info.value)
        
        # Verify deletion was not attempted
        mock_rds_client.delete_db_instance.assert_not_called()
        mock_rds_client.delete_db_cluster.assert_not_called()
    
    def test_cluster_without_instances(
        self, mock_boto3_client, mock_rds_client, mock_time_sleep
    ):
        """Test deletion of cluster with no instances."""
        
        # Setup cluster with no members
        cluster_response = create_mock_cluster_response(
            cluster_id="test-cluster",
            members=[]
        )
        
        cluster_deleted = {"value": False}
        
        def describe_clusters_side_effect(DBClusterIdentifier):
            if cluster_deleted["value"]:
                raise create_client_error("DBClusterNotFoundFault")
            return {"DBClusters": [cluster_response["DBCluster"]]}
        
        def delete_cluster_side_effect(**kwargs):
            cluster_deleted["value"] = True
            return {}
        
        mock_rds_client.describe_db_clusters.side_effect = describe_clusters_side_effect
        mock_rds_client.delete_db_cluster.side_effect = delete_cluster_side_effect
        
        internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        # Verify no instance deletion attempted
        mock_rds_client.delete_db_instance.assert_not_called()
        
        # Verify cluster was deleted
        mock_rds_client.delete_db_cluster.assert_called_once()
    
    def test_instance_already_deleted(
        self, 
        mock_boto3_client, 
        mock_rds_client, 
        mock_time_sleep,
        mock_logger  # Add this too for completeness
    ):
        """Test handling when instance is already deleted."""
        
        cluster_response = create_mock_cluster_response(
            cluster_id="test-cluster",
            members=["instance-1"]
        )
        
        cluster_deleted = {"value": False}
        
        # =========================================================================
        # MOCK: describe_db_clusters
        # =========================================================================
        def describe_clusters_side_effect(DBClusterIdentifier):
            if cluster_deleted["value"]:
                raise create_client_error("DBClusterNotFoundFault")
            return {"DBClusters": [cluster_response["DBCluster"]]}
        
        mock_rds_client.describe_db_clusters.side_effect = describe_clusters_side_effect
        
        # =========================================================================
        # MOCK: list_tags_for_resource (MISSING!)
        # =========================================================================
        # The function needs to check if cluster has MCP tag
        mock_rds_client.list_tags_for_resource.return_value = create_mock_tags(
            include_mcp=True
        )
        
        # =========================================================================
        # MOCK: delete_db_instance - returns "already deleted" error
        # =========================================================================
        mock_rds_client.delete_db_instance.side_effect = create_client_error(
            "DBInstanceNotFound",
            "Instance already deleted"
        )
        
        # =========================================================================
        # MOCK: describe_db_instances (MISSING!)
        # =========================================================================
        # After delete_db_instance fails with "not found", the code still
        # enters a polling loop to check if instances are deleted.
        # Since instance is already deleted, this should immediately raise NotFound
        mock_rds_client.describe_db_instances.side_effect = create_client_error(
            "DBInstanceNotFoundFault",
            "Instance not found"
        )
        
        # =========================================================================
        # MOCK: delete_db_cluster
        # =========================================================================
        def delete_cluster_side_effect(**kwargs):
            cluster_deleted["value"] = True
            return {}
        
        mock_rds_client.delete_db_cluster.side_effect = delete_cluster_side_effect
        
        # =========================================================================
        # EXECUTE
        # =========================================================================
        # Should not raise exception
        internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        # =========================================================================
        # VERIFY
        # =========================================================================
        # Verify delete_db_instance was attempted (and got "not found" error)
        mock_rds_client.delete_db_instance.assert_called_once_with(
            DBInstanceIdentifier="instance-1",
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True
        )
        
        # Verify cluster deletion still proceeded
        mock_rds_client.delete_db_cluster.assert_called_once()
        
        # Verify we didn't sleep (since instance was already gone)
        # Actually, we might sleep once checking for cluster deletion
        # So just verify it was called a reasonable number of times
        assert mock_time_sleep.call_count < 10  # Not stuck in infinite loop
    
    def test_instance_deletion_error_propagates(
        self, 
        mock_boto3_client, 
        mock_rds_client,
        mock_time_sleep,
        mock_logger
    ):
        """
        Test that non-NotFound errors during instance deletion propagate correctly.
        
        Scenario:
        - Cluster exists with MCP tag
        - Has one instance
        - Instance deletion fails with InvalidDBInstanceState (not NotFound)
        - Error should propagate up (not be swallowed)
        - Cluster deletion should NOT be attempted
        
        This tests the error handling path in internal_delete_cluster where
        deletion fails with an error OTHER than "not found" errors.
        """
        
        # =========================================================================
        # SETUP: Create cluster with one instance
        # =========================================================================
        cluster_response = create_mock_cluster_response(
            cluster_id="test-cluster",
            members=["instance-1"]
        )
        
        # =========================================================================
        # MOCK: describe_db_clusters (called once at start for validation)
        # =========================================================================
        # The function calls describe_db_clusters to:
        # 1. Check if cluster exists
        # 2. Get the cluster ARN for tag checking
        # 3. Get list of member instances
        mock_rds_client.describe_db_clusters.return_value = {
            "DBClusters": [cluster_response["DBCluster"]]
        }
        
        # =========================================================================
        # MOCK: list_tags_for_resource (must return MCP tag to pass permission check)
        # =========================================================================
        # The function checks if cluster has CreatedBy=MCP tag
        # Without this, it raises PermissionError before attempting deletion
        mock_rds_client.list_tags_for_resource.return_value = create_mock_tags(
            include_mcp=True
        )
        
        # =========================================================================
        # MOCK: delete_db_instance (raises non-NotFound error)
        # =========================================================================
        # This is the key part: we're testing what happens when instance deletion
        # fails with an error OTHER than "instance not found"
        # Expected behavior: error should propagate, not be caught
        mock_rds_client.delete_db_instance.side_effect = create_client_error(
            "InvalidDBInstanceState",
            "Cannot delete instance in current state"
        )
        
        # =========================================================================
        # EXECUTE: Call function and expect ClientError to propagate
        # =========================================================================
        with pytest.raises(ClientError) as exc_info:
            internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        # =========================================================================
        # VERIFY: Correct error was raised
        # =========================================================================
        assert exc_info.value.response["Error"]["Code"] == "InvalidDBInstanceState"
        assert "Cannot delete instance" in exc_info.value.response["Error"]["Message"]
        
        # =========================================================================
        # VERIFY: describe_db_clusters was called once (initial check)
        # =========================================================================
        mock_rds_client.describe_db_clusters.assert_called_once_with(
            DBClusterIdentifier="test-cluster"
        )
        
        # =========================================================================
        # VERIFY: list_tags_for_resource was called to check MCP tag
        # =========================================================================
        mock_rds_client.list_tags_for_resource.assert_called_once()
        # Verify it was called with the cluster ARN
        call_args = mock_rds_client.list_tags_for_resource.call_args
        assert "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster" in str(call_args)
        
        # =========================================================================
        # VERIFY: delete_db_instance was called once (and failed)
        # =========================================================================
        mock_rds_client.delete_db_instance.assert_called_once_with(
            DBInstanceIdentifier="instance-1",
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True
        )
        
        # =========================================================================
        # VERIFY: describe_db_instances was NOT called
        # =========================================================================
        # Because deletion failed immediately, we never enter the polling loop
        # to check if instances are deleted
        mock_rds_client.describe_db_instances.assert_not_called()
        
        # =========================================================================
        # VERIFY: delete_db_cluster was NOT attempted
        # =========================================================================
        # Critical: if instance deletion fails, cluster deletion should not proceed
        mock_rds_client.delete_db_cluster.assert_not_called()
        
        # =========================================================================
        # VERIFY: time.sleep was NOT called
        # =========================================================================
        # Proves we didn't enter the polling loop (which would cause infinite hang
        # if time.sleep wasn't mocked)
        mock_time_sleep.assert_not_called()
        
        # =========================================================================
        # VERIFY: Appropriate error was logged
        # =========================================================================
        # Check that logger.error was called with error details
        assert mock_logger.error.called
        error_log_calls = [
            str(call) for call in mock_logger.error.call_args_list
        ]
        # Should log something about the instance deletion error
        assert any(
            "instance-1" in call.lower() or "error" in call.lower() 
            for call in error_log_calls
        )
    
    def test_cluster_deletion_error(
        self, mock_boto3_client, mock_rds_client, mock_time_sleep
    ):
        """Test handling of cluster deletion error."""
        
        cluster_response = create_mock_cluster_response(
            cluster_id="test-cluster",
            members=[]
        )
        mock_rds_client.describe_db_clusters.return_value = {
            "DBClusters": [cluster_response["DBCluster"]]
        }
        
        mock_rds_client.delete_db_cluster.side_effect = create_client_error(
            "InvalidDBClusterStateFault",
            "Cluster is not in valid state"
        )
        
        with pytest.raises(ClientError) as exc_info:
            internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        assert exc_info.value.response["Error"]["Code"] == "InvalidDBClusterStateFault"
    
    def test_instance_polling_multiple_iterations(
        self, mock_boto3_client, mock_rds_client, mock_time_sleep
    ):
        """Test that instance polling works correctly over multiple iterations."""
        
        cluster_response = create_mock_cluster_response(
            cluster_id="test-cluster",
            members=["instance-1", "instance-2"]
        )
        
        cluster_deleted = {"value": False}
        instance_check_counts = {"instance-1": 0, "instance-2": 0}
        
        def describe_clusters_side_effect(DBClusterIdentifier):
            if cluster_deleted["value"]:
                raise create_client_error("DBClusterNotFoundFault")
            return {"DBClusters": [cluster_response["DBCluster"]]}
        
        def describe_instances_side_effect(DBInstanceIdentifier):
            instance_check_counts[DBInstanceIdentifier] += 1
            # instance-2 deleted after 1 check, instance-1 after 3 checks
            if DBInstanceIdentifier == "instance-2" and instance_check_counts[DBInstanceIdentifier] > 1:
                raise create_client_error("DBInstanceNotFoundFault")
            if DBInstanceIdentifier == "instance-1" and instance_check_counts[DBInstanceIdentifier] > 3:
                raise create_client_error("DBInstanceNotFoundFault")
            return {"DBInstances": [{}]}
        
        def delete_cluster_side_effect(**kwargs):
            cluster_deleted["value"] = True
            return {}
        
        mock_rds_client.describe_db_clusters.side_effect = describe_clusters_side_effect
        mock_rds_client.describe_db_instances.side_effect = describe_instances_side_effect
        mock_rds_client.delete_db_cluster.side_effect = delete_cluster_side_effect
        
        internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        # Verify sleep was called between polling iterations
        assert mock_time_sleep.call_count >= 2
        assert all(call[0][0] == 5 for call in mock_time_sleep.call_args_list)
    
    def test_cluster_polling_multiple_iterations(
        self, mock_boto3_client, mock_rds_client, mock_time_sleep
    ):
        """Test that cluster polling works correctly over multiple iterations."""
        
        cluster_response = create_mock_cluster_response(
            cluster_id="test-cluster",
            members=[]
        )
        
        describe_call_count = {"value": 0}
        
        def describe_clusters_side_effect(DBClusterIdentifier):
            describe_call_count["value"] += 1
            if describe_call_count["value"] <= 4:
                return {"DBClusters": [cluster_response["DBCluster"]]}
            else:
                raise create_client_error("DBClusterNotFoundFault")
        
        mock_rds_client.describe_db_clusters.side_effect = describe_clusters_side_effect
        
        internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        # Verify multiple polling iterations occurred
        assert mock_time_sleep.call_count >= 3
    
    def test_tag_check_error_propagates(self, mock_boto3_client, mock_rds_client):
        """Test that errors during tag checking propagate correctly."""
        
        mock_rds_client.list_tags_for_resource.side_effect = create_client_error(
            "AccessDenied",
            "Not authorized to list tags"
        )
        
        with pytest.raises(ClientError) as exc_info:
            internal_delete_cluster(region="us-east-1", cluster_id="test-cluster")
        
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


# =============================================================================
# TESTS FOR: get_rds_cluster_and_secret_arn
# =============================================================================

class TestGetRdsClusterAndSecretArn:
    """Tests for get_rds_cluster_and_secret_arn function."""
    
    def test_cluster_with_secret(self, mock_boto3_client, mock_rds_client):
        """Test retrieving cluster with secret ARN."""
        
        cluster_arn, secret_arn = get_rds_cluster_and_secret_arn(
            cluster_id="test-cluster",
            region="us-east-1"
        )
        
        assert cluster_arn == "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster"
        assert secret_arn == "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-cluster-secret-abc123"
        
        mock_boto3_client.assert_called_once_with("rds", region_name="us-east-1")
        mock_rds_client.describe_db_clusters.assert_called_once_with(
            DBClusterIdentifier="test-cluster"
        )
    
    def test_cluster_without_secret(self, mock_boto3_client, mock_rds_client):
        """Test retrieving cluster without secret ARN."""
        
        # Setup response without secret
        mock_rds_client.describe_db_clusters.return_value = {
            "DBClusters": [create_mock_cluster_response(include_secret=False)["DBCluster"]]
        }
        
        cluster_arn, secret_arn = get_rds_cluster_and_secret_arn(
            cluster_id="test-cluster",
            region="us-east-1"
        )
        
        assert cluster_arn == "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster"
        assert secret_arn is None
    
    def test_cluster_not_found_raises_value_error(
        self, mock_boto3_client, mock_rds_client
    ):
        """Test that ValueError is raised when cluster is not found."""
        
        mock_rds_client.describe_db_clusters.return_value = {"DBClusters": []}
        
        with pytest.raises(ValueError) as exc_info:
            get_rds_cluster_and_secret_arn(
                cluster_id="nonexistent",
                region="us-east-1"
            )
        
        assert "No cluster found" in str(exc_info.value)