# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Integration tests for Postgres MCP Server.

This module contains integration tests that test all @mcp.tool functions
against real AWS resources. Tests can be configured via integration_test_config.yaml.

To run these tests:
    pytest tests/test_integration.py -v -m integration

To skip integration tests:
    pytest tests/ -v -m "not integration"
"""

import asyncio
import json
import os
import time
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from mcp.server.fastmcp import Context

import awslabs.postgres_mcp_server.server as server_module
from awslabs.postgres_mcp_server.connection.db_connection_map import (
    ConnectionMethod,
    DatabaseType,
)
from awslabs.postgres_mcp_server.server import (
    connect_to_database,
    create_cluster,
    get_database_connection_info,
    get_job_status,
    get_table_schema,
    is_database_connected,
    run_query,
)


# Load integration test configuration
CONFIG_FILE = Path(__file__).parent / 'integration_test_config.yaml'


def load_config() -> Dict[str, Any]:
    """Load integration test configuration from YAML file."""
    if not CONFIG_FILE.exists():
        pytest.skip(f'Integration test config not found: {CONFIG_FILE}')
    
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope='session')
def integration_config():
    """Provide integration test configuration."""
    return load_config()


@pytest.fixture(scope='session')
def aws_region(integration_config):
    """Get AWS region from config."""
    return integration_config['aws']['region']


class MockContext:
    """Mock MCP Context for integration tests."""
    
    def __init__(self):
        self.errors = []
    
    async def error(self, message):
        """Record error messages."""
        self.errors.append(message)


@pytest.fixture
def mock_ctx():
    """Provide a mock MCP context."""
    return MockContext()


@pytest.fixture(scope='session')
def cluster_endpoints(integration_config):
    """Get cluster endpoints from configuration."""
    endpoints = {}
    
    # Get regular cluster endpoint from config
    regular_config = integration_config['clusters']['regular']
    endpoints['regular'] = {
        'endpoint': regular_config.get('endpoint', ''),
        'port': regular_config.get('port', 5432),
        'cluster_identifier': regular_config['cluster_identifier']
    }
    
    # Get express cluster endpoint from config
    express_config = integration_config['clusters']['express']
    endpoints['express'] = {
        'endpoint': express_config.get('endpoint', ''),
        'port': express_config.get('port', 5432),
        'cluster_identifier': express_config['cluster_identifier']
    }
    
    return endpoints


def ensure_connection(
    cluster_identifier: str,
    db_endpoint: str,
    database: str,
    port: int,
    region: str,
    connection_method: ConnectionMethod,
    database_type: DatabaseType = DatabaseType.APG,
    with_express_configuration: bool = False
) -> None:
    """Ensure a database connection exists, creating it if necessary.
    
    Args:
        cluster_identifier: Cluster identifier
        db_endpoint: Database endpoint
        database: Database name
        port: Database port
        region: AWS region
        connection_method: Connection method to use
        database_type: Database type (default: APG)
        with_express_configuration: Whether cluster uses express configuration
    """
    if not is_database_connected(
        cluster_identifier=cluster_identifier,
        db_endpoint=db_endpoint,
        database=database
    ):
        connect_to_database(
            region=region,
            database_type=database_type,
            connection_method=connection_method,
            cluster_identifier=cluster_identifier,
            db_endpoint=db_endpoint,
            port=port,
            database=database,
            with_express_configuration=with_express_configuration
        )


@pytest.fixture
def ensure_rds_api_connection(integration_config, aws_region, cluster_endpoints):
    """Fixture to ensure RDS API connection exists for regular cluster."""
    cluster_config = integration_config['clusters']['regular']
    endpoint_info = cluster_endpoints['regular']
    
    ensure_connection(
        cluster_identifier=cluster_config['cluster_identifier'],
        db_endpoint=endpoint_info['endpoint'],
        database=cluster_config['database'],
        port=endpoint_info['port'],
        region=aws_region,
        connection_method=ConnectionMethod.RDS_API,
        with_express_configuration=False
    )
    
    return {
        'cluster_id': cluster_config['cluster_identifier'],
        'endpoint': endpoint_info['endpoint'],
        'port': endpoint_info['port'],
        'database': cluster_config['database']
    }


@pytest.fixture
def ensure_pgwire_connection_regular(integration_config, aws_region, cluster_endpoints):
    """Fixture to ensure PG Wire connection exists for regular cluster."""
    cluster_config = integration_config['clusters']['regular']
    endpoint_info = cluster_endpoints['regular']
    
    if not endpoint_info['endpoint']:
        pytest.skip('Regular cluster endpoint not available')
    
    ensure_connection(
        cluster_identifier=cluster_config['cluster_identifier'],
        db_endpoint=endpoint_info['endpoint'],
        database=cluster_config['database'],
        port=endpoint_info['port'],
        region=aws_region,
        connection_method=ConnectionMethod.PG_WIRE_PROTOCOL,
        with_express_configuration=False
    )
    
    return {
        'cluster_id': cluster_config['cluster_identifier'],
        'endpoint': endpoint_info['endpoint'],
        'port': endpoint_info['port'],
        'database': cluster_config['database']
    }


@pytest.fixture
def ensure_pgwire_iam_connection_regular(integration_config, aws_region, cluster_endpoints):
    """Fixture to ensure PG Wire IAM connection exists for regular cluster."""
    cluster_config = integration_config['clusters']['regular']
    endpoint_info = cluster_endpoints['regular']
    
    if not endpoint_info['endpoint']:
        pytest.skip('Regular cluster endpoint not available')
    
    ensure_connection(
        cluster_identifier=cluster_config['cluster_identifier'],
        db_endpoint=endpoint_info['endpoint'],
        database=cluster_config['database'],
        port=endpoint_info['port'],
        region=aws_region,
        connection_method=ConnectionMethod.PG_WIRE_IAM_PROTOCOL,
        with_express_configuration=False
    )
    
    return {
        'cluster_id': cluster_config['cluster_identifier'],
        'endpoint': endpoint_info['endpoint'],
        'port': endpoint_info['port'],
        'database': cluster_config['database']
    }


@pytest.fixture
def ensure_pgwire_iam_connection_express(integration_config, aws_region, cluster_endpoints):
    """Fixture to ensure PG Wire IAM connection exists for express cluster."""
    cluster_config = integration_config['clusters']['express']
    endpoint_info = cluster_endpoints['express']
    
    if not endpoint_info['endpoint']:
        pytest.skip('Express cluster endpoint not available')
    
    ensure_connection(
        cluster_identifier=cluster_config['cluster_identifier'],
        db_endpoint=endpoint_info['endpoint'],
        database=cluster_config['database'],
        port=endpoint_info['port'],
        region=aws_region,
        connection_method=ConnectionMethod.PG_WIRE_IAM_PROTOCOL,
        with_express_configuration=True
    )
    
    return {
        'cluster_id': cluster_config['cluster_identifier'],
        'endpoint': endpoint_info['endpoint'],
        'port': endpoint_info['port'],
        'database': cluster_config['database']
    }


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


class TestClusterCreation:
    """Test cluster creation functionality."""
    
    @pytest.mark.asyncio
    async def test_create_regular_cluster(self, integration_config, aws_region):
        """Test creating a regular Aurora Serverless v2 cluster."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        
        # Create cluster
        result_str = create_cluster(
            region=aws_region,
            cluster_identifier=cluster_id,
            database=cluster_config['database'],
            engine_version=cluster_config['engine_version'],
            with_express_configuration=False
        )
        
        result = json.loads(result_str)
        
        # Verify async job started
        assert result['status'] == 'Pending'
        assert 'job_id' in result
        assert result['cluster_identifier'] == cluster_id
        
        # Poll job status
        job_id = result['job_id']
        max_wait = 600  # 10 minutes
        poll_interval = 30  # 30 seconds
        elapsed = 0
        
        while elapsed < max_wait:
            status = get_job_status(job_id)
            
            if status['state'] == 'succeeded':
                break
            elif status['state'] == 'failed':
                pytest.fail(f"Cluster creation failed: {status.get('result')}")
            
            time.sleep(poll_interval)
            elapsed += poll_interval
        
        assert status['state'] == 'succeeded', 'Cluster creation timed out'
    
    @pytest.mark.asyncio
    async def test_create_express_cluster(self, integration_config, aws_region):
        """Test creating an express configuration cluster."""
        cluster_config = integration_config['clusters']['express']
        cluster_id = cluster_config['cluster_identifier']
        
        # Create cluster
        result_str = create_cluster(
            region=aws_region,
            cluster_identifier=cluster_id,
            database=cluster_config['database'],
            engine_version=cluster_config['engine_version'],
            with_express_configuration=True
        )
        
        result = json.loads(result_str)
        
        # Verify synchronous completion
        assert result['status'] == 'Completed'
        assert result['cluster_identifier'] == cluster_id
        assert 'db_endpoint' in result
        assert 'rds-preview.amazonaws.com' in result['db_endpoint']


class TestDatabaseConnection:
    """Test database connection functionality."""
    
    @pytest.mark.asyncio
    async def test_connect_via_rds_api(self, integration_config, aws_region, cluster_endpoints):
        """Test connecting to cluster via RDS Data API."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        endpoint_info = cluster_endpoints['regular']
        
        # Check if already connected
        is_connected = is_database_connected(
            cluster_identifier=cluster_id,
            database=cluster_config['database']
        )
        
        if not is_connected:
            # Connect to database
            result_str = connect_to_database(
                region=aws_region,
                database_type=DatabaseType.APG,
                connection_method=ConnectionMethod.RDS_API,
                cluster_identifier=cluster_id,
                db_endpoint=endpoint_info['endpoint'],
                port=endpoint_info['port'],
                database=cluster_config['database'],
                with_express_configuration=False
            )
            
            result = json.loads(result_str)
            assert result['connection_method'] == 'rdsapi'
            assert result['cluster_identifier'] == cluster_id
        
        # Verify connection
        is_connected = is_database_connected(
            cluster_identifier=cluster_id,
            db_endpoint=endpoint_info['endpoint'],
            database=cluster_config['database']
        )
        assert is_connected
    
    @pytest.mark.asyncio
    async def test_connect_via_pgwire_iam_express(
        self, integration_config, aws_region, cluster_endpoints
    ):
        """Test connecting to express cluster via PG Wire with IAM."""
        cluster_config = integration_config['clusters']['express']
        cluster_id = cluster_config['cluster_identifier']
        endpoint_info = cluster_endpoints['express']
        
        # Skip if endpoint not available
        if not endpoint_info['endpoint']:
            pytest.skip('Express cluster endpoint not available')
        
        # Connect to database
        result_str = connect_to_database(
            region=aws_region,
            database_type=DatabaseType.APG,
            connection_method=ConnectionMethod.PG_WIRE_IAM_PROTOCOL,
            cluster_identifier=cluster_id,
            db_endpoint=endpoint_info['endpoint'],
            port=endpoint_info['port'],
            database=cluster_config['database'],
            with_express_configuration=True
        )
        
        result = json.loads(result_str)
        assert result['connection_method'] == 'pgwire_iam'
        assert result['cluster_identifier'] == cluster_id
        
        # # Verify connection
        # is_connected = is_database_connected(
        #     cluster_identifier=cluster_id,
        #     db_endpoint=endpoint_info['endpoint'],
        #     database=cluster_config['database']
        # )
        # assert is_connected
    
    @pytest.mark.asyncio
    async def test_connect_via_pgwire_regular(
        self, integration_config, aws_region, cluster_endpoints
    ):
        """Test connecting to regular cluster via PG Wire with Secrets Manager."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        endpoint_info = cluster_endpoints['regular']
        
        # Skip if endpoint not available
        if not endpoint_info['endpoint']:
            pytest.skip('Regular cluster endpoint not available')
        
        # Connect to database
        result_str = connect_to_database(
            region=aws_region,
            database_type=DatabaseType.APG,
            connection_method=ConnectionMethod.PG_WIRE_PROTOCOL,
            cluster_identifier=cluster_id,
            db_endpoint=endpoint_info['endpoint'],
            port=endpoint_info['port'],
            database=cluster_config['database'],
            with_express_configuration=False
        )
        
        result = json.loads(result_str)
        assert result['connection_method'] == 'pgwire'
        assert result['cluster_identifier'] == cluster_id
        
        # Verify connection
        is_connected = is_database_connected(
            cluster_identifier=cluster_id,
            db_endpoint=endpoint_info['endpoint'],
            database=cluster_config['database']
        )
        assert is_connected
    
    @pytest.mark.asyncio
    async def test_connect_via_pgwire_iam_regular(
        self, integration_config, aws_region, cluster_endpoints
    ):
        """Test connecting to regular cluster via PG Wire with IAM."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        endpoint_info = cluster_endpoints['regular']
        
        # Skip if endpoint not available
        if not endpoint_info['endpoint']:
            pytest.skip('Regular cluster endpoint not available')
        
        # Connect to database
        result_str = connect_to_database(
            region=aws_region,
            database_type=DatabaseType.APG,
            connection_method=ConnectionMethod.PG_WIRE_IAM_PROTOCOL,
            cluster_identifier=cluster_id,
            db_endpoint=endpoint_info['endpoint'],
            port=endpoint_info['port'],
            database=cluster_config['database'],
            with_express_configuration=False
        )
        
        result = json.loads(result_str)
        assert result['connection_method'] == 'pgwire_iam'
        assert result['cluster_identifier'] == cluster_id
        
        # # Verify connection
        # is_connected = is_database_connected(
        #     cluster_identifier=cluster_id,
        #     db_endpoint=endpoint_info['endpoint'],
        #     database=cluster_config['database']
        # )
        # assert is_connected
    
    @pytest.mark.asyncio
    async def test_get_database_connection_info(self):
        """Test retrieving all cached database connections."""
        result_str = get_database_connection_info()
        connections = json.loads(result_str)
        
        print(f"\n=== Cached Database Connections ===")
        print(f"Total connections: {len(connections)}")
        for i, conn in enumerate(connections, 1):
            print(f"\nConnection {i}:")
            print(f"  Method: {conn.get('connection_method')}")
            print(f"  Cluster: {conn.get('cluster_identifier')}")
            print(f"  Endpoint: {conn.get('db_endpoint')}")
            print(f"  Database: {conn.get('database')}")
        print(f"===================================\n")
        
        assert isinstance(connections, list)
        
        # Verify connection structure
        for conn in connections:
            assert 'connection_method' in conn
            assert 'cluster_identifier' in conn
            assert 'database' in conn


class TestQueryExecution:
    """Test query execution functionality."""
    
    @pytest.mark.asyncio
    async def test_run_select_query_rds_api(self, mock_ctx, ensure_rds_api_connection):
        """Test running SELECT query via RDS API."""
        conn_info = ensure_rds_api_connection
        
        # Run query
        result = await run_query(
            sql='SELECT version(), current_database(), current_user',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database']
        )
        
        # Verify result
        assert isinstance(result, list)
        assert len(result) > 0
        assert 'version' in result[0]
        assert 'PostgreSQL' in result[0]['version']
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_run_select_query_pgwire_iam_express(
        self, mock_ctx, ensure_pgwire_iam_connection_express
    ):
        """Test running SELECT query via PG Wire IAM on express cluster."""
        conn_info = ensure_pgwire_iam_connection_express
        
        # Run query
        result = await run_query(
            sql='SELECT 1 as test, current_database()',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.PG_WIRE_IAM_PROTOCOL,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database']
        )
        
        # Verify result
        assert isinstance(result, list)
        assert len(result) > 0
        assert result[0]['test'] == 1
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_run_select_query_pgwire_regular(
        self, mock_ctx, ensure_pgwire_connection_regular
    ):
        """Test running SELECT query via PG Wire on regular cluster."""
        conn_info = ensure_pgwire_connection_regular
        
        # Run query
        result = await run_query(
            sql='SELECT version(), current_user',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.PG_WIRE_PROTOCOL,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database']
        )
        
        # Verify result
        assert isinstance(result, list)
        assert len(result) > 0
        assert 'version' in result[0]
        assert 'PostgreSQL' in result[0]['version']
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_run_select_query_pgwire_iam_regular(
        self, mock_ctx, ensure_pgwire_iam_connection_regular
    ):
        """Test running SELECT query via PG Wire IAM on regular cluster."""
        conn_info = ensure_pgwire_iam_connection_regular
        
        # Run query
        result = await run_query(
            sql='SELECT version(), current_user',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.PG_WIRE_IAM_PROTOCOL,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database']
        )
        
        # Verify result
        assert isinstance(result, list)
        assert len(result) > 0
        assert 'version' in result[0]
        assert 'PostgreSQL' in result[0]['version']
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_run_parameterized_query(self, mock_ctx, ensure_rds_api_connection):
        """Test running parameterized query."""
        conn_info = ensure_rds_api_connection
        
        # Run parameterized query
        result = await run_query(
            sql='SELECT %(value)s as result',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database'],
            query_parameters=[
                {'name': 'value', 'value': {'stringValue': 'test_param'}}
            ]
        )
        
        # Verify result
        assert isinstance(result, list)
        assert len(result) > 0
        assert result[0]['result'] == 'test_param'
        assert mock_ctx.errors == []


class TestDDLOperations:
    """Test DDL (Data Definition Language) operations."""
    
    @pytest.mark.asyncio
    async def test_create_table(self, mock_ctx, ensure_rds_api_connection):
        """Test creating a table."""
        conn_info = ensure_rds_api_connection
        
        # Create table
        result = await run_query(
            sql='''
                CREATE TABLE IF NOT EXISTS test_integration_table (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    value INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database']
        )
        
        # Verify no errors
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_get_table_schema(self, mock_ctx, ensure_rds_api_connection):
        """Test retrieving table schema."""
        conn_info = ensure_rds_api_connection
        
        # Get table schema
        result = await get_table_schema(
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database'],
            table_name='test_integration_table',
            ctx=mock_ctx
        )
        
        # Verify schema information
        assert isinstance(result, list)
        assert len(result) > 0
        
        # Check for expected columns
        column_names = [col['column_name'] for col in result]
        assert 'id' in column_names
        assert 'name' in column_names
        assert 'value' in column_names
        assert 'created_at' in column_names
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_drop_table(self, mock_ctx, ensure_rds_api_connection):
        """Test dropping a table."""
        conn_info = ensure_rds_api_connection
        
        # Drop table
        result = await run_query(
            sql='DROP TABLE IF EXISTS test_integration_table',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database']
        )
        
        # Verify no errors
        assert mock_ctx.errors == []


class TestDMLOperations:
    """Test DML (Data Manipulation Language) operations."""
    
    @pytest.fixture(autouse=True)
    async def setup_test_table(self, mock_ctx, ensure_rds_api_connection):
        """Set up test table before each test."""
        conn_info = ensure_rds_api_connection
        
        # Create test table
        await run_query(
            sql='''
                CREATE TABLE IF NOT EXISTS test_dml_table (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100),
                    value INTEGER
                )
            ''',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database']
        )
        
        yield
        
        # Cleanup: Drop test table
        await run_query(
            sql='DROP TABLE IF EXISTS test_dml_table',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=conn_info['cluster_id'],
            db_endpoint=conn_info['endpoint'],
            database=conn_info['database']
        )
    
    @pytest.mark.asyncio
    async def test_insert_data(self, integration_config, aws_region, mock_ctx):
        """Test inserting data."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        
        # Insert data
        result = await run_query(
            sql="INSERT INTO test_dml_table (name, value) VALUES ('test1', 100), ('test2', 200)",
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_select_data(self, integration_config, aws_region, mock_ctx):
        """Test selecting data."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        
        # Insert test data first
        await run_query(
            sql="INSERT INTO test_dml_table (name, value) VALUES ('test1', 100)",
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        # Select data
        result = await run_query(
            sql='SELECT * FROM test_dml_table ORDER BY id',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        # Verify result
        assert isinstance(result, list)
        assert len(result) > 0
        assert result[0]['name'] == 'test1'
        assert result[0]['value'] == 100
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_update_data(self, integration_config, aws_region, mock_ctx):
        """Test updating data."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        
        # Insert test data
        await run_query(
            sql="INSERT INTO test_dml_table (name, value) VALUES ('test1', 100)",
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        # Update data
        result = await run_query(
            sql="UPDATE test_dml_table SET value = 200 WHERE name = 'test1'",
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        # Verify update
        select_result = await run_query(
            sql="SELECT value FROM test_dml_table WHERE name = 'test1'",
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        assert select_result[0]['value'] == 200
        assert mock_ctx.errors == []
    
    @pytest.mark.asyncio
    async def test_delete_data(self, integration_config, aws_region, mock_ctx):
        """Test deleting data."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        
        # Insert test data
        await run_query(
            sql="INSERT INTO test_dml_table (name, value) VALUES ('test1', 100)",
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        # Delete data
        result = await run_query(
            sql="DELETE FROM test_dml_table WHERE name = 'test1'",
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        # Verify deletion
        select_result = await run_query(
            sql='SELECT COUNT(*) as count FROM test_dml_table',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        assert select_result[0]['count'] == 0
        assert mock_ctx.errors == []


class TestReadonlyMode:
    """Test readonly mode enforcement."""
    
    @pytest.mark.asyncio
    async def test_readonly_blocks_write_operations(
        self, integration_config, aws_region, mock_ctx, monkeypatch
    ):
        """Test that readonly mode blocks write operations."""
        # Set readonly mode
        monkeypatch.setattr(server_module, 'readonly_query', True)
        
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        
        # Attempt INSERT (should be blocked)
        result = await run_query(
            sql="INSERT INTO test_table (name) VALUES ('test')",
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        # Verify write was blocked
        assert isinstance(result, list)
        assert len(result) > 0
        assert 'error' in result[0]
        assert len(mock_ctx.errors) > 0
    
    @pytest.mark.asyncio
    async def test_readonly_allows_select(
        self, integration_config, aws_region, mock_ctx, monkeypatch
    ):
        """Test that readonly mode allows SELECT queries."""
        # Set readonly mode
        monkeypatch.setattr(server_module, 'readonly_query', True)
        
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        
        # Run SELECT query (should succeed)
        result = await run_query(
            sql='SELECT 1 as test',
            ctx=mock_ctx,
            connection_method=ConnectionMethod.RDS_API,
            cluster_identifier=cluster_id,
            db_endpoint='',
            database=cluster_config['database']
        )
        
        # Verify query succeeded
        assert isinstance(result, list)
        assert len(result) > 0
        assert result[0]['test'] == 1
        assert mock_ctx.errors == []


class TestSQLInjectionProtection:
    """Test SQL injection protection."""
    
    @pytest.mark.asyncio
    async def test_sql_injection_detection(
        self, integration_config, aws_region, mock_ctx
    ):
        """Test that SQL injection patterns are detected and blocked."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = cluster_config['cluster_identifier']
        
        # Attempt query with injection pattern
        malicious_queries = [
            "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
            "SELECT * FROM users WHERE name = '' OR '1'='1'",
            "SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords",
        ]
        
        for sql in malicious_queries:
            result = await run_query(
                sql=sql,
                ctx=mock_ctx,
                connection_method=ConnectionMethod.RDS_API,
                cluster_identifier=cluster_id,
                db_endpoint='',
                database=cluster_config['database']
            )
            
            # Verify injection was blocked
            assert isinstance(result, list)
            assert len(result) > 0
            assert 'error' in result[0]


class TestJobStatus:
    """Test background job status tracking."""
    
    def test_get_job_status_not_found(self):
        """Test getting status for non-existent job."""
        result = get_job_status('non-existent-job-id')
        assert result['state'] == 'not_found'
    
    def test_get_job_status_existing(self, integration_config, aws_region):
        """Test getting status for existing job."""
        cluster_config = integration_config['clusters']['regular']
        cluster_id = f"{cluster_config['cluster_identifier']}-status-test"
        
        # Start cluster creation
        result_str = create_cluster(
            region=aws_region,
            cluster_identifier=cluster_id,
            database=cluster_config['database'],
            engine_version=cluster_config['engine_version'],
            with_express_configuration=False
        )
        
        result = json.loads(result_str)
        job_id = result['job_id']
        
        # Get job status
        status = get_job_status(job_id)
        assert 'state' in status
        assert status['state'] in ['pending', 'succeeded', 'failed']


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'integration'])
