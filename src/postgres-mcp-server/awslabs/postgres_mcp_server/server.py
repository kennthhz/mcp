# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
# with the License. A copy of the License is located at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
# and limitations under the License.

"""awslabs postgres MCP Server implementation."""

import argparse
import asyncio
import sys
from loguru import logger
from typing import Optional, TypedDict, List, Dict, Literal, Any
import boto3
from botocore.exceptions import ClientError
from pydantic import BaseModel, Field
import mcp.types as types
from mcp.server.fastmcp import FastMCP

db_connection = None

class DBClusterUpdateRequest(BaseModel):
    cluster_id: str = Field(
        alias="DBClusterIdentifier",
        description="DB Cluster Identifier")
    min_capacity: Optional[float] = Field(
        default=None,
        description="Minimum serverless V2 scaling capacity"
    )
    max_capacity: Optional[float] = Field(
        default=None,
        description="Maximum serverless V2 scaling capacity"
    )
    enable_iam: Optional[bool] = Field(
        default=None,
        alias="EnableIAMDatabaseAuthentication",
        description="Enable or disable IAM Authentication"
    )
    backup_retention_period: Optional[int] = Field(
        default=None,
        alias="BackupRetentionPeriod",
        description="Backup retention period in days"
    )
    deletion_protection: Optional[bool] = Field(
        default=None,
        alias="DeletionProtection",
        description="Enable or disable delettion protection"
    )
    auto_minor_version_upgrade: Optional[bool] = Field(
        default=None,
        alias="AutoMinorVersionUpgrade",
        description="Specifies whether minor engine upgrades are applied automatically to the DB cluster during the maintenance window"
    )

class DBConnection:
    def __init__(self, cluster_arn, secret_arn, database, region):
        self.cluster_arn = cluster_arn
        self.secret_arn = secret_arn
        self.database = database
        self.data_client = boto3.client('rds-data', region_name = region)
        self.rds_client = boto3.client('rds', region_name = region)

    async def test_connection(self):
        await self.run_sql('SELECT 1')

    async def run_sql (
        self,
        sql: str,
        parameters: Optional[List[Dict[str, Any]]] = None
    ) -> []: # type: ignore
        """
        Execute a SQL statement using the RDS Data API
        
        Args:
            sql: SQL query to execute
            parameters: List of parameters for the query
            
        Returns:
            List of dictionaries containing the query results
        """

        execute_params = {
            'resourceArn': self.cluster_arn,
            'secretArn': self.secret_arn,
            'database': self.database,
            'sql': sql,
            'includeResultMetadata':True
        }

        if parameters:
            execute_params['parameters'] = parameters
        
        return self.data_client.execute_statement(**execute_params)
    
    async def create_serverless_v2_cluster_instance(self, cluster_name: str):
        self.rds_client.create_db_cluster(
            DBClusterIdentifier=cluster_name,
            Engine="aurora-postgresql",
            DatabaseName="postgres",
            ServerlessV2ScalingConfiguration={
                'MinCapacity': 0.5 ,
                'MaxCapacity': 25
            },
            MasterUsername = "postgres",
            ManageMasterUserPassword=True,
            DeletionProtection=False,
            EnableHttpEndpoint=True
        )
        
        self.rds_client.create_db_instance(
            DBInstanceIdentifier=cluster_name + '-instance',
            DBClusterIdentifier=cluster_name,
            Engine='aurora-postgresql',
            DBInstanceClass='db.serverless',
    )
        
    async def describe_db_cluster(self, cluster_name: str) -> Any:
        return self.rds_client.describe_db_clusters(DBClusterIdentifier=cluster_name)
    
    async def modify_db_cluster(self, req : DBClusterUpdateRequest) -> Any:
        # Start with the required field
        update_params = req.dict(
            exclude_unset=True,
            by_alias=True,
            exclude={"min_capacity", "max_capacity"}  # We'll handle these manually
        )

        # Conditionally add ServerlessV2ScalingConfiguration if either value is set
        if req.min_capacity is not None or req.max_capacity is not None:
            update_params["ServerlessV2ScalingConfiguration"] = {}
            if req.min_capacity is not None:
                update_params["ServerlessV2ScalingConfiguration"]["MinCapacity"] = req.min_capacity
            if req.max_capacity is not None:
                update_params["ServerlessV2ScalingConfiguration"]["MaxCapacity"] = req.max_capacity

        # Always apply immediately unless you want to defer
        update_params["ApplyImmediately"] = True

        logger.info("Final update payload:", update_params)
        return self.rds_client.modify_db_cluster(**update_params)

def parse_records(records) -> List[Dict[str, str]]:
    """
    Convert RDS Data API records into list of dicts.
    Each row is converted into a dictionary keyed by column name.
    """
    result = []
    for row in records:
        parsed_row = {}
        for field in row:
            for key, value in field.items():
                parsed_row[key] = value
        result.append(parsed_row)
    return result

mcp = FastMCP(
    'apg-mcp MCP server. This is the starting point for all solutions created',
    dependencies=[
        'loguru',
    ],
)

@mcp.tool(
    name = "run_query",
    description = 'Run a SQL query'
)
async def run_query(sql : str) -> Any:
    global db_connection
    try:
        logger.info(f"Executing SQL: {sql}")
        response = await db_connection.run_sql(sql)
        logger.success("Successfully execute query:{}", sql)
        return parse_records(response.get('records', []))
    except ClientError as e:
        logger.error(f"run_query error: {e.response['Error']['Message']}")
        return {"error": f"run_query error: {e.response['Error']['Message']}"}
    except Exception as e:
        logger.exception("Unexpected error during run_query")
        return {"error": f"run_query unexpected error: {str(e)}"}
    
@mcp.tool(
    name = 'describe_db_cluster',
    description = 'describe or get information of a db cluster'
)
async def describe_db_cluster(cluster_name: str) -> Any:
    global db_connection
    try:
        logger.info(f"describe_db_cluster: {cluster_name}")
        return await db_connection.describe_db_cluster(cluster_name)
    except ClientError as e:
        logger.error(f"describe_db_cluster error: {e.response['Error']['Message']}")
        return {"error": f"describe_db_cluster error: {e.response['Error']['Message']}"}
    except Exception as e:
        logger.exception("Unexpected error during describe_db_cluster")
        return {"error": f"describe_db_cluster unexpected error: {str(e)}"}

@mcp.tool(
    name = 'modify_db_cluster',
    description = 'Modify or update a db cluster'
)
async def modify_db_cluster(req : DBClusterUpdateRequest) -> Any:
    global db_connection
    try:
        logger.info(f"modify_db_cluster: {req.cluster_id}")
        return await db_connection.modify_db_cluster(req)
    except ClientError as e:
        logger.error(f"modify_db_cluster error: {e.response['Error']['Message']}")
        return {"error": f"modify_db_cluster error: {e.response['Error']['Message']}"}
    except Exception as e:
        logger.exception("Unexpected error during modify_db_cluster")
        return {"error": f"modify_db_cluster unexpected error: {str(e)}"}

@mcp.tool(
    name = 'create_serverless_aurora_postgreSQL_cluster',
    description = 'create a serverless Aurora PostgreSQL cluster'
)
async def create_serverless_aurora_postgreSQL_cluster(cluster_name : str) -> Any:
    global db_connection
    try:
        logger.info(f"create_serverless_aurora_postgreSQL_cluster: {cluster_name}")
        return await db_connection.create_serverless_v2_cluster_instance(cluster_name)
        logger.success("Successfully created serverless V2 cluster {} and instance", cluster_name)
    except ClientError as e:
        logger.error(f"create_serverless_aurora_postgreSQL_cluster error: {e.response['Error']['Message']}")
        return {"error": f"create_serverless_aurora_postgreSQL_cluster error: {e.response['Error']['Message']}"}
    except Exception as e:
        logger.exception("Unexpected error during create_serverless_aurora_postgreSQL_cluster")
        return {"error": f"create_serverless_aurora_postgreSQL_cluster unexpected error: {str(e)}"}

def init_db_connection(resource_arn, secret_arn, database, region):
    db_connection = DBConnection(resource_arn, secret_arn, database, region)
    asyncio.run(db_connection.test_connection())
    return db_connection

def main():
    global db_connection

    """Run the MCP server with CLI argument support."""
    parser = argparse.ArgumentParser(description='An AWS Labs Model Context Protocol (MCP) server for postgres')
    parser.add_argument('--sse', action='store_true', help='Use SSE transport')
    parser.add_argument('--port', type=int, default=8888, help='Port to run the server on')
    parser.add_argument('--resource_arn', required=True, help='ARN of the RDS cluster')
    parser.add_argument('--secret_arn', required=True, help='ARN of the Secrets Manager secret for database credentials')
    parser.add_argument('--database', required=True, help='Database name')
    parser.add_argument('--region', required=True, default='us-west-2', help='AWS region for RDS Data API (default: us-west-2)')

    args = parser.parse_args()

    logger.info("Postgres MCP init with CLUSTER_ARN:{}, SECRET_ARN:{}, REGION:{}, DATABASE:{}", 
                args.resource_arn, args.secret_arn, args.region, args.database)

    try:
        db_connection = init_db_connection(args.resource_arn, args.secret_arn, args.database, args.region)
    except Exception as e:
        logger.exception("Failed to validate connection to Postgres. Exit the MCP server")
        sys.exit(1)

    logger.success("Successfully validated connection to Postgres")

    # Run server with appropriate transport
    if args.sse:
        mcp.settings.port = args.port
        mcp.run(transport='sse')
    else:
        logger.info("Starting Postgres MCP server")
        mcp.run()
        
if __name__ == '__main__':
    main()
