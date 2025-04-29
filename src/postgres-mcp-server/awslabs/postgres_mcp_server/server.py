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
from loguru import logger
from typing import Optional, TypedDict, List, Dict, Literal, Any
import asyncio
import boto3
from pydantic import BaseModel, Field
import mcp.types as types
from mcp.server.fastmcp import FastMCP

CLUSTER_ARN = ''
SECRET_ARN = ''
REGION = 'us-east-1'   
DATABASE = 'mydb'

'''
Extracted values from Data API response, including ColumnName, Data Type (e.g., StringValue, DoubleValue, etc.), and Value
'''
class RDSDataAPIResponse: 
    def __init__(self, name, type, value):
        self.name = name #The column Name
        self.type = type #The data type of the column
        self.value = value #The value of the cell
    def __repr__(self):
        return f"Name: {self.name}, Type: {self.type}, Value: {self.value}"
    
    def __str__(self):
        return f"Name: {self.name}, Type: {self.type}, Value: {self.value}"

class RDSDataClient:
    def __init__(self, region: str = REGION):
        self.client = boto3.client('rds-data', region_name=region)
        print("Initialized RDS Data API client.")

        # These can be set via environment variables or passed to run_sql
        self.resource_arn = CLUSTER_ARN
        self.secret_arn = SECRET_ARN
        self.database = DATABASE

    async def run_sql (
        self,
        sql: str,
        parameters: Optional[List[Dict[str, Any]]] = None,
        resource_arn: Optional[str] = None,
        secret_arn: Optional[str] = None,
        database: Optional[str] = None
    ) -> []: # type: ignore
        """
        Execute a SQL statement using the RDS Data API
        
        Args:
            sql: SQL query to execute
            parameters: List of parameters for the query
            resource_arn: Aurora cluster ARN (optional if set in constructor)
            secret_arn: Secrets Manager ARN (optional if set in constructor)
            database: Database name (optional if set in constructor)
            
        Returns:
            List of dictionaries containing the query results
        """
        execute_params = {
            'resourceArn': resource_arn or self.resource_arn,
            'secretArn': secret_arn or self.secret_arn,
            'database': database or self.database,
            'sql': sql,
            'includeResultMetadata':True
        }

        if parameters:
            execute_params['parameters'] = parameters

        try:
            result = self.client.execute_statement(**execute_params)
            # If no records, return empty list
            if 'records' not in result:
                return [[]]
            else: 
                # Extract Column Name 
                '''
                'columnMetadata': 
                    [
                        {'name': 'server_id', 'type': 12, 'typeName': 'text', 'label': 'server_id', 'schemaName': '', 'tableName': '', 'isAutoIncrement': False, 'isSigned': False, 'isCurrency': False, 'isCaseSensitive': True, 'nullable': 1, 'precision': 2147483647, 'scale': 0, 'arrayBaseColumnType': 0}, 
                        {'name': 'replica_lag_in_msec', 'type': 7, 'typeName': 'float4', 'label': 'replica_lag_in_msec', 'schemaName': '', 'tableName': '', 'isAutoIncrement': False, 'isSigned': True, 'isCurrency': False, 'isCaseSensitive': False, 'nullable': 1, 'precision': 8, 'scale': 8, 'arrayBaseColumnType': 0}
                    ],
                '''
                columnDetails = result['columnMetadata']
                columnNames = [row['name'] for row in columnDetails]
                # Extract Column Name 
                '''
                'records': [[{'stringValue': 'my-test-db-instance-1'}, {'isNull': True}], [{'stringValue': 'reader-1'}, {'doubleValue': 16.0}]],
                '''
                response = []
                for row in result['records']:
                    index = 0
                    response_row = []
                    for col in columnNames:
                        #print(f"Col: {col}")
                        #print(f"Row: {row[index]}")
                        for type, value in row[index].items(): 
                            response_row.append(RDSDataAPIResponse(col, type, value))
                            index += 1
                    response.append(response_row)
            
            return response

        except Exception as e:
            print(f"Error executing SQL: {str(e)}")
            raise

class AuroraReplicaStatus(BaseModel):
    server_id: str = Field(description="The DB instance ID (identifier)")
    replica_lag_in_msec: int = Field(description="Time that reader instance lags behind writer writer instance, in milliseconds.")

class APGReplicaStatusOutput(BaseModel):
    top_replica_lags: List[AuroraReplicaStatus] = Field(description="List of top replication status ordered by replica lag in decreasing order")

class TableName(BaseModel):
    table_name: str = Field(description="Table name")
    schema_name: str = Field(description="Schema name")

class ColumnInfo(BaseModel):
    name: str = Field(..., description="Column name")
    data_type: str = Field(..., description="PostgreSQL data type")
    comment: Optional[str] = Field(None, description="Column comment")

class IndexInfo(BaseModel):
    name: str = Field(..., description="Index name")
    definition: str = Field(..., description="Index definition")

class ConstraintInfo(BaseModel):
    name: str = Field(..., description="Constraint name")
    constraint_type: str = Field(..., description="Type of constraint: p=PK, f=FK, u=UNIQUE, c=CHECK")
    definition: str = Field(..., description="Constraint definition")

class TableInfo(BaseModel):
    name: str = Field(..., description="Table name")
    comment: Optional[str] = Field(None, description="Table comment")
    columns: List[ColumnInfo] = Field(..., description="List of column definitions")
    indexes: List[IndexInfo] = Field(..., description="List of indexes on the table")
    constraints: List[ConstraintInfo] = Field(..., description="List of constraints on the table")

logging.basicConfig(
    level=logging.INFO,   # ✅ Show INFO, WARNING, ERROR, CRITICAL
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

mcp = FastMCP(
    'apg-mcp MCP server. This is the starting point for all solutions created',
    dependencies=[
        'loguru',
    ],
)
@mcp.tool(
    name="list_table_names",
    description="Get all table names")

async def get_tables() -> List[TableName]:
    """Get all table names"""
    results = []
    try:
            table_query = """
                            SELECT tablename, schemaname 
                            FROM pg_catalog.pg_tables 
                            WHERE schemaname != 'pg_catalog' 
                            ORDER BY schemaname, tablename
                        """
            results = await RDSDataClient().run_sql(table_query)
        
            return [
                        TableName(
                            table_name=row[0].value,
                            schema_name=row[1].value)
                        for row in results
                    ]
        
    except RuntimeError as e:
        print("❌ Error:", e)

@mcp.tool()
async def run_query(sql : str) -> Any:
    """Run a query using Data API"""
    results = []
    try:
            RDSDataClient().run_sql("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;")
            table_query = sql
            return await RDSDataClient().run_sql(table_query)
    except RuntimeError as e:
        print("❌ Error:", e)

@mcp.tool(
        name="list_replica_lags",
        description="List read replica lags ordered by replica_lag_in_msec")
async def list_replica_lags() -> APGReplicaStatusOutput:
    """List read replica lags ordered by replica_lag_in_msec"""

    try:
        client = RDSDataClient()
        result =  await client.run_sql("SELECT server_id, replica_lag_in_msec FROM aurora_replica_status() ORDER BY replica_lag_in_msec DESC")
        stats = []
        for row in result:
            if (row[1].type == 'doubleValue'):
                replica_name=row[0].value
                replica_lag_in_msec=row[1].value
                stats.append(
                    AuroraReplicaStatus(
                        server_id=replica_name,
                        replica_lag_in_msec=replica_lag_in_msec))
        return APGReplicaStatusOutput(top_replica_lags=stats)
    except OperationalError as e:
        print("❌ Connection error:", e)
    except DatabaseError as e:
        print("❌ Query execution error:", e)
    except Exception as e:
        print("❌ Unexpected error:", e)

@mcp.tool(
        name = "create_aurora_postgres_serverless_cluster",
        description = 'Create a serverless Aurora PostgreSQL cluster',
        fields = [
            Field(name="cluster_name", type="string", description="Name of the cluster")
        ]
)
def create_aurora_postgres_serverless_cluster(cluster_name):
    """
    Creates a serverless Aurora PostgreSQL cluster.

    Args:
        cluster_name (str): The name of the Aurora cluster.
        engine (str): The database engine (e.g., 'aurora-mysql', 'aurora-postgresql').
        engine_version (str): The engine version (e.g., '5.6', '10.14').
        db_name (str): The name of the database.
        master_username (str): The master username for the database.
        master_password (str): The master password for the database.
        min_capacity (float): Minimum Aurora capacity unit.
        max_capacity (float): Maximum Aurora capacity unit.
        vpc_security_group_ids (list): List of VPC security group IDs.
        subnet_group_name (str): The name of the DB subnet group.

    Returns:
        dict: The response from the create_db_cluster API call.
    """
    rds_client = boto3.client('rds')
    response = rds_client.create_db_cluster(
        DBClusterIdentifier=cluster_name,
        Engine="aurora-postgresql",
        EngineVersion="16.6",
        DatabaseName="postgres",
        ServerlessV2ScalingConfiguration={
            'MinCapacity': 0.5,
            'MaxCapacity': 25
        },
        MasterUsername = "postgres",
        ManageMasterUserPassword=True,
        DeletionProtection=False,
        EnableHttpEndpoint=True
    )
    return response

def main():
    """Run the MCP server with CLI argument support."""
    parser = argparse.ArgumentParser(description='An AWS Labs Model Context Protocol (MCP) server for postgres')
    parser.add_argument('--sse', action='store_true', help='Use SSE transport')
    parser.add_argument('--port', type=int, default=8888, help='Port to run the server on')

    args = parser.parse_args()

    logger.trace('A trace message.')
    logger.debug('A debug message.')
    logger.info('An info message.')
    logger.success('A success message.')
    logger.warning('A warning message.')
    logger.error('An error message.')
    logger.critical('A critical message.')

    # Run server with appropriate transport
    if args.sse:
        mcp.settings.port = args.port
        mcp.run(transport='sse')
    else:
        mcp.run()

if __name__ == '__main__':
    main()
