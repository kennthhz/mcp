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
import sys
import asyncio
from loguru import logger
from typing import Optional, List, Dict, Annotated, Any
import boto3
from botocore.exceptions import ClientError
from pydantic import Field
from mcp.server.fastmcp import FastMCP

class DBConnection:
    def __init__(self, cluster_arn, secret_arn, database, region):
        self.cluster_arn = cluster_arn
        self.secret_arn = secret_arn
        self.database = database
        self.data_client = boto3.client('rds-data', region_name = region)

class DBConnectionSingleton:
    _instance = None

    def __init__(self, resource_arn, secret_arn, database, region):
        if not all([resource_arn, secret_arn, database, region]):
            raise ValueError("All connection parameters must be provided for initial initialization")
        self._db_connection = DBConnection(resource_arn, secret_arn, database, region)

    @classmethod
    def initialize(cls, resource_arn, secret_arn, database, region):
        if cls._instance is None:
            cls._instance = cls(resource_arn, secret_arn, database, region)

    @classmethod
    def get(cls):
        if cls._instance is None:
            raise RuntimeError("DBConnectionSingleton is not initialized.")
        return cls._instance
    
    @property
    def db_connection(self):
        return self._db_connection

def extract_cell(cell: dict):
    """Extracts the scalar or array value from a single cell"""
    if cell.get("isNull"):
        return None
    for key in (
        "stringValue", "longValue", "doubleValue", "booleanValue", "blobValue", "arrayValue"
    ):
        if key in cell:
            return cell[key]
    return None

def parse_execute_response(response: dict) -> list[dict]:
    """Convert RDS Data API execute_statement response to list of rows"""
    columns = [col["name"] for col in response.get("columnMetadata", [])]
    records = []

    for row in response.get("records", []):
        row_data = {col: extract_cell(cell) for col, cell in zip(columns, row)}
        records.append(row_data)

    return records

mcp = FastMCP(
    'apg-mcp MCP server. This is the starting point for all solutions created',
    dependencies=[
        'loguru',
    ],
)

@mcp.tool(
    name = "run_query",
    description = 'Run a SQL query using boto3 execute_statement'
)
async def run_query(
    sql : Annotated[str, Field(description="The SQL query to run")], 
    query_parameters: Annotated[Optional[List[Dict[str, Any]]], Field(description="Parameters for the SQL query")] = None) -> list[dict]:
    try:
        logger.info(f"run_query: {sql}")

        db_connection = DBConnectionSingleton.get().db_connection

        execute_params = {
            'resourceArn': db_connection.cluster_arn,
            'secretArn': db_connection.secret_arn,
            'database': db_connection.database,
            'sql': sql,
            'includeResultMetadata':True
        }

        if query_parameters:
            execute_params['parameters'] = query_parameters
        
        response = await asyncio.to_thread(db_connection.data_client.execute_statement, **execute_params)
        
        logger.success("run_query successfully executed query:{}", sql)
        return parse_execute_response(response)
    except ClientError as e:
        logger.error(f"run_query ClientError: {e.response['Error']['Message']}")
        return [{"run_query ClientError": f"{type(e).__name__}: {str(e)}"}]
    except Exception as e:
        logger.error(f"run_query unexpected error: {e.response['Error']['Message']}")
        return [{"run_query unexpected error": f"{type(e).__name__}: {str(e)}"}]

@mcp.tool(
    name="get_table_schema",
    description="Fetch table columns and comments from Postgres using RDS Data API"
)
async def get_table_schema(table_name: Annotated[str, Field(description="name of the table")]) -> list[dict]:
    try:
        logger.info(f"get_table_schema: {table_name}")

        sql = """
            SELECT 
                a.attname AS column_name,
                pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
                col_description(a.attrelid, a.attnum) AS column_comment
            FROM 
                pg_attribute a
            WHERE 
                a.attrelid = %s::regclass
                AND a.attnum > 0
                AND NOT a.attisdropped
            ORDER BY a.attnum
        """

        parameters = [ {
                "name": "table",  # name is ignored, position matters
                "value": {"stringValue": table_name}
            }
        ]

        response = await run_query.run_sql(sql, parameters)
        logger.success("Successfully get_table_schema:{}", table_name)

        columns = response.get("records", [])
        tool_response = [
            {
                "column_name": col[0]["stringValue"],
                "data_type": col[1]["stringValue"],
                "comment": col[2].get("stringValue") if len(col) > 2 and "stringValue" in col[2] else None
            }
            for col in columns
        ]

        return tool_response
    except ClientError as e:
        logger.error(f"get_table_schema error: {e.response['Error']['Message']}")
        return [{"get_table_schema ClientError": f"{type(e).__name__}: {str(e)}"}]
    except Exception as e:
        logger.error(f"get_table_schema unexpected error: {e.response['Error']['Message']}")
        return [{"get_table_schema unexpected": f"{type(e).__name__}: {str(e)}"}]

def main():
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
        DBConnectionSingleton.initialize(args.resource_arn, args.secret_arn, args.database, args.region)
        asyncio.run(run_query('SELECT 1'))
    except Exception as e:
        logger.exception("Failed to create and validate db connection to Postgres. Exit the MCP server")
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
