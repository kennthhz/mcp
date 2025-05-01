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
        logger.error(f"AWS ClientError: {e.response['Error']['Message']}")
        return {"error": f"AWS error: {e.response['Error']['Message']}"}

    except Exception as e:
        logger.exception("Unexpected error during query execution")
        return {"error": f"Unexpected error: {str(e)}"}

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
