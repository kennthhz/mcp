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

"""awslabs postgres MCP Server implementation."""

import argparse
import asyncio
import sys
import threading

from awslabs.postgres_mcp_server.connection.db_connection_map import DBConnectionMap
from awslabs.postgres_mcp_server.connection.rds_api_connection import RDSDataAPIConnection
from awslabs.postgres_mcp_server.connection.cp_api_connection import internal_create_cluster, internal_delete_cluster, get_rds_cluster_and_secret_arn
from awslabs.postgres_mcp_server.connection.psycopg_pool_connection import PsycopgPoolConnection
from awslabs.postgres_mcp_server.mutable_sql_detector import (
    check_sql_injection_risk,
    detect_mutating_keywords,
)
from botocore.exceptions import BotoCoreError, ClientError
from loguru import logger
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field
from typing import Annotated, Any, Dict, List, Optional
from datetime import datetime


db_connection_map = DBConnectionMap()
async_job_status: Dict[str, dict] = {}
async_job_status_lock = threading.Lock()
client_error_code_key = 'run_query ClientError code'
unexpected_error_key = 'run_query unexpected error'
write_query_prohibited_key = 'Your MCP tool only allows readonly query. If you want to write, change the MCP configuration per README.md'
query_comment_prohibited_key = 'The comment in query is prohibited because of injection risk'
query_injection_risk_key = 'Your query contains risky injection patterns'


class DummyCtx:
    """A dummy context class for error handling in MCP tools."""

    async def error(self, message):
        """Raise a runtime error with the given message.

        Args:
            message: The error message to include in the runtime error
        """
        # Do nothing
        pass


def extract_cell(cell: dict):
    """Extracts the scalar or array value from a single cell."""
    if cell.get('isNull'):
        return None
    for key in (
        'stringValue',
        'longValue',
        'doubleValue',
        'booleanValue',
        'blobValue',
        'arrayValue',
    ):
        if key in cell:
            return cell[key]
    return None


def parse_execute_response(response: dict) -> list[dict]:
    """Convert RDS Data API execute_statement response to list of rows."""
    columns = [col['name'] for col in response.get('columnMetadata', [])]
    records = []

    for row in response.get('records', []):
        row_data = {col: extract_cell(cell) for col, cell in zip(columns, row)}
        records.append(row_data)

    return records


mcp = FastMCP(
    'pg-mcp MCP server. This is the starting point for all solutions created',
    dependencies=[
        'loguru',
    ])


@mcp.tool(name='run_query', description='Run a SQL query against PostgreSQL')
async def run_query(
    sql: Annotated[str, Field(description='The SQL query to run')],
    ctx: Context,
    connection_key: Annotated[str, Field(description='Cluster identifier or Postgres instance host name')],
    database: Annotated[str, Field(description='database name')],
    query_parameters: Annotated[
        Optional[List[Dict[str, Any]]], Field(description='Parameters for the SQL query')
    ] = None) -> list[dict]:  # type: ignore

    """Run a SQL query against PostgreSQL.

    Args:
        sql: The sql statement to run
        ctx: MCP context for logging and state management
        connection_key: Cluster identifier or Aurora Postgres instance host name.
        database: database name
        query_parameters: Parameters for the SQL query

    Returns:
        List of dictionary that contains query response rows
    """
    global client_error_code_key
    global unexpected_error_key
    global write_query_prohibited_key
    global db_connection_map

    try:
        # Try to get the connection from the singleton
        db_connection = db_connection_map.get(connection_key, database)
    except RuntimeError:
        # If the singleton is not initialized, this might be a direct connection
        logger.error('No database connection available')
        await ctx.error('No database connection available')
        return [{'error': 'No database connection available'}]

    if db_connection.readonly_query:
        matches = detect_mutating_keywords(sql)
        if (bool)(matches):
            logger.info(
                f'query is rejected because current setting only allows readonly query. detected keywords: {matches}, SQL query: {sql}'
            )
            await ctx.error(write_query_prohibited_key)
            return [{'error': write_query_prohibited_key}]

    issues = check_sql_injection_risk(sql)
    if issues:
        logger.info(
            f'query is rejected because it contains risky SQL pattern, SQL query: {sql}, reasons: {issues}'
        )
        await ctx.error(
            str({'message': 'Query parameter contains suspicious pattern', 'details': issues})
        )
        return [{'error': query_injection_risk_key}]

    try:
        logger.info(f"run_query: sql:{sql} connection_key:{connection_key} database:{database} "
                    f"readonly:{db_connection.readonly_query} query_parameters:{query_parameters}")

        # Execute the query using the abstract connection interface
        response = await db_connection.execute_query(sql, query_parameters)

        logger.success(f'run_query successfully executed query:{sql}')
        return parse_execute_response(response)
    except ClientError as e:
        logger.exception(client_error_code_key)
        await ctx.error(
            str({'code': e.response['Error']['Code'], 'message': e.response['Error']['Message']})
        )
        return [{'error': client_error_code_key}]
    except Exception as e:
        logger.exception(unexpected_error_key)
        error_details = f'{type(e).__name__}: {str(e)}'
        await ctx.error(str({'message': error_details}))
        return [{'error': unexpected_error_key}]


@mcp.tool(
    name='get_table_schema',
    description='Fetch table columns and comments from Postgres')
async def get_table_schema(
    connection_key: Annotated[str, Field(description='Cluster identifier or instance host name')],
    database: Annotated[str, Field(description='database name')],
    table_name: Annotated[str, Field(description='name of the table')],
    ctx: Context) -> list[dict]:
    """Get a table's schema information given the table name.

    Args:
        connection_key: Cluster identifier or Aurora Postgres instance host name.
        database: database name
        table_name: name of the table
        ctx: MCP context for logging and state management

    Returns:
        List of dictionary that contains query response rows
    """
    logger.info(f"""get_table_schema: table_name:{table_name}
                    connection_key:{connection_key} database:{database}""")

    sql = """
        SELECT
            a.attname AS column_name,
            pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
            col_description(a.attrelid, a.attnum) AS column_comment
        FROM
            pg_attribute a
        WHERE
            a.attrelid = to_regclass(:table_name)
            AND a.attnum > 0
            AND NOT a.attisdropped
        ORDER BY a.attnum
    """

    params = [{'name': 'table_name', 'value': {'stringValue': table_name}}]

    return await run_query(sql=sql, ctx=ctx, 
                           connection_key=connection_key, database=database, 
                           query_parameters=params)

@mcp.tool(
    name='connect_to_database',
    description='Connect to a specific database and save the connection internally')
def connect_to_database(
    region: Annotated[str, Field(description='region')],
    cluster_identifier: Annotated[str, Field(description='cluster identifier')],
    database: Annotated[str, Field(description='database name')] = 'postgres',
    use_rds_api: Annotated[bool, Field(description='whether to use RDS API to connect to the databse')] = True)-> str:

    """Connect to a specific database and save the connection internally

    Args:
        region: region
        cluster_identifier: cluster identifier
        database: database name

    Returns:
        connection status
    """

    global db_connection_map
    value = None
    try:
        value = db_connection_map.get(cluster_identifier, database)
    except Exception as e:
        logger.error(e)
    if value is not None:
        logger.info(f"Connection already established for database {database} in {cluster_identifier} in region {region}")
        return f"Connection already established for database {database} in {cluster_identifier} in region {region}"
    else:
        logger.info(f"Establishing a new connection for database {database} in {cluster_identifier} in region {region} use_rds_api {use_rds_api}")
        if use_rds_api:
            cluster_arn, secret_arn = get_rds_cluster_and_secret_arn(cluster_identifier, region)

            if secret_arn is None:
                raise ValueError(f"Cluster {cluster_arn} doesn't have secret manager configured") 

            db_connection = RDSDataAPIConnection(
                    cluster_arn=cluster_arn,
                    secret_arn=str(secret_arn),
                    database=database,
                    region=region,
                    readonly=False)
            
            db_connection_map.set(cluster_identifier, database, db_connection)
            return f"Established a new RDS API connection for database {database} in {cluster_identifier} in region {region}"
        else:
            raise NotImplementedError("direct connect not supported yet in connect_to_database")
            

@mcp.tool(
    name='is_database_connected',
    description='Check if a connection has been established for a given database')
def is_database_connected(
    region: Annotated[str, Field(description='region')],
    connection_key: Annotated[str, Field(description='cluster identifier or instance host name')],
    database: Annotated[str, Field(description='database name')] = 'postgres') -> bool:


    """Check if a connection has been established for a given database'

    Args:
        region: region
        cluster_identifier: cluster identifier
        database: database name

    Returns:
        result in boolean
    """

    global db_connection_map
    value = db_connection_map.get(connection_key, database)
    if value is not None:
        return True
    else:
        return False

@mcp.tool(
    name='start_create_cluster',
    description='Start a background job to create a RDS or Aurora Postgres cluster')
def start_create_cluster_job(
    region: Annotated[str, Field(description='region')],
    cluster_identifier: Annotated[str, Field(description='cluster identifier')],
    database: Annotated[str, Field(description='default database name')] = 'postgres',
    engine_version: Annotated[str, Field(description='engine version')] = '17.5') -> str:

    """Start a background job to create a RDS or Aurora Postgres cluster

    Args:
        region: region
        cluster_identifier: cluster identifier
        database: database name
        engine_version: engine version

    Returns:
        job id
    """

    job_id = f"create-cluster-{cluster_identifier}-{datetime.now().isoformat(timespec='milliseconds')}"

    t = threading.Thread(
        target=create_cluster_worker,
        args=(job_id, region, cluster_identifier, engine_version, database),
        daemon=True,
    )
    t.start()

    logger.info(f"start_create_cluster_job return with job_id:{job_id}"
                f"region:{region} cluster_identifier:{cluster_identifier} database:{database} engine_version:{engine_version}")
    return job_id


@mcp.tool(
    name='start_delete_cluster_job',
    description='Start a background job to delete a RDS or Aurora Postgres cluster and its instances')
def start_delete_cluster_job(
    region: Annotated[str, Field(description='region')],
    cluster_identifier: Annotated[str, Field(description='cluster identifier')])-> str:

    """Start a background job to delete a RDS or Aurora Postgres cluster and its instances

    Args:
        region: region
        cluster_identifier: cluster identifier

    Returns:
         job id
    """
    global async_job_status
    global async_job_status_lock

    job_id = f"delete-cluster-{cluster_identifier}-{datetime.now().isoformat(timespec='milliseconds')}"

    try:
        async_job_status_lock.acquire()
        async_job_status[job_id] = {"state":"pending", "result":None}
    finally:
        async_job_status_lock.release()

    t = threading.Thread(
        target=delete_cluster_worker,
        args=(job_id, region, cluster_identifier),
        daemon=True,
    )
    t.start()

    logger.info(f"start_delete_cluster_job return with job_id:{job_id}"
                f"region:{region} cluster_identifier:{cluster_identifier}")
    return job_id


@mcp.tool(
    name='get_job_status',
    description='get background job status')
def get_job_status(job_id: str) -> dict:

    """Get background job status

    Args:
        job_id: job id
    Returns:
        job status
    """
    global async_job_status
    global async_job_status_lock

    try:
        async_job_status_lock.acquire()
        return async_job_status.get(job_id, {"state": "not_found"})
    finally:
        async_job_status_lock.release()

def create_cluster_worker(job_id:str, region:str, cluster_identifier:str, engine_version:str, database:str):
    global db_connection_map
    global async_job_status
    global async_job_status_lock

    try:

        try:
            async_job_status_lock.acquire()
            async_job_status[job_id] = {"state":"pending", "result":None}
        finally:
            async_job_status_lock.release()

        cluster_arn, secret_arn = internal_create_cluster(region, cluster_identifier, engine_version, database)
        db_connection = RDSDataAPIConnection(
                cluster_arn=cluster_arn,
                secret_arn=secret_arn,
                database=database,
                region=region,
                readonly=False)
        
        db_connection_map.set(cluster_identifier, database, db_connection)
        async_job_status_lock.acquire()
        async_job_status[job_id]["state"] = "succeeded"
        async_job_status_lock.release()
    except Exception as e:
            async_job_status[job_id]["state"] = "failed"
            async_job_status[job_id]["result"] = str(e)

def delete_cluster_worker(job_id:str, region:str, cluster_identifier:str):
    try:
        internal_delete_cluster(region, cluster_identifier)
        async_job_status[job_id]["state"] = "succeeded"
    except Exception as e:
            async_job_status[job_id]["state"] = "failed"
            async_job_status[job_id]["result"] = str(e)

#@mcp.tool(
#    name='get_available_db_connection_keys',
#    description='get a list of available db connections keys')
#def get_available_db_connection_keys():
#    global db_connection_map

#   db_connection_map.


def main():

    """Main entry point for the MCP server application."""
    global client_error_code_key
    global db_connection_map

    """Run the MCP server with CLI argument support."""
    parser = argparse.ArgumentParser(
        description='An AWS Labs Model Context Protocol (MCP) server for postgres'
    )

    # Connection method 1: RDS Data API
    parser.add_argument('--resource_arn', help='ARN of the RDS cluster (for RDS Data API)')

    # Connection method 2: Psycopg Direct Connection
    parser.add_argument('--hostname', help='Database hostname (for direct PostgreSQL connection)')
    parser.add_argument('--port', type=int, default=5432, help='Database port (default: 5432)')

    # Common parameters
    parser.add_argument('--secret_arn',
        help='ARN of the Secrets Manager secret for database credentials')
    parser.add_argument('--database', help='Database name')
    parser.add_argument('--region', help='AWS region')
    parser.add_argument('--readonly', required=True, help='Enforce readonly SQL statements')

    args = parser.parse_args()

    if args.resource_arn and args.hostname:
        parser.error(
            'Cannot specify both --resource_arn and --hostname. Choose one connection method.'
        )

    # Convert readonly string to boolean
    readonly = args.readonly.lower() == 'true'

    if args.resource_arn:
        logger.info(
            f"""Postgres MCP init with RDS Data API: CONNECTION_TARGET:{args.resource_arn},
                SECRET_ARN:{args.secret_arn}, REGION:{args.region}, DATABASE:{args.database},
                READONLY:{args.readonly}"""
        )
    if args.hostname:
        logger.info(
            f"""Postgres MCP init with psycopg: CONNECTION_TARGET:{args.hostname}, 
                PORT:{args.port}, DATABASE:{args.database}, READONLY:{args.readonly}"""
        )

    # Create the appropriate database connection based on the provided parameters
    db_connection = None
    connection_key = None

    try:
        if args.resource_arn:
            # Use RDS Data API with singleton pattern
            try:
                # Initialize the RDS Data API connection
                db_connection = RDSDataAPIConnection(
                    cluster_arn=args.resource_arn,
                    secret_arn=args.secret_arn,
                    database=args.database,
                    region=args.region,
                    readonly=readonly
                )

                db_connection_map.set(args.resource_arn, args.database, db_connection)
                connection_key = args.resource_arn

            except Exception as e:
                logger.exception(f'Failed to create RDS Data API connection: {str(e)}')
                sys.exit(1)

        elif args.hostname:
            # Use Direct PostgreSQL connection using psycopg connection pool
            try:
                # Create a direct PostgreSQL connection pool
                db_connection = PsycopgPoolConnection(
                    host=args.hostname,
                    port=args.port,
                    database=args.database,
                    readonly=readonly,
                    secret_arn=args.secret_arn,
                    region=args.region,
                )

                db_connection_map.set(args.hostname, args.database, db_connection)
                connection_key = args.hostname

            except Exception as e:
                logger.exception(f'Failed to create PostgreSQL connection: {str(e)}')
                sys.exit(1)

        # Test database connection
        if connection_key:
            ctx = DummyCtx()
            response = asyncio.run(run_query('SELECT 1', ctx, connection_key, args.database ))
            if (
                isinstance(response, list)
                and len(response) == 1
                and isinstance(response[0], dict)
                and 'error' in response[0]
            ):
                logger.error('Failed to validate database connection to Postgres. Exit the MCP server')
                sys.exit(1)
            else:
                logger.success('Successfully validated database connection to Postgres')

    except BotoCoreError as e:
        logger.exception(f'Failed to create database connection: {str(e)}')
        sys.exit(1)

    logger.info('Postgres MCP server started')
    mcp.run()

async def test():
    job_id = await start_create_cluster_job('us-west-2','kiro-test-2','postgres','17.4')
    logger.info(f"start_create_cluster return job id: {job_id}")
    while True:
        result = await get_job_status(job_id)
        if result["state"] == "succeeded":
            logger.info(f"{job_id} succeeded")
            break
        if result["state"] == "failed":
            logger.error(f"{job_id} failed")
            break
        await asyncio.sleep(1)

    
    ctx = Context()
    response = await run_query('CREATE TABLE test(id INT, data TEXT)', ctx, 'kiro-test-2', 'postgres')
    logger.info(f'response:{response}')


    
    #job_id = await start_delete_cluster_job('us-west-2','kiro-test-2')
    #logger.info(f"start_delete_cluster return job id: {job_id}")
    #while True:
    #    result = await get_job_status(job_id)
    #    if result["state"] == "succeeded":
    #        logger.info(f"{job_id} succeeded")
    #        break
    #    if result["state"] == "failed":
    #        logger.error(f"{job_id} failed")
    #        break
    #    await asyncio.sleep(1)


if __name__ == '__main__':
    #asyncio.run(test())
    main()
