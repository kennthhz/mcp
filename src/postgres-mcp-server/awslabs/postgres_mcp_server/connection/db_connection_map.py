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

"""Database connection map for postgres MCP Server."""

from typing import Annotated
from pydantic import Field
from awslabs.postgres_mcp_server.connection.abstract_db_connection import AbstractDBConnection
from awslabs.postgres_mcp_server.connection.rds_api_connection import RDSDataAPIConnection
from loguru import logger
import threading

db_connection_map_lock = threading.Lock()

class DBConnectionMap:
    """Manages Postgres DB connection map"""

    def __init__(self):
        self.map = dict()
    
    def get(
        self,
        connection_key: Annotated[str, Field(description='Cluster identifer or host name, must not be None')],
        database: Annotated[str, Field(description='Database name, must not be None')]
    ) -> AbstractDBConnection:
        global db_connection_map_lock

        if not connection_key:
            raise ValueError("connection_key cannot be None or empty") 
        
        if not database:
            raise ValueError("database cannot be None or empty") 
        
        try:
            db_connection_map_lock.acquire()
            return self.map[(connection_key, database)]
        finally:
            db_connection_map_lock.release()

    def set(
        self,
        connection_key: Annotated[str, Field(description='Cluster identifer or host name, must not be None')],
        database: Annotated[str, Field(description='Database name, must not be None')],
        conn: Annotated[AbstractDBConnection, Field(description='Connection objec, must not be None')]
    ) -> None:
        if not connection_key:
            raise ValueError("connection_key cannot be None or empty") 
        
        if not database:
            raise ValueError("database cannot be None or empty")
        
        try:
            db_connection_map_lock.acquire()
            self.map[(connection_key, database)] = conn
        finally:
            db_connection_map_lock.release()

    def get_keys(self) -> list[str]:
        try:
            db_connection_map_lock.acquire()
            keys_copy = list(self.map.keys())
            return keys_copy
        finally:
            db_connection_map_lock.release()

