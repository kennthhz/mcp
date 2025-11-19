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

import threading
from enum import Enum
from loguru import logger

from awslabs.postgres_mcp_server.connection.abstract_db_connection import AbstractDBConnection

class ConnectionMethod(str, Enum):
    RDS_API = "rdsapi"
    PG_WIRE_PROTOCOL = "pgwire"

class DBConnectionMap:
    """Manages Postgres DB connection map"""

    def __init__(self):
        self.map = {} 
        self._lock = threading.Lock()
    
    def get(
        self,
        method: ConnectionMethod,
        cluster_identifier: str,
        db_endpoint: str,
        database: str,
    ) -> AbstractDBConnection | None:

        if not method:
            raise ValueError("method cannot be None")
         
        if not cluster_identifier:
            raise ValueError("cluster_identifier cannot be None or empty") 
        
        if not database:
            raise ValueError("database cannot be None or empty") 
        
        with self._lock:
            return self.map.get((method, cluster_identifier, db_endpoint, database))

    def set(
        self,
        method: ConnectionMethod,
        cluster_identifier: str,
        db_endpoint: str,
        database: str,
        conn: AbstractDBConnection
    ) -> None:
        if not cluster_identifier:
            raise ValueError("cluster_identifier cannot be None or empty") 
        
        if not database:
            raise ValueError("database cannot be None or empty")
        
        if not conn:
            raise ValueError("conn cannot be None")
        
        with self._lock:
            self.map[(method, cluster_identifier, db_endpoint, database)] = conn

    def remove(
        self,
        method: ConnectionMethod,
        cluster_identifier: str,
        db_endpoint: str,
        database: str,
    ) -> None:
        if not cluster_identifier:
            raise ValueError("cluster_identifier cannot be None or empty") 
        
        if not database:
            raise ValueError("database cannot be None or empty")
        
        with self._lock:
            try:
                self.map.pop((method, cluster_identifier, db_endpoint, database))
            except KeyError:
                logger.info(f"Try to remove a non-existing connection. {method} {cluster_identifier} {db_endpoint} {database}")

    def get_keys(self) -> list[tuple[ConnectionMethod, str, str, str]]:
        with self._lock:
            return list(self.map.keys())

    def close_all(self) -> None:
        """Close all connections and clear the map."""
        with self._lock:
            for key, conn in self.map.items():
                try:
                    conn.close()
                except Exception as e:
                    logger.warning(f"Failed to close connection {key}: {e}")
            self.map.clear()