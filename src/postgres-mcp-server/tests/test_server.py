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
"""Tests for the postgres MCP Server."""

import asyncio
import pytest
import json
import uuid
import datetime
import decimal
from conftest import Mock_DBConnection
from awslabs.postgres_mcp_server.server import run_query, DBConnectionSingleton
from awslabs.postgres_mcp_server.mutable_sql_detector import detect_mutating_keywords

def wrap_value(val):
    """
    Convert a Python value into an AWS RDS Data API-compatible field dict.
    """
    if isinstance(val, str):
        return {"stringValue": val}
    elif isinstance(val, bool):
        return {"booleanValue": val}
    elif isinstance(val, int):
        return {"longValue": val}
    elif isinstance(val, float):
        return {"doubleValue": val}
    elif isinstance(val, decimal.Decimal):
        return {"stringValue": str(val)}
    elif isinstance(val, uuid.UUID):
        return {"stringValue": str(val)}
    elif isinstance(val, datetime.datetime):
        return {"stringValue": val.isoformat()}
    elif isinstance(val, datetime.date):
        return {"stringValue": val.isoformat()}
    elif isinstance(val, datetime.time):
        return {"stringValue": val.isoformat()}
    elif isinstance(val, list):
        return {"arrayValue": {"stringValues": [str(v) for v in val]}}
    elif isinstance(val, dict):
        return {"stringValue": json.dumps(val)}
    elif val is None:
        return {"isNull": True}
    else:
        raise TypeError(f"Unsupported value type: {type(val)}")


def mock_execute_statement_response(
    columns: list[str],
    rows: list[list],
    number_of_records_updated: int = 0,
    generated_fields: list = None
):
    """
    Generate a complete mock RDS Data API response from a SQL query.
    """
    return {
        "columnMetadata": [
            {
                "name": col,
                "label": col,
                "typeName": "text",  # simplified for mocking
                "nullable": True,
                "isSigned": False,
                "arrayBaseColumnType": 0,
                "scale": 0,
                "precision": 0,
                "type": 12  # JDBC type for VARCHAR
            }
            for col in columns
        ],
        "records": [
            [wrap_value(cell) for cell in row]
            for row in rows
        ],
        "numberOfRecordsUpdated": number_of_records_updated,
        "generatedFields": generated_fields or [],
        "formattedRecords": "",
        "responseMetadata": {
            "RequestId": "mock-request-id",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "content-type": "application/x-amz-json-1.1",
                "x-amzn-requestid": "mock-request-id",
                "content-length": "123"
            },
            "RetryAttempts": 0
        }
    }

@pytest.mark.asyncio
async def test_run_query_well_formatted_response():
    DBConnectionSingleton.initialize('mock', 'mock', 'mock', 'mock', readonly = True, is_test = True)
    mock_db_connection = Mock_DBConnection(True)

    columns = [
    "text_column", "boolean_column", "integer_column", "float_column", "numeric_column",
    "uuid_column", "timestamp_column", "date_column", "time_column", "text_array_column", "json_column", "null_column"
    ]

    row = [
        "Hello world",                            # TEXT
        True,                                     # BOOLEAN
        123,                                      # INTEGER
        45.67,                                    # FLOAT
        decimal.Decimal("12345.6789"),            # NUMERIC
        uuid.uuid4(),                             # UUID
        datetime.datetime(2023, 1, 1, 12, 0),      # TIMESTAMP
        datetime.date(2023, 1, 1),                # DATE
        datetime.time(14, 30),                    # TIME
        ["one", "two", "three"],                 # TEXT[]
        {"key": "value", "flag": True},           # JSON
        None                                      # NULL
    ]

    sql_text="SELECT * FROM example_table"
    response = mock_execute_statement_response(
        columns=columns,
        rows=[row]
    )

    mock_db_connection.data_client.add_mock_response(response)
    tool_response = await run_query(sql_text, mock_db_connection)

    #validate tool_response
    assert(isinstance(tool_response, (list, tuple)) and len(tool_response) == 1 and isinstance(tool_response[0], dict))
    column_records = tool_response[0]
    assert(len(column_records) == len(columns))
    for col_name in columns:
        assert(col_name in column_records)

@pytest.mark.asyncio
def test_run_query_readonly_allowed():
    allowed_sqls = [
        r"""-- Select with join]
        SELECT u.id, u.name, o.order_date, o.total
        FROM users u
        JOIN orders o ON u.id = o.user_id
        WHERE o.total > 100
        ORDER BY o.order_date DESC
        LIMIT 10;""",

        r"""-- Aggregation with GROUP BY and HAVING
        SELECT department_id, COUNT(*) AS employee_count, AVG(salary) AS avg_salary
        FROM employees
        GROUP BY department_id
        HAVING COUNT(*) > 5;""",

        """-- Subquery in WHERE UPDATE
        SELECT *
        FROM products
        WHERE price < (
            SELECT AVG(price)
            FROM products
        );""",

        r"""-- CTE and Window Function
        WITH ranked_orders AS (
            SELECT
                o.*,
                RANK() OVER (PARTITION BY user_id ORDER BY order_date DESC) AS rank
            FROM orders o
        )
        SELECT *
        FROM ranked_orders
        WHERE rank = 1;""",

        r"""-- EXISTS with correlated subquery
        SELECT name
        FROM customers c
        WHERE EXISTS (
            SELECT 1
            FROM orders o
            WHERE o.customer_id = c.id
            AND o.status = 'shipped'
        );""",

        r"""-- Subquery in FROM clause (derived table)
        SELECT avg_by_category.category_id, avg_by_category.avg_price
        FROM (
            SELECT category_id, AVG(price) AS avg_price
            FROM products
            GROUP BY category_id
        ) AS avg_by_category
        WHERE avg_price > 50;""",

        r"""-- SELECT with CASE expression
        SELECT
            id,
            name,
            CASE
                WHEN score >= 90 THEN 'A'
                WHEN score >= 80 THEN 'B'
                WHEN score >= 70 THEN 'C'
                ELSE 'F'
            END AS grade
        FROM students;""",

        r"""-- Windowed aggregates with ROW_NUMBER
        SELECT
            *,
            ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) AS salary_rank
        FROM employees;""",

        r"""-- IN and BETWEEN usage
        SELECT *
        FROM sales
        WHERE region IN ('North', 'South')
        AND sale_date BETWEEN '2023-01-01' AND '2023-12-31';""",

        r"""-- Pattern match with LIKE
        SELECT name
        FROM customers
        WHERE email LIKE '%@gmail.com';""",
        
        r"""SELECT 'This is not a real DELETE statement' AS example;""",
        r"""SELECT "DROP" FROM actions;""",
        r"""SELECT * FROM logs WHERE message LIKE '%CREATE TABLE%';""",
        r"""SELECT json_extract_path_text(payload, 'DROP TABLE users') FROM logs;""",
        r"""SELECT 1 /* DROP TABLE abc */;""",
        r"""-- DELETE FROM customers;
        SELECT * FROM customers;"""]
    
    for sql in allowed_sqls:
        assert(not detect_mutating_keywords(sql))

if __name__ == "__main__":
    DBConnectionSingleton.initialize('mock', 'mock', 'mock', 'mock', readonly = True, is_test = True)
    asyncio.run(test_run_query_well_formatted_response())
    test_run_query_readonly_allowed()