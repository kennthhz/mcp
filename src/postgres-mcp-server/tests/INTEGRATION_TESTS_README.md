# Integration Tests for Postgres MCP Server

This directory contains integration tests that test all `@mcp.tool` functions against real AWS resources.

## Overview

The integration test suite (`test_integration.py`) provides comprehensive testing of:

- **Cluster Creation**: Regular and Express Aurora PostgreSQL clusters
- **Database Connections**: RDS API, PG Wire Protocol, and PG Wire with IAM
- **Query Execution**: SELECT, INSERT, UPDATE, DELETE operations
- **DDL Operations**: CREATE TABLE, DROP TABLE, schema retrieval
- **DML Operations**: Data manipulation across different connection methods
- **Readonly Mode**: Enforcement of readonly query restrictions
- **SQL Injection Protection**: Detection and blocking of malicious patterns
- **Job Status Tracking**: Background job monitoring

## Configuration

### Setup Configuration File

1. Copy the template configuration:
   ```bash
   cp tests/integration_test_config.local.yaml.template tests/integration_test_config.local.yaml
   ```

2. Edit `integration_test_config.local.yaml` with your AWS details:
   ```yaml
   aws:
     region: us-east-2
   
   clusters:
     regular:
       cluster_identifier: "your-test-cluster-name"
       endpoint: "your-cluster.cluster-abc123.us-east-2.rds.amazonaws.com"  # REQUIRED
       port: 5432
     express:
       cluster_identifier: "your-express-cluster-name"
       endpoint: "your-express.cluster-xyz789.us-east-2.rds-preview.amazonaws.com"  # REQUIRED
       port: 5432
   ```

3. Get your cluster endpoints:
   ```bash
   # For regular clusters
   aws rds describe-db-clusters \
     --db-cluster-identifier your-cluster-name \
     --query 'DBClusters[0].Endpoint' \
     --output text
   
   # For express clusters
   aws rds describe-db-clusters \
     --db-cluster-identifier your-express-cluster \
     --endpoint-url https://rds-preview.us-east-2.amazonaws.com \
     --query 'DBClusters[0].Endpoint' \
     --output text
   ```

3. The test suite will use `integration_test_config.local.yaml` if it exists, otherwise falls back to `integration_test_config.yaml`.

### Configuration Options

#### AWS Configuration
- `region`: AWS region for test resources (e.g., `us-east-2`)
- `account_id`: Your AWS account ID

#### Cluster Configuration
- **Regular Cluster**: Aurora Serverless v2 with RDS Data API
  - `cluster_identifier`: Unique cluster name
  - `connection_methods`: `rdsapi`, `pgwire` (requires specific setup)
  
- **Express Cluster**: Fast-provisioning cluster with IAM auth
  - `cluster_identifier`: Unique cluster name
  - `connection_methods`: `pgwire_iam`

#### MCP Configuration Variants
- `readonly`: Tests with `allow_write_query: false`
- `readwrite`: Tests with `allow_write_query: true`

#### Cleanup Options
- `delete_clusters_after_tests`: Auto-delete test clusters (default: `false`)
- `drop_test_tables`: Drop test tables after completion (default: `true`)

## Running Tests

### Run All Integration Tests
```bash
pytest tests/test_integration.py -v -m integration
```

### Run Specific Test Classes
```bash
# Test cluster creation only
pytest tests/test_integration.py::TestClusterCreation -v

# Test database connections only
pytest tests/test_integration.py::TestDatabaseConnection -v

# Test query execution only
pytest tests/test_integration.py::TestQueryExecution -v

# Test DDL operations only
pytest tests/test_integration.py::TestDDLOperations -v

# Test DML operations only
pytest tests/test_integration.py::TestDMLOperations -v

# Test readonly mode only
pytest tests/test_integration.py::TestReadonlyMode -v

# Test SQL injection protection only
pytest tests/test_integration.py::TestSQLInjectionProtection -v
```

### Run Specific Test Functions
```bash
# Test creating regular cluster
pytest tests/test_integration.py::TestClusterCreation::test_create_regular_cluster -v

# Test RDS API connection
pytest tests/test_integration.py::TestDatabaseConnection::test_connect_via_rds_api -v

# Test SELECT query
pytest tests/test_integration.py::TestQueryExecution::test_run_select_query_rds_api -v
```

### Skip Integration Tests
```bash
# Run all tests except integration tests
pytest tests/ -v -m "not integration"
```

### Run with Coverage
```bash
pytest tests/test_integration.py -v -m integration --cov=awslabs.postgres_mcp_server --cov-report=html
```

## Test Coverage

### MCP Tools Tested

| Tool | Test Coverage | Test Classes |
|------|---------------|--------------|
| `create_cluster` | ✅ Regular & Express | `TestClusterCreation` |
| `connect_to_database` | ✅ All connection methods | `TestDatabaseConnection` |
| `is_database_connected` | ✅ Connection verification | `TestDatabaseConnection` |
| `get_database_connection_info` | ✅ Connection listing | `TestDatabaseConnection` |
| `run_query` | ✅ All query types | `TestQueryExecution`, `TestDDLOperations`, `TestDMLOperations` |
| `get_table_schema` | ✅ Schema retrieval | `TestDDLOperations` |
| `get_job_status` | ✅ Job tracking | `TestJobStatus` |

### Connection Methods Tested

| Method | Description | Test Coverage |
|--------|-------------|---------------|
| `rdsapi` | RDS Data API (HTTP-based) | ✅ Regular clusters |
| `pgwire` | PG Wire with Secrets Manager | ✅ Regular clusters (requires setup) |
| `pgwire_iam` | PG Wire with IAM authentication | ✅ Both regular and express clusters |

### Query Types Tested

| Query Type | Readonly Mode | Readwrite Mode |
|------------|---------------|----------------|
| SELECT | ✅ Allowed | ✅ Allowed |
| CREATE TABLE | ❌ Blocked | ✅ Allowed |
| INSERT | ❌ Blocked | ✅ Allowed |
| UPDATE | ❌ Blocked | ✅ Allowed |
| DELETE | ❌ Blocked | ✅ Allowed |
| DROP TABLE | ❌ Blocked | ✅ Allowed |

## Prerequisites

### AWS Resources
1. **AWS Account**: Valid AWS credentials configured
2. **IAM Permissions**: Permissions to create/manage Aurora clusters
3. **VPC Setup**: Default VPC or custom VPC with proper networking

### Required Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:CreateDBCluster",
        "rds:DescribeDBClusters",
        "rds:ModifyDBCluster",
        "rds:DeleteDBCluster",
        "rds:CreateDBInstance",
        "rds:DescribeDBInstances",
        "rds-data:ExecuteStatement",
        "rds-data:BatchExecuteStatement",
        "secretsmanager:GetSecretValue",
        "iam:CreatePolicy",
        "iam:AttachUserPolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

### Python Dependencies
All dependencies are specified in `pyproject.toml`:
- `pytest>=8.0.0`
- `pytest-asyncio>=0.26.0`
- `pytest-cov>=4.1.0`
- `pytest-mock>=3.12.0`
- `pyyaml` (for config loading)

Install dev dependencies:
```bash
pip install -e ".[dev]"
```

## Test Workflow

### 1. Cluster Creation Tests
- Creates regular Aurora Serverless v2 cluster (async)
- Creates express configuration cluster (sync)
- Polls job status for async operations
- Verifies cluster endpoints and configuration

### 2. Connection Tests
- Tests RDS Data API connection
- Tests PG Wire Protocol with IAM
- Tests PG Wire Protocol with Secrets Manager
- Verifies connection caching and reuse

### 3. Query Execution Tests
- Runs SELECT queries on different connection methods
- Tests parameterized queries
- Verifies query results and error handling

### 4. DDL Operation Tests
- Creates test tables
- Retrieves table schemas
- Drops test tables
- Verifies schema information accuracy

### 5. DML Operation Tests
- Inserts test data
- Selects and verifies data
- Updates existing data
- Deletes data
- Verifies data integrity

### 6. Security Tests
- Tests readonly mode enforcement
- Tests SQL injection detection
- Verifies malicious patterns are blocked

## Troubleshooting

### Common Issues

#### 1. Cluster Creation Timeout
**Problem**: Cluster creation exceeds 10-minute timeout

**Solution**:
- Increase `max_wait` in test configuration
- Check AWS service health
- Verify IAM permissions

#### 2. Connection Failures
**Problem**: Cannot connect to cluster

**Solution**:
- Verify cluster is in "available" state
- Check security group rules
- Ensure cluster is publicly accessible (for pgwire)
- Verify RDS Data API is enabled (for rdsapi)

#### 3. PG Wire Connection Issues
**Problem**: pgwire connection fails

**Solution**:
- Ensure cluster is publicly accessible
- Verify security group allows inbound on port 5432
- Check that Secrets Manager secret exists
- For express clusters, use `pgwire_iam` instead of `pgwire`

#### 4. Readonly Mode Tests Fail
**Problem**: Write operations succeed in readonly mode

**Solution**:
- Verify `readonly_query` global variable is set correctly
- Check monkeypatch is working in test
- Ensure connection was created with readonly flag

#### 5. Test Data Cleanup Issues
**Problem**: Test tables not cleaned up

**Solution**:
- Check `cleanup.drop_test_tables` in config
- Manually drop tables: `DROP TABLE IF EXISTS test_*`
- Verify test fixtures are running cleanup code

### Debug Mode

Run tests with verbose output:
```bash
pytest tests/test_integration.py -v -s -m integration
```

Enable debug logging:
```bash
export LOGURU_LEVEL=DEBUG
pytest tests/test_integration.py -v -m integration
```

## Best Practices

### 1. Use Separate Test Clusters
- Don't run integration tests against production clusters
- Use dedicated test clusters with clear naming (e.g., `mcp-test-*`)

### 2. Clean Up Resources
- Enable `delete_clusters_after_tests` for CI/CD pipelines
- Manually verify cleanup after test runs
- Monitor AWS costs for orphaned resources

### 3. Parallel Execution
- Integration tests can be slow (cluster creation ~5-10 minutes)
- Consider running tests in parallel with `pytest-xdist`:
  ```bash
  pytest tests/test_integration.py -n auto -m integration
  ```

### 4. CI/CD Integration
- Use GitHub Actions secrets for AWS credentials
- Cache cluster creation across test runs
- Set reasonable timeouts for CI pipelines

### 5. Test Data Management
- Use unique identifiers for test data
- Clean up test data in fixtures
- Avoid hardcoded values that may conflict

## Example CI/CD Configuration

### GitHub Actions
```yaml
name: Integration Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-2
      
      - name: Run integration tests
        run: |
          pytest tests/test_integration.py -v -m integration
        env:
          AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
```

## Contributing

When adding new MCP tools:

1. Add corresponding integration tests in `test_integration.py`
2. Update test configuration in `integration_test_config.yaml`
3. Document new test cases in this README
4. Ensure tests cover all connection methods
5. Add both positive and negative test cases

## Support

For issues or questions:
- Check existing test cases for examples
- Review MCP_TEST_CASES.md for manual test scenarios
- Open an issue on GitHub with test logs
