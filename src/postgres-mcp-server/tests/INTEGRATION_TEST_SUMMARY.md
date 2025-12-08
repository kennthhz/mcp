# Integration Test Suite Summary

## Overview

This integration test suite provides comprehensive testing of all MCP tool functions in the Postgres MCP Server against real AWS resources.

## Files Created

### 1. `test_integration.py` (Main Test Suite)
**Purpose**: Contains all integration test classes and test functions

**Test Classes**:
- `TestClusterCreation`: Tests cluster creation (regular and express)
- `TestDatabaseConnection`: Tests all connection methods
- `TestQueryExecution`: Tests query execution across connection methods
- `TestDDLOperations`: Tests CREATE TABLE, DROP TABLE, schema retrieval
- `TestDMLOperations`: Tests INSERT, SELECT, UPDATE, DELETE operations
- `TestReadonlyMode`: Tests readonly mode enforcement
- `TestSQLInjectionProtection`: Tests SQL injection detection
- `TestJobStatus`: Tests background job status tracking

**Total Test Functions**: 20+

### 2. `integration_test_config.yaml` (Configuration)
**Purpose**: Defines test configuration including:
- AWS region and account ID
- Cluster configurations (regular and express)
- MCP server configuration variants (readonly/readwrite)
- Test data schemas and sample data
- Test scenarios and expected behaviors
- Cleanup options

### 3. `integration_test_config.local.yaml.template` (Local Config Template)
**Purpose**: Template for creating local configuration
- Copy to `integration_test_config.local.yaml`
- Customize with your AWS details
- Gitignored to prevent committing sensitive info

### 4. `INTEGRATION_TESTS_README.md` (Documentation)
**Purpose**: Comprehensive documentation including:
- Setup instructions
- Configuration guide
- Running tests (all variations)
- Test coverage matrix
- Troubleshooting guide
- Best practices
- CI/CD integration examples

### 5. `run_integration_tests.sh` (Test Runner Script)
**Purpose**: Convenient script to run integration tests
- Interactive prompts
- Configuration validation
- AWS credential checks
- Test filtering options
- Coverage report generation

## MCP Tools Coverage

| Tool | Test Coverage | Notes |
|------|---------------|-------|
| `create_cluster` | ✅ Complete | Regular (async) and Express (sync) |
| `connect_to_database` | ✅ Complete | All 3 connection methods |
| `is_database_connected` | ✅ Complete | Connection verification |
| `get_database_connection_info` | ✅ Complete | List all connections |
| `run_query` | ✅ Complete | All query types (SELECT, DDL, DML) |
| `get_table_schema` | ✅ Complete | Schema retrieval and validation |
| `get_job_status` | ✅ Complete | Job tracking and status |

## Connection Methods Coverage

| Method | Description | Test Coverage |
|--------|-------------|---------------|
| `rdsapi` | RDS Data API (HTTP) | ✅ Regular clusters |
| `pgwire` | PG Wire + Secrets Manager | ✅ Regular clusters |
| `pgwire_iam` | PG Wire + IAM auth | ✅ Both regular and express clusters |

## Query Types Coverage

| Query Type | Readonly | Readwrite | Test Class |
|------------|----------|-----------|------------|
| SELECT | ✅ | ✅ | `TestQueryExecution` |
| CREATE TABLE | ❌ | ✅ | `TestDDLOperations` |
| INSERT | ❌ | ✅ | `TestDMLOperations` |
| UPDATE | ❌ | ✅ | `TestDMLOperations` |
| DELETE | ❌ | ✅ | `TestDMLOperations` |
| DROP TABLE | ❌ | ✅ | `TestDDLOperations` |

## Quick Start

### 1. Setup Configuration
```bash
cd tests
cp integration_test_config.local.yaml.template integration_test_config.local.yaml
# Edit integration_test_config.local.yaml with your AWS details
```

### 2. Install Dependencies
```bash
pip install -e ".[dev]"
```

### 3. Configure AWS Credentials
```bash
export AWS_PROFILE=your-profile
# OR
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
```

### 4. Run Tests

**Using the script (recommended)**:
```bash
./tests/run_integration_tests.sh
```

**Using pytest directly**:
```bash
# All integration tests
pytest tests/test_integration.py -v -m integration

# Specific test class
pytest tests/test_integration.py::TestQueryExecution -v

# With coverage
pytest tests/test_integration.py -v -m integration --cov=awslabs.postgres_mcp_server
```

## Test Execution Flow

### Phase 1: Cluster Creation (5-10 minutes)
1. Create regular Aurora Serverless v2 cluster (async)
2. Poll job status until completion
3. Create express configuration cluster (sync, <1 minute)
4. Verify cluster endpoints and configuration

### Phase 2: Connection Testing (<1 minute)
1. Test RDS API connection to regular cluster
2. Test PG Wire IAM connection to express cluster
3. Test PG Wire Secrets Manager connection (if configured)
4. Verify connection caching and retrieval

### Phase 3: Query Execution (<1 minute)
1. Run SELECT queries on all connection methods
2. Test parameterized queries
3. Verify query results and error handling

### Phase 4: DDL Operations (<1 minute)
1. Create test tables
2. Retrieve and validate table schemas
3. Drop test tables
4. Verify schema information accuracy

### Phase 5: DML Operations (<1 minute)
1. Insert test data
2. Select and verify data
3. Update existing data
4. Delete data
5. Verify data integrity

### Phase 6: Security Testing (<1 minute)
1. Test readonly mode enforcement
2. Test SQL injection detection
3. Verify malicious patterns are blocked

**Total Estimated Time**: 10-15 minutes (first run with cluster creation)

## Configuration Options

### MCP Server Configurations Tested

1. **Readonly Mode** (`allow_write_query: false`)
   - SELECT queries: ✅ Allowed
   - Write operations: ❌ Blocked

2. **Readwrite Mode** (`allow_write_query: true`)
   - SELECT queries: ✅ Allowed
   - Write operations: ✅ Allowed

### Cluster Types Tested

1. **Regular Aurora Serverless v2**
   - Connection: RDS Data API (preferred)
   - Connection: PG Wire + Secrets Manager (requires setup)
   - Connection: PG Wire + IAM authentication
   - Creation: Async (5-10 minutes)
   - Endpoint: `*.rds.amazonaws.com`

2. **Express Configuration**
   - Connection: PG Wire + IAM authentication
   - Creation: Sync (<1 minute)
   - Endpoint: `*.rds-preview.amazonaws.com`

## Test Data

### Tables Created
- `test_integration_table`: General testing
- `test_dml_table`: DML operations testing
- `test_products`: Sample product data
- `test_users`: Sample user data

### Cleanup
- Test tables are automatically dropped after tests (configurable)
- Clusters are NOT deleted by default (configurable)

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run integration tests
  run: |
    pytest tests/test_integration.py -v -m integration
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
```

### GitLab CI Example
```yaml
integration-tests:
  script:
    - pip install -e ".[dev]"
    - pytest tests/test_integration.py -v -m integration
  variables:
    AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY
```

## Troubleshooting

### Common Issues

1. **Cluster creation timeout**
   - Increase timeout in config
   - Check AWS service health
   - Verify IAM permissions

2. **Connection failures**
   - Verify cluster is "available"
   - Check security groups
   - Ensure public accessibility (for pgwire)

3. **Test data conflicts**
   - Use unique cluster identifiers
   - Enable cleanup options
   - Manually drop test tables if needed

### Debug Commands

```bash
# Verbose output
pytest tests/test_integration.py -v -s -m integration

# Debug logging
export LOGURU_LEVEL=DEBUG
pytest tests/test_integration.py -v -m integration

# Run single test
pytest tests/test_integration.py::TestQueryExecution::test_run_select_query_rds_api -v
```

## Best Practices

1. **Use dedicated test clusters** - Don't test against production
2. **Enable cleanup** - Set `delete_clusters_after_tests: true` for CI/CD
3. **Monitor costs** - Test clusters incur charges
4. **Parallel execution** - Use `pytest-xdist` for faster runs
5. **Cache clusters** - Reuse clusters across test runs when possible

## Metrics

- **Test Functions**: 20+
- **Test Classes**: 8
- **MCP Tools Covered**: 7/7 (100%)
- **Connection Methods**: 3/3 (100%)
- **Query Types**: 6 (SELECT, CREATE, INSERT, UPDATE, DELETE, DROP)
- **Estimated Runtime**: 10-15 minutes (first run), 2-3 minutes (subsequent)

## Future Enhancements

Potential additions to the test suite:

1. **Performance Testing**
   - Query execution time benchmarks
   - Connection pool performance
   - Large dataset handling

2. **Failure Scenarios**
   - Network interruption handling
   - IAM token expiration
   - Connection pool exhaustion

3. **Multi-Database Testing**
   - Multiple databases per cluster
   - Cross-database queries
   - Database switching

4. **Advanced Security**
   - Row-level security testing
   - Column-level encryption
   - Audit logging verification

5. **Concurrent Operations**
   - Parallel query execution
   - Connection pool stress testing
   - Transaction isolation testing

## Support

For questions or issues:
- Review `INTEGRATION_TESTS_README.md` for detailed documentation
- Check `MCP_TEST_CASES.md` for manual test scenarios
- Open GitHub issue with test logs and configuration
