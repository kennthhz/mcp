# Endpoint Configuration in Integration Tests

## Overview

The integration test suite requires cluster endpoints to be explicitly specified in the configuration file. This provides clear, explicit configuration and avoids runtime AWS API calls.

## How It Works

### 1. Configuration File

Endpoints are specified in `integration_test_config.yaml` (or `integration_test_config.local.yaml`):

```yaml
clusters:
  regular:
    cluster_identifier: "my-cluster"
    endpoint: "my-cluster.cluster-abc123.us-east-2.rds.amazonaws.com"  # REQUIRED
    port: 5432
    database: "postgres"
    
  express:
    cluster_identifier: "my-express-cluster"
    endpoint: "my-express-cluster.cluster-xyz789.us-east-2.rds-preview.amazonaws.com"  # REQUIRED
    port: 5432
    database: "postgres"
```

### 2. Cluster Endpoints Fixture

The `cluster_endpoints` fixture (session-scoped) reads endpoints from the configuration:

```python
@pytest.fixture(scope='session')
def cluster_endpoints(integration_config):
    """Get cluster endpoints from configuration."""
    endpoints = {}
    
    # Get regular cluster endpoint from config
    regular_config = integration_config['clusters']['regular']
    endpoints['regular'] = {
        'endpoint': regular_config.get('endpoint', ''),
        'port': regular_config.get('port', 5432),
        'cluster_identifier': regular_config['cluster_identifier']
    }
    
    # Similar for express cluster...
    
    return endpoints
```

### 2. Usage in Tests

Tests inject the `cluster_endpoints` fixture and use the resolved endpoints:

```python
@pytest.mark.asyncio
async def test_connect_via_rds_api(
    self, integration_config, aws_region, cluster_endpoints
):
    cluster_config = integration_config['clusters']['regular']
    cluster_id = cluster_config['cluster_identifier']
    endpoint_info = cluster_endpoints['regular']  # Get resolved endpoint
    
    result_str = connect_to_database(
        region=aws_region,
        database_type=DatabaseType.APG,
        connection_method=ConnectionMethod.RDS_API,
        cluster_identifier=cluster_id,
        db_endpoint=endpoint_info['endpoint'],  # Use actual endpoint
        port=endpoint_info['port'],              # Use actual port
        database=cluster_config['database'],
        with_express_configuration=False
    )
```

### 3. Graceful Handling of Missing Endpoints

If an endpoint is not specified in the config, tests skip execution:

```python
# Skip if endpoint not available
if not endpoint_info['endpoint']:
    pytest.skip('Regular cluster endpoint not available')
```

This allows you to:
- Run tests for only the clusters you have configured
- Skip tests for clusters that don't exist yet
- Gradually add cluster configurations as needed

## Configuration Flow

```
Test Session Start
    ↓
Load integration_test_config.yaml (or .local.yaml)
    ↓
cluster_endpoints fixture executes
    ↓
For each cluster in config:
    ├─ Read endpoint from config
    ├─ Read port from config (default: 5432)
    ├─ Read cluster_identifier from config
    └─ Store in endpoints dictionary
    ↓
Tests execute with configured endpoints
    ↓
If endpoint missing/empty → pytest.skip()
If endpoint present → test runs with configured endpoint
```

## Benefits

### 1. **Explicit Configuration**
- Endpoints clearly specified in config file
- No hidden AWS API calls during test execution
- Easy to see what clusters tests will use

### 2. **Simple and Predictable**
- No runtime endpoint resolution
- No AWS credentials needed just to load config
- Tests use exactly what you configure

### 3. **Flexible Configuration**
- Change endpoints in config file
- Support multiple environments (dev, staging, prod)
- No code changes needed for different clusters

### 4. **Graceful Degradation**
- Tests skip if endpoints not configured
- Allows running subset of tests
- Clear skip messages explain why

### 5. **Fast Test Startup**
- No AWS API calls during fixture setup
- Instant configuration loading
- Faster test execution

## Endpoint Information Retrieved

For each cluster, the fixture retrieves:

| Property | Description | Example |
|----------|-------------|---------|
| `endpoint` | Cluster writer endpoint | `my-cluster.cluster-abc123.us-east-2.rds.amazonaws.com` |
| `port` | PostgreSQL port | `5432` |
| `cluster_identifier` | Cluster identifier | `my-cluster` |

## Connection Methods and Endpoints

Different connection methods use endpoints differently:

### RDS Data API (`rdsapi`)
- **Endpoint Usage**: Optional (can be empty)
- **Why**: RDS Data API uses cluster ARN, not endpoint
- **Resolution**: Endpoint retrieved but may not be used directly

### PG Wire Protocol (`pgwire`)
- **Endpoint Usage**: Required
- **Why**: Direct PostgreSQL connection needs hostname
- **Resolution**: Must have valid endpoint or test skips

### PG Wire with IAM (`pgwire_iam`)
- **Endpoint Usage**: Required
- **Why**: Direct PostgreSQL connection with IAM auth needs hostname
- **Resolution**: Must have valid endpoint or test skips

## How to Get Your Cluster Endpoint

### Option 1: AWS Console
1. Go to RDS Console
2. Click on your cluster
3. Copy the "Endpoint" value from the "Connectivity & security" tab

### Option 2: AWS CLI
```bash
# For regular clusters
aws rds describe-db-clusters \
  --db-cluster-identifier my-cluster \
  --query 'DBClusters[0].Endpoint' \
  --output text

# For express clusters (use preview endpoint)
aws rds describe-db-clusters \
  --db-cluster-identifier my-express-cluster \
  --endpoint-url https://rds-preview.us-east-2.amazonaws.com \
  --query 'DBClusters[0].Endpoint' \
  --output text
```

### Option 3: After Cluster Creation
When you create a cluster using the `create_cluster` tool, the endpoint is returned in the response:

```json
{
  "status": "Completed",
  "cluster_identifier": "my-cluster",
  "db_endpoint": "my-cluster.cluster-abc123.us-east-2.rds.amazonaws.com"
}
```

## Example Configuration

### Regular Cluster
```yaml
clusters:
  regular:
    cluster_identifier: "my-test-cluster"
    endpoint: "my-test-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com"
    port: 5432
    database: "postgres"
```

### Express Cluster
```yaml
clusters:
  express:
    cluster_identifier: "my-express-cluster"
    endpoint: "my-express-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com"
    port: 5432
    database: "postgres"
```

Note the different domain: `rds-preview.amazonaws.com` for express clusters.

## Troubleshooting

### Issue: "Cluster endpoint not available" skip message

**Cause**: Endpoint not specified in configuration file

**Solutions**:
1. Add the `endpoint` field to your cluster configuration
2. Get the endpoint from AWS Console or CLI (see "How to Get Your Cluster Endpoint" above)
3. Update `integration_test_config.yaml` or `integration_test_config.local.yaml`
4. Ensure the endpoint is not empty or commented out

### Issue: Connection timeout even with valid endpoint

**Cause**: Network connectivity issues

**Solutions**:
1. Verify cluster is publicly accessible (for pgwire connections)
2. Check security group allows inbound on port 5432
3. Verify VPC/subnet configuration
4. Check if running from allowed IP range

### Issue: Endpoint resolves but connection fails

**Cause**: Cluster not ready or authentication issues

**Solutions**:
1. Verify cluster status is "available"
2. Check IAM authentication is enabled (for pgwire_iam)
3. Verify Secrets Manager secret exists (for pgwire)
4. Check RDS Data API is enabled (for rdsapi)

## Advanced: Environment Variable Override

You can override endpoints using environment variables for CI/CD:

```python
@pytest.fixture(scope='session')
def cluster_endpoints(integration_config):
    """Get endpoints from config or environment variables."""
    regular_config = integration_config['clusters']['regular']
    express_config = integration_config['clusters']['express']
    
    return {
        'regular': {
            'endpoint': os.environ.get('TEST_REGULAR_ENDPOINT', regular_config.get('endpoint', '')),
            'port': int(os.environ.get('TEST_REGULAR_PORT', regular_config.get('port', 5432))),
            'cluster_identifier': regular_config['cluster_identifier']
        },
        'express': {
            'endpoint': os.environ.get('TEST_EXPRESS_ENDPOINT', express_config.get('endpoint', '')),
            'port': int(os.environ.get('TEST_EXPRESS_PORT', express_config.get('port', 5432))),
            'cluster_identifier': express_config['cluster_identifier']
        }
    }
```

Then in CI/CD:
```bash
export TEST_REGULAR_ENDPOINT="my-cluster.cluster-abc123.us-east-2.rds.amazonaws.com"
export TEST_EXPRESS_ENDPOINT="my-express.cluster-xyz789.us-east-2.rds-preview.amazonaws.com"
pytest tests/test_integration.py -v -m integration
```

## Summary

The integration test suite uses **explicit endpoint configuration** to:
- ✅ Provide clear, visible configuration
- ✅ Avoid runtime AWS API calls
- ✅ Work with any cluster configuration
- ✅ Test real network connectivity
- ✅ Gracefully handle missing endpoints
- ✅ Support multiple environments
- ✅ Enable fast test startup

This approach ensures tests are simple, predictable, and easy to configure for any environment.
