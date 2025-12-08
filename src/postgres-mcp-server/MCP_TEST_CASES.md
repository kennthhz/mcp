# MCP Manual Test Cases - Postgres Server

**Test Session Started:** 2025-11-24  
**MCP Server Version:** 1.0.10  
**Tester:** goelshar

---

## Test Environment Setup

- **Server:** postgres-mcp-server
- **Region:** [To be filled during testing]
- **Readonly Mode:** [To be filled during testing]
- **Connection Method:** [RDS_API / PG_WIRE_PROTOCOL]

---

## Test Cases

### TC-001: Create Aurora PostgreSQL Cluster
**Status:** ✅ Pass  

**Objective:**  
Test the create_cluster tool to provision a new Aurora Serverless v2 PostgreSQL cluster

**Prompt:**  
```
Create a new Aurora PostgreSQL cluster named 'regular-cluster' in us-east-2 region
```

**Tool Calls:**
```json
{
  "tool": "create_cluster",
  "params": {
    "region": "us-east-2",
    "cluster_identifier": "regular-cluster",
    "database": "postgres",
    "engine_version": "17.5",
    "with_express_configuration": false
  }
}
```

**Response:**
```json
{
  "status": "Pending",
  "message": "cluster creation started",
  "job_id": "create-cluster-regular-cluster-2025-11-24T15:50:42.526",
  "cluster_identifier": "regular-cluster",
  "check_status_tool": "get_job_status",
  "next_action": "Use get_job_status(job_id='create-cluster-regular-cluster-2025-11-24T15:50:42.526') to get results"
}
```

**Follow-up Tool Calls:**
```json
{
  "tool": "get_job_status",
  "params": {
    "job_id": "create-cluster-regular-cluster-2025-11-24T15:50:42.526"
  }
}
```

**Final Status:**
```json
{
  "state": "succeeded",
  "result": null
}
```

**Duration:** ~5-10 minutes (async operation)  
**Notes:** 
- Cluster creation is asynchronous and runs in background thread
- Job status polling required to check completion
- Automatically sets up IAM policies and database connection
- Serverless v2 cluster with default scaling configuration

**Conversation Log:**
```
User: Create a new Aurora PostgreSQL cluster named 'regular-cluster' in us-east-2 region
Assistant: [Calls create_cluster tool]
Assistant: Great! The cluster creation has started. Job ID: create-cluster-regular-cluster-2025-11-24T15:50:42.526

User: Yes keep checking every 1 minute until it is complete
Assistant: [Explains manual polling needed]

User: status
Assistant: [Calls get_job_status] Still pending...

User: status
Assistant: [Calls get_job_status] ✅ Cluster creation succeeded!

```

---

### TC-002: Create Express Configuration Cluster
**Status:** ✅ Pass  

**Objective:**  
Test the create_cluster tool with express configuration enabled for faster synchronous cluster creation

**Prompt:**  
```
Create a cluster named 'ufc-cluster' with express configuration in us-east-2 region
```

**Tool Calls:**
```json
{
  "tool": "create_cluster",
  "params": {
    "region": "us-east-2",
    "cluster_identifier": "ufc-cluster",
    "database": "postgres",
    "engine_version": "17.5",
    "with_express_configuration": true
  }
}
```

**Response:**
```json
{
  "status": "Completed",
  "cluster_identifier": "ufc-cluster",
  "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
  "message": "Express cluster creation completed successfully"
}
```

**Duration:** < 1 minute (synchronous operation)  
**Notes:** 
- Express configuration creates cluster synchronously (no background job)
- Uses RDS preview endpoint (rds-preview.amazonaws.com)
- Much faster than regular cluster creation
- Automatically sets up IAM policies and establishes connection
- No job polling required - returns immediately when complete

**Conversation Log:**
```
User: Create a cluster named 'ufc-cluster' with express configuration in us-east-2 region
Assistant: [Calls create_cluster with with_express_configuration=true]
Assistant: ✅ Express cluster created successfully! Endpoint: ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com

```

---

### TC-003: Connect to Cluster via RDS API
**Status:** ✅ Pass  

**Objective:**  
Test the connect_to_database tool to establish connection using RDS Data API method

**Prompt:**  
```
Connect to my Aurora cluster 'regular-cluster' using RDS API connection method
```

**Tool Calls:**
```json
{
  "tool": "is_database_connected",
  "params": {
    "cluster_identifier": "regular-cluster",
    "database": "postgres"
  }
}
```

**Initial Check Response:**
```json
false
```

**Connection Tool Call:**
```json
{
  "tool": "connect_to_database",
  "params": {
    "region": "us-east-2",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-abc123.us-east-2.rds.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "with_express_configuration": false
  }
}
```

**Response:**
```json
{
  "connection_method": "rdsapi",
  "cluster_identifier": "regular-cluster",
  "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres"
}
```

**Duration:** < 5 seconds  
**Notes:** 
- Connection automatically detected RDS Data API was enabled on cluster
- Used RDS API connection method (HTTP-based, no connection pooling)
- Connection is cached in db_connection_map for reuse
- Fetches cluster properties to determine best connection method
- Retrieves secret ARN from cluster metadata for authentication

**Conversation Log:**
```
User: Connect to my Aurora cluster 'regular-cluster' using RDS API connection method
Assistant: [Calls is_database_connected] The cluster isn't connected yet
Assistant: [Calls connect_to_database]
Assistant: ✅ Connected successfully! Method: RDS API, Endpoint: regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com

```

---

### TC-004: Connect to Express Cluster with IAM Authentication
**Status:** ✅ Pass  

**Objective:**  
Test connection to express configuration cluster and verify it uses PG Wire Protocol with IAM authentication (pgwire_iam)

**Prompt:**  
```
Create an express cluster with identifier ufc-2, connect to it, and query the version
```

**Step 1: Create Express Cluster**
```json
{
  "tool": "create_cluster",
  "params": {
    "region": "us-east-2",
    "cluster_identifier": "ufc-2",
    "database": "postgres",
    "engine_version": "17.5",
    "with_express_configuration": true
  }
}
```

**Create Response:**
```json
{
  "status": "Completed",
  "cluster_identifier": "ufc-2",
  "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
  "message": "Express cluster creation completed successfully"
}
```

**Step 2: Connect with pgwire_iam**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "APG",
    "region": "us-east-2",
    "cluster_identifier": "ufc-2",
    "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "connection_method": "pgwire_iam",
    "with_express_configuration": true
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire_iam",
  "cluster_identifier": "ufc-2",
  "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Step 3: Query Database Version**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire_iam",
    "cluster_identifier": "ufc-2",
    "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT version()"
  }
}
```

**Query Response:**
```json
{
  "version": "PostgreSQL 17.4 on aarch64-unknown-linux-gnu, compiled by aarch64-unknown-linux-gnu-gcc (GCC) 10.5.0, 64-bit"
}
```

**Step 4: Create Sample Table**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire_iam",
    "cluster_identifier": "ufc-2",
    "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "CREATE TABLE products (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, price DECIMAL(10,2), category VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
  }
}
```

**Response:**
```
(No output - successful execution)
```

**Step 5: Insert Sample Data**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire_iam",
    "cluster_identifier": "ufc-2",
    "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "INSERT INTO products (name, price, category) VALUES ('Laptop', 999.99, 'Electronics'), ('Coffee Mug', 12.50, 'Kitchen'), ('Notebook', 5.99, 'Office'), ('Headphones', 79.99, 'Electronics')"
  }
}
```

**Response:**
```
(No output - successful execution)
```

**Step 6: Query Sample Data**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire_iam",
    "cluster_identifier": "ufc-2",
    "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT * FROM products ORDER BY id"
  }
}
```

**Query Response:**
```json
{
  "id": 1,
  "name": "Laptop",
  "price": "999.99",
  "category": "Electronics",
  "created_at": "2025-12-04 00:02:35.498753"
}
{
  "id": 2,
  "name": "Coffee Mug",
  "price": "12.50",
  "category": "Kitchen",
  "created_at": "2025-12-04 00:02:35.498753"
}
{
  "id": 3,
  "name": "Notebook",
  "price": "5.99",
  "category": "Office",
  "created_at": "2025-12-04 00:02:35.498753"
}
{
  "id": 4,
  "name": "Headphones",
  "price": "79.99",
  "category": "Electronics",
  "created_at": "2025-12-04 00:02:35.498753"
}
```

**Duration:** < 3 minutes (including cluster creation)  
**Notes:** 
- **Key Finding:** Express clusters require `pgwire_iam` connection method for IAM authentication
- ✅ DDL operations (CREATE TABLE) work correctly
- ✅ DML operations (INSERT, SELECT) work correctly
- Uses IAM token-based authentication (generate_db_auth_token)
- Different from regular clusters which prefer RDS Data API
- Connection method must be explicitly specified as `pgwire_iam`
- IAM tokens are temporary (~15 minutes validity)
- Direct PostgreSQL connection with connection pooling
- Express clusters are created in preview region (rds-preview.amazonaws.com)
- PostgreSQL version 17.4 on ARM64 architecture
- Write operations require `--allow_write_query` flag in MCP configuration

**Conversation Log:**
```
User: create an express cluster with identifier ufc-2
Assistant: [Calls create_cluster with with_express_configuration=true]
Assistant: ✅ Express cluster created! Endpoint: ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com

User: connect to it
Assistant: [Calls connect_to_database with connection_method=pgwire_iam]
Assistant: ✅ Connected successfully! Method: pgwire_iam

User: run select version()
Assistant: [Executes query]
Assistant: ✅ PostgreSQL 17.4 on aarch64-unknown-linux-gnu

User: create a sample table and insert rows
Assistant: [Creates products table with 5 columns]
Assistant: [Inserts 4 product records]
Assistant: [Queries all data]
Assistant: ✅ Table created with 4 products
```

---

### TC-004a: Query Express Cluster via RDS API (Extension of TC-004)
**Status:** ❌ Fail  

**Objective:**  
Attempt to query express cluster using RDS API connection method to verify connection method enforcement

**Prompt:**  
```
select cluster_info table via RDS api in ufc-cluster
```

**Tool Calls:**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "rdsapi",
    "cluster_identifier": "ufc-cluster",
    "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT * FROM cluster_info"
  }
}
```

**Response:**
```json
{
  "error": [
    "No database connection available for method:rdsapi,",
    " cluster_identifier:ufc-cluster, db_endpoint:ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com, database:postgres"
  ]
}
```

**Attempted Reconnection:**
```json
{
  "tool": "connect_to_database",
  "params": {
    "region": "us-east-2",
    "cluster_identifier": "ufc-cluster",
    "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "with_express_configuration": true
  }
}
```

**Reconnection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "ufc-cluster",
  "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
  "database": "postgres"
}
```

**Duration:** < 5 seconds  
**Notes:** 
- **Key Finding:** Express clusters with IAM auth CANNOT use RDS API connection
- Connection logic automatically selects pgwire for express configuration
- No way to force RDS API connection for express clusters
- This is by design - express clusters require IAM authentication via pgwire
- Mirror opposite of TC-006a (regular clusters cannot use pgwire)
- Query succeeds when using pgwire connection method instead

**Conversation Log:**
```
User: select cluster_info table via RDS api in ufc-cluster
Assistant: [Attempts query with rdsapi] ❌ Error: No rdsapi connection available
Assistant: [Attempts to connect] Still returns pgwire connection
Assistant: ❌ Cannot query via RDS API - express clusters always use pgwire with IAM
```

---

### TC-004b: Attempt pgwire Connection to Express Cluster (Extension of TC-004)
**Status:** ❌ Fail  

**Objective:**  
Verify that express clusters cannot use pgwire (Secrets Manager) connection method and require pgwire_iam (IAM authentication)

**Prompt:**  
```
Query version of the ufc-cluster with pgwire connection
```

**Tool Calls - Attempt 1 (pgwire):**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "APG",
    "region": "us-east-2",
    "cluster_identifier": "ufc-cluster",
    "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "connection_method": "pgwire",
    "with_express_configuration": false
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "ufc-cluster",
  "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Query Attempt:**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "ufc-cluster",
    "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT version()"
  }
}
```

**Query Response:**
```json
{
  "error": "run_query unexpected error"
}
```

**Tool Calls - Attempt 2 (pgwire_iam - Correct Method):**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "APG",
    "region": "us-east-2",
    "cluster_identifier": "ufc-2",
    "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "connection_method": "pgwire_iam",
    "with_express_configuration": true
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire_iam",
  "cluster_identifier": "ufc-2",
  "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Query Response:**
```json
{
  "version": "PostgreSQL 17.4 on aarch64-unknown-linux-gnu, compiled by aarch64-unknown-linux-gnu-gcc (GCC) 10.5.0, 64-bit"
}
```

**Duration:** < 10 seconds  
**Notes:** 
- **Key Finding:** Express clusters do NOT support pgwire (Secrets Manager) connection method
- pgwire connection appears to succeed but queries fail with "unexpected error"
- Express clusters have no Secrets Manager secrets associated - they use IAM authentication only
- Must use `pgwire_iam` connection method for express clusters
- This is by design - express clusters are configured for IAM authentication, not Secrets Manager
- Regular clusters with Secrets Manager work fine with pgwire (see TC-011)
- Demonstrates the authentication method difference between regular and express clusters

**Conversation Log:**
```
User: Query version of the ufc-cluster with pgwire
Assistant: [Attempts connection with pgwire]
Assistant: [Attempts query] ❌ Error: "run_query unexpected error"

User: try again
Assistant: [Retries multiple times] ❌ Still failing

User: can you try pgwire_iam connection
Assistant: [Connects with pgwire_iam]
Assistant: [Queries version] ✅ Success! PostgreSQL 17.4
Assistant: Express clusters require pgwire_iam, not pgwire
```

---

### TC-005: List All Cached Connections
**Status:** ✅ Pass  

**Objective:**  
Test the get_database_connection_info tool to retrieve all cached database connections

**Prompt:**  
```
Show me all connections
```

**Tool Calls:**
```json
{
  "tool": "get_database_connection_info"
}
```

**Response:**
```json
[
  {
    "connection_method": "rdsapi",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres"
  },
  {
    "connection_method": "pgwire",
    "cluster_identifier": "ufc-cluster",
    "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres"
  }
]
```

**Duration:** < 1 second  
**Notes:** 
- Returns all connections cached in db_connection_map
- Shows connection method, cluster ID, endpoint, and database name
- Useful for debugging and connection management
- Connections persist until server restart or expiration
- No tool available to manually drop/close individual connections

**Conversation Log:**
```
User: Show me all connections
Assistant: [Calls get_database_connection_info]
Assistant: Shows 2 active connections (regular-cluster via RDS API, ufc-cluster via pgwire)

```

---

### TC-006: Connect to Regular Cluster via Direct Connection
**Status:** ✅ Pass  

**Objective:**  
Test connecting to a regular Aurora cluster using direct connection method (pgwire)

**Prompt:**  
```
Connect to my Aurora cluster 'regular-cluster' using direct connection method
```

**Tool Calls:**
```json
{
  "tool": "connect_to_database",
  "params": {
    "db_endpoint": "regular-cluster.cluster-cni82m4m0h5z.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "with_express_configuration": false,
    "cluster_identifier": "regular-cluster",
    "region": "us-east-2",
    "port": 5432
  }
}
```

**Response:**
```json
{
  "connection_method": "rdsapi",
  "cluster_identifier": "regular-cluster",
  "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres"
}
```

**Duration:** < 5 seconds  
**Notes:** 
- **Key Finding:** Regular cluster defaulted to RDS API method even when requesting direct connection
- Connection method is auto-selected based on cluster capabilities
- RDS API is preferred when available on regular clusters
- Direct pgwire connection would be used if RDS API is unavailable or IAM auth is required
- Endpoint resolved to actual cluster endpoint (different from input)

**Conversation Log:**
```
User: Connect to my Aurora cluster 'regular-cluster' using direct connection method
Assistant: [Calls connect_to_database with with_express_configuration=false]
Assistant: ✅ Connected successfully using RDS API method (auto-selected)
Assistant: Note: Connection defaulted to RDS API. Direct pgwire would be used if RDS API isn't available

```

---

### TC-006a: Connect to Regular Cluster via PG Wire with RDS API Enabled
**Status:** ✅ Pass  

**Objective:**  
Test whether regular cluster can use pgwire connection method when RDS Data API is enabled

**Prompt:**  
```
can you try direct connection again?
```

**Prerequisites:**
- RDS Data API enabled on regular-cluster
- Cluster publicly accessible
- Security group allows inbound PostgreSQL traffic (port 5432)

**Tool Calls:**
```json
{
  "tool": "connect_to_database",
  "params": {
    "region": "us-east-2",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "database_type": "APG",
    "connection_method": "pgwire",
    "with_express_configuration": false
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "regular-cluster",
  "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Query Test:**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT version(), current_database(), current_user"
  }
}
```

**Query Response:**
```json
{
  "version": "PostgreSQL 17.5 on aarch64-unknown-linux-gnu, compiled by aarch64-unknown-linux-gnu-gcc (GCC) 10.5.0, 64-bit",
  "current_database": "postgres",
  "current_user": "postgres"
}
```

**Duration:** < 5 seconds  
**Notes:** 
- ✅ Regular clusters CAN use pgwire connection even when RDS Data API is enabled
- **Key Finding:** Must explicitly specify `connection_method: "pgwire"` in the connect_to_database call
- When connection_method is not specified, the tool auto-selects RDS API (preferred method)
- Both connection methods (rdsapi and pgwire) can coexist for the same cluster
- Cluster must be publicly accessible for pgwire to work
- pgwire uses Secrets Manager authentication
- RDS API is preferred by default when auto-selecting connection method

**Conversation Log:**
```
User: can you enable RDS API on regular cluster now
Assistant: [Enables RDS Data API via AWS CLI]
Assistant: ✅ HttpEndpointEnabled: true

User: can you try direct connection again?
Assistant: [Connects with explicit connection_method: "pgwire"]
Assistant: ✅ Connected via pgwire!
Assistant: [Tests query] ✅ Success! PostgreSQL 17.5
Assistant: Both rdsapi and pgwire work when RDS API is enabled - just need to specify the method explicitly
```

---

### TC-006b: Query Regular Cluster via PG Wire with Public Access (Extension of TC-006a)
**Status:** ✅ Pass  

**Objective:**  
Test PG Wire Protocol connection to regular Aurora cluster with RDS Data API disabled and cluster publicly accessible

**Prompt:**  
```
I have disabled RDS API, try direct connection now
```

**Prerequisites:**
- RDS Data API disabled on regular-cluster
- Cluster made publicly accessible via AWS Console
- Security group allows inbound PostgreSQL traffic (port 5432)

**Step 1: Disable RDS Data API**
```bash
aws rds modify-db-cluster \
  --db-cluster-identifier regular-cluster \
  --no-enable-http-endpoint \
  --region us-east-2 \
  --apply-immediately
```

**Step 2: Make Cluster Publicly Accessible**
Modified cluster settings in AWS Console:
- Publicly accessible: Yes
- Security group: Allow inbound on port 5432

**Step 3: Reconnect to Cluster**
```json
{
  "tool": "connect_to_database",
  "params": {
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "with_express_configuration": false,
    "region": "us-east-2",
    "cluster_identifier": "regular-cluster",
    "port": 5432
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "regular-cluster",
  "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres"
}
```

**Step 4: Test Query Execution**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "regular-cluster",
    "connection_method": "pgwire",
    "sql": "SELECT 1 as test, current_database(), current_user;"
  }
}
```

**Query Response:**
```json
{
  "test": 1,
  "current_database": "postgres",
  "current_user": "postgres"
}
```

**Duration:** < 10 seconds  
**Notes:** 
- ✅ PG Wire connection works WITHOUT RDS Data API when cluster is publicly accessible
- ✅ Query execution successful using Secrets Manager credentials
- **Key Finding:** TC-006a failed because RDS Data API was enabled; this test succeeds by disabling it AND making cluster publicly accessible
- **Root Cause of TC-006a failure:** RDS Data API enabled forces rdsapi connection method
- **Solution:** Disable RDS Data API AND make cluster publicly accessible to use pgwire
- Connection uses Secrets Manager for authentication (retrieves username/password from secret)
- No IAM token required for this connection method
- Demonstrates PG Wire + Secrets Manager works correctly when network is accessible and RDS Data API is disabled

**Conversation Log:**
```
User: I have disabled RDS API, try direct connection now
Assistant: [Attempts connection] ❌ Error: "run_query unexpected error"

User: try again
Assistant: [Retries query] ❌ Still failing

User: reopen the pool. It seems to be closed
Assistant: [Reconnects to cluster] Connection established
Assistant: [Retries query] ❌ Still failing

User: try again I just made it publicly accessible
Assistant: [Reconnects to cluster] Connection method: pgwire
Assistant: [Tests query] ✅ Success! Query returns results
Assistant: The issue was network accessibility, not RDS Data API!
```

**Comparison with TC-006a:**
| Aspect | TC-006a (Failed) | TC-006b (Success) |
|--------|------------------|-------------------|
| Connection Method Requested | pgwire | pgwire |
| RDS Data API | Enabled | Disabled |
| Publicly Accessible | N/A | Yes |
| Actual Connection Method | rdsapi (forced) | pgwire |
| Query Execution | N/A (wrong method) | Success |

**Conclusion:**
- Regular clusters with RDS Data API enabled always use rdsapi (TC-006a)
- To use pgwire on regular clusters, BOTH conditions required:
  1. RDS Data API disabled
  2. Cluster publicly accessible
- Network accessibility is critical for pgwire connections
- RDS Data API bypasses network restrictions by using HTTP endpoint

---

### TC-007: Reconnect to Express Cluster (Direct Method)
**Status:** ✅ Pass  

**Objective:**  
Test reconnecting to express cluster using direct connection method after connection expired/cleared

**Prompt:**  
```
Connect to my Aurora cluster 'ufc-cluster' using direct connection method
```

**Tool Calls:**
```json
{
  "tool": "is_database_connected",
  "params": {
    "cluster_identifier": "ufc-cluster",
    "database": "postgres"
  }
}
```

**Initial Check Response:**
```json
false
```

**Connection Tool Call:**
```json
{
  "tool": "connect_to_database",
  "params": {
    "region": "us-east-2",
    "cluster_identifier": "ufc-cluster",
    "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "with_express_configuration": true
  }
}
```

**Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "ufc-cluster",
  "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
  "database": "postgres"
}
```

**Duration:** < 5 seconds  
**Notes:** 
- Connection was not cached (returned false on is_database_connected check)
- Successfully reconnected using PG Wire Protocol (direct method)
- "Direct connection method" = PG Wire Protocol (pgwire)
- Confirms connection can be re-established after expiration
- IAM token regenerated for authentication

**Conversation Log:**
```
User: Connect to my Aurora cluster 'ufc-cluster' using direct connection method
Assistant: [Calls is_database_connected] Shows as not connected
Assistant: [Calls connect_to_database with with_express_configuration=true]
Assistant: ✅ Connected successfully! Method: PG Wire Protocol (direct connection)
```

---

### TC-008: Create Table and Insert Data in Multiple Clusters
**Status:** ✅ Pass  

**Objective:**  
Test run_query tool to execute DDL (CREATE TABLE) and DML (INSERT) statements across multiple clusters with different connection methods

**Prompt:**  
```
create a table cluster info in each regular-cluster and ufc-cluster databases and insert into them the cluster name
```

**Tool Calls - regular-cluster:**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "rdsapi",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "CREATE TABLE cluster_info (cluster_name VARCHAR(255) PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
  }
}
```

```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "rdsapi",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "INSERT INTO cluster_info (cluster_name) VALUES ('regular-cluster')"
  }
}
```

**Tool Calls - ufc-cluster:**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "ufc-cluster",
    "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "CREATE TABLE cluster_info (cluster_name VARCHAR(255) PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
  }
}
```

```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "ufc-cluster",
    "db_endpoint": "ufc-cluster.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "INSERT INTO cluster_info (cluster_name) VALUES ('ufc-cluster')"
  }
}
```

**Response:**
All queries executed successfully (no errors returned)

**Duration:** < 10 seconds total  
**Notes:** 
- Successfully executed DDL and DML across both connection methods
- RDS API (regular-cluster) and PG Wire (ufc-cluster) both handled queries
- No readonly restrictions (server allows write operations)
- Table schema: cluster_name (VARCHAR, PK), created_at (TIMESTAMP with default)
- Demonstrates multi-cluster query execution capability

**Conversation Log:**
```
User: create a table cluster info in each regular-cluster and ufc-cluster databases and insert into them the cluster name
Assistant: [Executes CREATE TABLE on regular-cluster via RDS API]
Assistant: [Executes INSERT on regular-cluster]
Assistant: [Executes CREATE TABLE on ufc-cluster via pgwire]
Assistant: [Executes INSERT on ufc-cluster]
Assistant: ✅ Both clusters complete! Tables created and data inserted.
```

---

### TC-009: Query Data from Multiple Clusters
**Status:** ✅ Pass  

**Objective:**  
Test run_query tool to execute SELECT statements across multiple clusters and verify data retrieval without connection issues

**Prompt:**  
```
Query the cluster_info table in console-create-cluster and products table in ufc-2
```

**Tool Calls - console-create-cluster:**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "console-create-cluster",
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT * FROM cluster_info ORDER BY id"
  }
}
```

**Response - console-create-cluster:**
```json
{
  "id": 1,
  "cluster_name": "console-create-cluster",
  "region": "us-east-2",
  "created_at": "2025-12-04 00:25:15.712645"
}
{
  "id": 2,
  "cluster_name": "regular-cluster",
  "region": "us-east-2",
  "created_at": "2025-12-04 00:25:15.712645"
}
{
  "id": 3,
  "cluster_name": "ufc-2",
  "region": "us-east-2",
  "created_at": "2025-12-04 00:25:15.712645"
}
```

**Tool Calls - ufc-2:**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire_iam",
    "cluster_identifier": "ufc-2",
    "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT * FROM products ORDER BY id"
  }
}
```

**Response - ufc-2:**
```json
{
  "id": 1,
  "name": "Laptop",
  "price": "999.99",
  "category": "Electronics",
  "created_at": "2025-12-04 00:02:35.498753"
}
{
  "id": 2,
  "name": "Coffee Mug",
  "price": "12.50",
  "category": "Kitchen",
  "created_at": "2025-12-04 00:02:35.498753"
}
{
  "id": 3,
  "name": "Notebook",
  "price": "5.99",
  "category": "Office",
  "created_at": "2025-12-04 00:02:35.498753"
}
{
  "id": 4,
  "name": "Headphones",
  "price": "79.99",
  "category": "Electronics",
  "created_at": "2025-12-04 00:02:35.498753"
}
```

**Duration:** < 10 seconds total  
**Notes:** 
- ✅ Both queries executed successfully without requiring reconnection
- **Issue #1 Resolution:** The initial connection failure issue seen in earlier testing is no longer present
- pgwire connection (console-create-cluster with Secrets Manager) worked without issues
- pgwire_iam connection (ufc-2 with IAM auth) worked without issues
- Both connections remained stable and did not require reconnection
- Demonstrates multi-cluster query execution capability across different authentication methods
- Successfully queried clusters using both Secrets Manager (pgwire) and IAM authentication (pgwire_iam)

**Conversation Log:**
```
User: query cluster_info table in console-create-cluster
Assistant: [Queries console-create-cluster using pgwire]
Assistant: ✅ Success! Retrieved 3 cluster records

User: query the table in ufc-2
Assistant: [Queries ufc-2 using pgwire_iam]
Assistant: ✅ Success! Retrieved 4 products from the table
```

---

### TC-010: Test Write Query Restriction Without allow_write_query Flag
**Status:** ✅ Pass  

**Objective:**  
Verify that write operations are blocked when MCP server is configured without the `--allow_write_query` flag, while read operations continue to work

**Prompt:**  
```
Insert another row into cluster_info table on regular-cluster
```

**Configuration:**
MCP server configured WITHOUT `--allow_write_query` flag in `~/.kiro/settings/mcp.json`:
```json
{
  "mcpServers": {
    "postgres": {
      "command": "uvx",
      "args": [
        "--from",
        "/Users/goelshar/mcp/src/postgres-mcp-server/dist/awslabs_postgres_mcp_server-1.0.10-py3-none-any.whl",
        "awslabs.postgres-mcp-server"
      ],
      "disabled": false
    }
  }
}
```

**Test Execution:**

**Test 1 - First INSERT (Successful with --allow_write_query):**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "rdsapi",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "INSERT INTO cluster_info (cluster_name, created_at) VALUES ('test-cluster', NOW())"
  }
}
```

**Response:**
```
(No output - successful execution)
```

**Test 2 - Second INSERT (After removing --allow_write_query flag):**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "rdsapi",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "INSERT INTO cluster_info (cluster_name, created_at) VALUES ('another-cluster', NOW())"
  }
}
```

**Response:**
```json
{
  "error": "Your MCP tool only allows readonly query. If you want to write, change the MCP configuration per README.md"
}
```

**Test 3 - SELECT Query (Verify reads still work):**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "rdsapi",
    "cluster_identifier": "regular-cluster",
    "db_endpoint": "regular-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT * FROM cluster_info ORDER BY created_at DESC LIMIT 5"
  }
}
```

**Response:**
```json
{
  "cluster_name": "test-cluster",
  "created_at": "2025-12-03 23:19:41.495131"
}
{
  "cluster_name": "regular-cluster",
  "created_at": "2025-11-25 00:54:00.843232"
}
```

**Duration:** < 10 seconds  
**Notes:** 
- ✅ Write operations successfully blocked when `--allow_write_query` flag is removed
- ✅ Read operations (SELECT) continue to work without the flag
- ✅ Error message is clear and helpful, references README.md for configuration
- **Key Finding:** Connection was lost after removing the flag, requiring reconnection
- Write restriction enforcement happens at server level via `detect_mutating_keywords()`
- Default behavior is read-only unless explicitly enabled with `--allow_write_query`
- This is a security feature to prevent accidental data modifications
- Connection needs to be re-established after MCP configuration changes

**Conversation Log:**
```
User: Insert another row into cluster_info table on regular-cluster
Assistant: [Attempts INSERT query]
Assistant: ❌ Error: "No database connection available"
Assistant: Connection was lost, reconnecting...

User: try to insert another row now
Assistant: [Reconnects to cluster]
Assistant: [Attempts INSERT query]
Assistant: ❌ Error: "Your MCP tool only allows readonly query. If you want to write, change the MCP configuration per README.md"
Assistant: Write operations are blocked without --allow_write_query flag

User: I had actually removed the allow_write_query flag from mcp.json so this was expected. Could you document this as TC-010
Assistant: [Documents test case]
```

**Configuration Comparison:**

| Configuration | Write Operations | Read Operations |
|---------------|------------------|-----------------|
| With `--allow_write_query` | ✅ Allowed | ✅ Allowed |
| Without `--allow_write_query` | ❌ Blocked | ✅ Allowed |

**Conclusion:**
- The `--allow_write_query` flag is required to enable write operations (INSERT, UPDATE, DELETE, etc.)
- Without this flag, the MCP server operates in read-only mode by default
- This is a security best practice to prevent accidental data modifications
- Read operations work regardless of the flag setting

---

### TC-011: Connect to Existing Cluster with Secrets Manager and Execute Queries
**Status:** ✅ Pass  

**Objective:**  
Connect to an existing Aurora PostgreSQL cluster that uses AWS Secrets Manager for credential management and verify DDL/DML operations work correctly

**Prompt:**  
```
I have an existing Aurora PostgreSQL cluster that I want to connect to:
Cluster name: console-create-cluster
Region: us-east-2
Database Name: postgres
Endpoint: console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com

Connect via pgwire
```

**Step 1: Connect to Cluster**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "APG",
    "region": "us-east-2",
    "cluster_identifier": "console-create-cluster",
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "connection_method": "pgwire",
    "with_express_configuration": false
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "console-create-cluster",
  "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Step 2: Verify Connection**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "console-create-cluster",
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT version(), current_database(), current_user"
  }
}
```

**Query Response:**
```json
{
  "version": "PostgreSQL 17.4 on aarch64-unknown-linux-gnu, compiled by aarch64-unknown-linux-gnu-gcc (GCC) 10.5.0, 64-bit",
  "current_database": "postgres",
  "current_user": "postgres"
}
```

**Step 3: Create Table**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "console-create-cluster",
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "CREATE TABLE cluster_info (id SERIAL PRIMARY KEY, cluster_name VARCHAR(255) NOT NULL, region VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
  }
}
```

**Response:**
```
(No output - successful execution)
```

**Step 4: Insert Data**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "console-create-cluster",
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "INSERT INTO cluster_info (cluster_name, region) VALUES ('console-create-cluster', 'us-east-2'), ('regular-cluster', 'us-east-2'), ('ufc-2', 'us-east-2')"
  }
}
```

**Response:**
```
(No output - successful execution)
```

**Step 5: Query Data**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "console-create-cluster",
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT * FROM cluster_info ORDER BY id"
  }
}
```

**Query Response:**
```json
{
  "id": 1,
  "cluster_name": "console-create-cluster",
  "region": "us-east-2",
  "created_at": "2025-12-04 00:25:15.712645"
}
{
  "id": 2,
  "cluster_name": "regular-cluster",
  "region": "us-east-2",
  "created_at": "2025-12-04 00:25:15.712645"
}
{
  "id": 3,
  "cluster_name": "ufc-2",
  "region": "us-east-2",
  "created_at": "2025-12-04 00:25:15.712645"
}
```

**Duration:** < 15 seconds  
**Notes:** 
- ✅ Connection successful using PG Wire Protocol with Secrets Manager
- ✅ DDL operations (CREATE TABLE) work correctly
- ✅ DML operations (INSERT, SELECT) work correctly
- **Key Finding:** Existing clusters with Secrets Manager work seamlessly with pgwire connection
- Connection method must be explicitly specified as `pgwire`
- Uses Secrets Manager for authentication (retrieves username/password from secret)
- No IAM token required for this connection method
- PostgreSQL version 17.4 on ARM64 architecture
- Write operations require `--allow_write_query` flag in MCP configuration
- Demonstrates successful Secrets Manager integration with existing clusters

**Conversation Log:**
```
User: I have an existing Aurora PostgreSQL cluster that I want to connect to:
Cluster name: console-create-cluster
Region: us-east-2
Database Name: postgres
Endpoint: console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com

User: connect via pgwire
Assistant: [Connects with connection_method=pgwire]
Assistant: ✅ Connected successfully! Method: pgwire

User: query cluster_info table
Assistant: [Checks if table exists]
Assistant: Table doesn't exist yet

User: create table and insert some rows
Assistant: [Creates cluster_info table with 4 columns]
Assistant: [Inserts 3 cluster records]
Assistant: [Queries all data]
Assistant: ✅ Table created with 3 clusters
```
Assistant: [Tests query: SELECT 1]
Assistant: ❌ Query fails with "run_query unexpected error"
Assistant: Connection works but query execution is failing

```

---

### TC-012: Enable RDS Data API and Connect to Existing Cluster
**Status:** ✅ Pass  

**Objective:**  
Enable RDS Data API on existing cluster (console-create-cluster) and verify connection and query execution work correctly

**Prompt:**  
```
enable RDS API on this cluster
```

**Step 1: Enable RDS Data API**
```bash
aws rds modify-db-cluster \
  --db-cluster-identifier console-create-cluster \
  --enable-http-endpoint \
  --region us-east-2 \
  --apply-immediately
```

**Step 2: Connect via RDS API**
```json
{
  "tool": "connect_to_database",
  "params": {
    "region": "us-east-2",
    "cluster_identifier": "console-create-cluster",
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "with_express_configuration": false
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "rdsapi",
  "cluster_identifier": "console-create-cluster",
  "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres"
}
```

**Step 3: Test Queries**
```json
{
  "tool": "run_query",
  "params": {
    "sql": "SELECT version()"
  }
}
```

**Response:**
```json
{
  "version": "PostgreSQL 17.4 on aarch64-unknown-linux-gnu, compiled by aarch64-unknown-linux-gnu-gcc (GCC) 10.5.0, 64-bit"
}
```

**Duration:** ~5 minutes  
**Notes:** 
- ✅ RDS Data API successfully enabled on Aurora PostgreSQL 17.4
- ✅ Connection automatically switched from pgwire to rdsapi
- ✅ All SELECT queries execute successfully
- ✅ Readonly mode enforcement working correctly
- **Key Finding:** RDS Data API resolves the query execution issues seen with pgwire + Secrets Manager (Issue #3)

**Conversation Log:**
```
User: enable RDS API on this cluster
Assistant: [Runs aws rds modify-db-cluster command]
Assistant: Modification submitted, checking status...

User: Can you try connecting via RDS API. I have enabled it on the cluster
Assistant: [Verifies] HttpEndpointEnabled = True ✅
Assistant: [Connects] Connection method: rdsapi ✅
Assistant: [Tests queries] All queries work! ✅
```

---

### TC-013: Connect and Query Standalone RDS PostgreSQL Instance
**Status:** ✅ Pass  

**Objective:**  
Test connection to a standalone RDS PostgreSQL instance (non-Aurora, non-Multi-AZ cluster) and verify table creation and query execution

**Prompt:**  
```
Connect to my RDS PostgreSQL database with endpoint rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com and DB identifier rds-postgresql-cluster
```

**Prerequisites:**
- Standalone RDS PostgreSQL instance (not Aurora, not Multi-AZ cluster)
- Instance made publicly accessible
- Security group allows inbound PostgreSQL traffic (port 5432)
- Credentials managed via Secrets Manager

**Step 1: Connect to Instance**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "RPG",
    "database": "postgres",
    "port": 5432,
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "region": "us-east-2",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "with_express_configuration": false
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "",
  "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Step 2: Test Version Query**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "sql": "SELECT VERSION()"
  }
}
```

**Query Response:**
```json
{
  "version": "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 12.4.0, 64-bit"
}
```

**Step 3: Create Sample Table**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "sql": "CREATE TABLE employees (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) UNIQUE NOT NULL, department VARCHAR(50), salary DECIMAL(10, 2), hire_date DATE DEFAULT CURRENT_DATE)"
  }
}
```

**Step 4: Insert Sample Data**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "sql": "INSERT INTO employees (name, email, department, salary) VALUES ('Alice Johnson', 'alice@example.com', 'Engineering', 95000.00), ('Bob Smith', 'bob@example.com', 'Marketing', 72000.00), ('Carol Davis', 'carol@example.com', 'Engineering', 88000.00)"
  }
}
```

**Step 5: Query Sample Data**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "sql": "SELECT * FROM employees"
  }
}
```

**Query Response:**
```json
[
  {
    "id": 1,
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "department": "Engineering",
    "salary": "95000.00",
    "hire_date": "2025-12-02"
  },
  {
    "id": 2,
    "name": "Bob Smith",
    "email": "bob@example.com",
    "department": "Marketing",
    "salary": "72000.00",
    "hire_date": "2025-12-02"
  },
  {
    "id": 3,
    "name": "Carol Davis",
    "email": "carol@example.com",
    "department": "Engineering",
    "salary": "88000.00",
    "hire_date": "2025-12-02"
  }
]
```

**Duration:** < 15 seconds  

**Notes:** 
- ✅ Standalone RDS PostgreSQL instances fully supported by MCP server
- ✅ Connection successful using PG Wire Protocol with Secrets Manager
- ✅ DDL operations (CREATE TABLE) work correctly
- ✅ DML operations (INSERT, SELECT) work correctly
- **Key Finding:** Must pass empty string `""` for `cluster_identifier` parameter when connecting to standalone instances
- **Connection Method:** PG Wire Protocol with Secrets Manager authentication
- **Network Requirement:** Instance must be publicly accessible for pgwire to work
- **PostgreSQL Version:** 17.4 on x86_64 Linux
- **Authentication:** Uses Secrets Manager to retrieve username/password
- Sample table created with 6 columns: id, name, email, department, salary, hire_date
- Successfully inserted 3 employee records
- All queries executed without errors

**Conversation Log:**
```
User: Connect to my RDS PostgreSQL database with endpoint rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com and DB identifier rds-postgresql-cluster
Assistant: [Attempts connection with cluster_identifier]
Assistant: ❌ Failed: DBClusterNotFoundFault

User: This is a standard RDS Postgres instance
Assistant: [Connects without cluster_identifier]
Assistant: ✅ Success! Connected to standalone RDS instance

User: Run SELECT VERSION()
Assistant: [Tests query]
Assistant: ✅ PostgreSQL 17.4 on x86_64-pc-linux-gnu

User: create a sample table
Assistant: [Creates employees table with 6 columns]
Assistant: [Inserts 3 sample records]
Assistant: [Queries all data]
Assistant: ✅ Table created with 3 employees
```

---

### TC-014: Connect to RDS PostgreSQL Multi-AZ DB Cluster
**Status:** ✅ Pass  

**Objective:**  
Test connection to RDS PostgreSQL Multi-AZ DB Cluster (not Aurora) using PG Wire Protocol with Secrets Manager and understand how MCP server handles cluster architecture

**Background:**
RDS PostgreSQL Multi-AZ DB Clusters were introduced by AWS in 2022 as a high-availability deployment option that uses cluster architecture similar to Aurora. Unlike standalone RDS instances, Multi-AZ DB Clusters have:
- 1 writer instance + 2 reader instances
- Cluster endpoint format: `*.cluster-*.rds.amazonaws.com`
- Support for `describe_db_clusters` API (same as Aurora)

**Prompt:**  
```
Connect to the following RDS PostgreSQL cluster rds-postgresql-multiaz.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com
```

**Prerequisites:**
- RDS PostgreSQL Multi-AZ DB Cluster created via AWS Console
- Cluster made publicly accessible
- Security group allows inbound PostgreSQL traffic (port 5432)
- Credentials managed via Secrets Manager

**Step 1: Connect to Cluster**
```json
{
  "tool": "connect_to_database",
  "params": {
    "db_endpoint": "rds-postgresql-multiaz.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "with_express_configuration": false,
    "region": "us-east-2",
    "cluster_identifier": "rds-postgresql-multiaz",
    "port": 5432
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "rds-postgresql-multiaz",
  "db_endpoint": "rds-postgresql-multiaz.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres"
}
```

**Step 2: Test Query Execution**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-multiaz.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "rds-postgresql-multiaz",
    "connection_method": "pgwire",
    "sql": "SELECT version(), current_database(), current_user;"
  }
}
```

**Query Response:**
```json
{
  "version": "PostgreSQL 17.6 on aarch64-unknown-linux-gnu, compiled by gcc (GCC) 12.4.0, 64-bit",
  "current_database": "postgres",
  "current_user": "postgres"
}
```

**Duration:** < 10 seconds  

**How MCP Connects to RDS PostgreSQL Cluster Architecture:**

1. **Cluster Detection:**
   - MCP server calls `describe_db_clusters` API to fetch cluster properties
   - Multi-AZ DB Clusters respond to this API (unlike standalone instances)
   - Cluster endpoint format `*.cluster-*.rds.amazonaws.com` indicates cluster architecture

2. **Connection Method Selection:**
   - Checks if RDS Data API is enabled (`HttpEndpointEnabled` property)
   - If disabled, falls back to PG Wire Protocol (pgwire)
   - For Multi-AZ clusters without RDS Data API, pgwire is the only option

3. **Authentication:**
   - Retrieves Secrets Manager secret ARN from cluster metadata
   - Fetches username/password from Secrets Manager
   - Uses standard PostgreSQL authentication (not IAM tokens)

4. **Connection Establishment:**
   - Creates psycopg connection pool with Secrets Manager credentials
   - Requires cluster to be publicly accessible for direct network access
   - Connection pool manages multiple connections for query execution

5. **Query Execution:**
   - Uses established connection pool to execute queries
   - Standard PostgreSQL wire protocol communication
   - No HTTP endpoint or RDS Data API involved

**Notes:** 
- ✅ RDS PostgreSQL Multi-AZ DB Clusters fully supported by MCP server
- ✅ Query execution successful using Secrets Manager credentials
- **Key Finding:** MCP server supports cluster architecture (Aurora + Multi-AZ DB Clusters), not standalone instances
- **Architecture:** Multi-AZ clusters use cluster architecture (1 writer + 2 readers)
- **Endpoint Format:** `*.cluster-*.rds.amazonaws.com` (note the `.cluster.` in the endpoint)
- **API Used:** `describe_db_clusters` (same as Aurora, which is why it works)
- **Connection Method:** PG Wire Protocol with Secrets Manager authentication
- **Network Requirement:** Cluster must be publicly accessible for pgwire to work
- **PostgreSQL Version:** 17.6 (newer than Aurora's 17.4/17.5)
- Initial connection attempts failed until cluster was made publicly accessible
- Connection pool needed time to initialize after making cluster publicly accessible

**Conversation Log:**
```
User: Connect to the following RDS PostgreSQL cluster rds-postgresql-multiaz.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com
Assistant: [Connects to cluster] Connection method: pgwire
Assistant: [Tests query] ❌ Error: "run_query unexpected error"

User: try again. Made it publicly accessible
Assistant: [Reconnects to cluster]
Assistant: [Tests query] ❌ Still failing

User: try connecting and running query again
Assistant: [Reconnects to cluster]
Assistant: [Tests query] ✅ Success! PostgreSQL 17.6
```

**Conclusion:**
- RDS PostgreSQL Multi-AZ DB Clusters ARE supported by the MCP server
- They use cluster architecture and `describe_db_clusters` API like Aurora
- Connection works via pgwire + Secrets Manager when publicly accessible
- This is different from standalone RDS PostgreSQL instances which are NOT supported
- The key differentiator is cluster architecture, not the database engine (Aurora vs RDS)

---

### TC-013: Connect and Query Standalone RDS PostgreSQL Instance
**Status:** ✅ Pass  

**Objective:**  
Test connection to a standalone RDS PostgreSQL instance (non-Aurora, non-Multi-AZ cluster) and verify table creation and query execution

**Prompt:**  
```
Connect to my RDS PostgreSQL database with endpoint rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com and DB identifier rds-postgresql-cluster
```

**Prerequisites:**
- Standalone RDS PostgreSQL instance (not Aurora, not Multi-AZ cluster)
- Instance made publicly accessible
- Security group allows inbound PostgreSQL traffic (port 5432)
- Credentials managed via Secrets Manager

**Step 1: Connect to Instance**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "RPG",
    "database": "postgres",
    "port": 5432,
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "region": "us-east-2",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "with_express_configuration": false
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "",
  "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Step 2: Test Version Query**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "sql": "SELECT VERSION()"
  }
}
```

**Query Response:**
```json
{
  "version": "PostgreSQL 17.4 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 12.4.0, 64-bit"
}
```

**Step 3: Create Sample Table**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "sql": "CREATE TABLE employees (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) UNIQUE NOT NULL, department VARCHAR(50), salary DECIMAL(10, 2), hire_date DATE DEFAULT CURRENT_DATE)"
  }
}
```

**Step 4: Insert Sample Data**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "sql": "INSERT INTO employees (name, email, department, salary) VALUES ('Alice Johnson', 'alice@example.com', 'Engineering', 95000.00), ('Bob Smith', 'bob@example.com', 'Marketing', 72000.00), ('Carol Davis', 'carol@example.com', 'Engineering', 88000.00)"
  }
}
```

**Step 5: Query Sample Data**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "",
    "connection_method": "pgwire",
    "sql": "SELECT * FROM employees"
  }
}
```

**Query Response:**
```json
[
  {
    "id": 1,
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "department": "Engineering",
    "salary": "95000.00",
    "hire_date": "2025-12-02"
  },
  {
    "id": 2,
    "name": "Bob Smith",
    "email": "bob@example.com",
    "department": "Marketing",
    "salary": "72000.00",
    "hire_date": "2025-12-02"
  },
  {
    "id": 3,
    "name": "Carol Davis",
    "email": "carol@example.com",
    "department": "Engineering",
    "salary": "88000.00",
    "hire_date": "2025-12-02"
  }
]
```

**Duration:** < 15 seconds  

**Notes:** 
- ✅ Standalone RDS PostgreSQL instances fully supported by MCP server
- ✅ Connection successful using PG Wire Protocol with Secrets Manager
- ✅ DDL operations (CREATE TABLE) work correctly
- ✅ DML operations (INSERT, SELECT) work correctly
- **Key Finding:** Must pass empty string `""` for `cluster_identifier` parameter when connecting to standalone instances
- **Connection Method:** PG Wire Protocol with Secrets Manager authentication
- **Network Requirement:** Instance must be publicly accessible for pgwire to work
- **PostgreSQL Version:** 17.4 on x86_64 Linux
- **Authentication:** Uses Secrets Manager to retrieve username/password
- Sample table created with 6 columns: id, name, email, department, salary, hire_date
- Successfully inserted 3 employee records
- All queries executed without errors

**Conversation Log:**
```
User: Connect to my RDS PostgreSQL database with endpoint rds-postgresql-cluster.c4gbhisi7urs.us-east-2.rds.amazonaws.com and DB identifier rds-postgresql-cluster
Assistant: [Attempts connection with cluster_identifier]
Assistant: ❌ Failed: DBClusterNotFoundFault

User: This is a standard RDS Postgres instance
Assistant: [Connects without cluster_identifier]
Assistant: ✅ Success! Connected to standalone RDS instance

User: Run SELECT VERSION()
Assistant: [Tests query]
Assistant: ✅ PostgreSQL 17.4 on x86_64-pc-linux-gnu

User: create a sample table
Assistant: [Creates employees table with 6 columns]
Assistant: [Inserts 3 sample records]
Assistant: [Queries all data]
Assistant: ✅ Table created with 3 employees

User: Document this as TC-013 now
Assistant: [Documents test case in MCP_TEST_CASES.md]
```

---

### TC-015: Query Cluster Without Secrets Manager Enabled (Negative Test)
**Status:** ❌ Fail (Expected)  

**Objective:**  
Verify that pgwire connection method fails gracefully when attempting to query a cluster that does not have AWS Secrets Manager enabled

**Prompt:**  
```
connect to console-create-cluster with endpoint console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com via pgwire
run query select version()
```

**Prerequisites:**
- Aurora PostgreSQL cluster created without Secrets Manager integration
- Cluster publicly accessible
- Security group allows inbound PostgreSQL traffic (port 5432)

**Step 1: Connect to Cluster**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "APG",
    "database": "postgres",
    "port": 5432,
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "region": "us-east-2",
    "cluster_identifier": "console-create-cluster",
    "connection_method": "pgwire",
    "with_express_configuration": false
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "console-create-cluster",
  "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Step 2: Attempt Query Execution**
```json
{
  "tool": "run_query",
  "params": {
    "connection_method": "pgwire",
    "cluster_identifier": "console-create-cluster",
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "sql": "SELECT version()"
  }
}
```

**Query Response:**
```json
{
  "error": "run_query unexpected error"
}
```

**Duration:** < 10 seconds  

**Notes:** 
- ❌ Query fails as expected when Secrets Manager is not enabled
- ✅ Connection appears to succeed but query execution fails
- **Root Cause:** pgwire connection method requires Secrets Manager credentials to authenticate
- **Expected Behavior:** Query should fail when no Secrets Manager secret is associated with the cluster
- **Error Message:** Generic "run_query unexpected error" - could be more descriptive
- **Workaround:** Enable Secrets Manager on the cluster or use pgwire_iam connection method if IAM authentication is configured
- This is a negative test case demonstrating proper failure when prerequisites are not met
- Similar to Issue #1 (TC-004b) where express clusters without Secrets Manager fail with pgwire

**Conversation Log:**
```
User: connect to console-create-cluster with endpoint console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com via pgwire
Assistant: [Connects with connection_method=pgwire]
Assistant: ✅ Connection established

User: run query select version()
Assistant: [Attempts query]
Assistant: ❌ Error: "run_query unexpected error"
Assistant: Query failed - likely due to missing Secrets Manager configuration

User: Document this as negative test case TC-015 along with an entry in summary table for TC-015 in MCP_TEST_CASES.md and also in the corresponding quip. Actually AWS secrets manager was not enabled on the cluster so query was expected to fail.
Assistant: [Documents test case]
```

**Suggested Improvements:**
1. Add validation during connection to check if Secrets Manager secret exists
2. Return more descriptive error message indicating missing Secrets Manager configuration
3. Suggest alternative connection methods (pgwire_iam or rdsapi) in error message
4. Fail fast at connection time rather than during query execution

**Related Test Cases:**  
- TC-004b: Similar issue with express clusters requiring pgwire_iam
- TC-011: Successful pgwire connection with Secrets Manager enabled
- TC-006b: Successful pgwire connection after enabling public access

---

### TC-016: Connect to Non-Existent Cluster (Negative Test)
**Status:** ❌ Fail (Expected)  

**Objective:**  
Test connection behavior when attempting to connect to a cluster that does not exist in the AWS account

**Prompt:**  
```
connect to random-cluster with endpoint random-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com
```

**Tool Calls:**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "APG",
    "database": "postgres",
    "port": 5432,
    "db_endpoint": "random-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "region": "us-east-2",
    "cluster_identifier": "random-cluster",
    "connection_method": "pgwire"
  }
}
```

**Response:**
```json
{
  "status": "Failed",
  "error": "An error occurred (DBClusterNotFoundFault) when calling the DescribeDBClusters operation: DBCluster random-cluster not found."
}
```

**Duration:** < 5 seconds  

**Notes:** 
- ❌ Connection fails as expected when cluster does not exist
- ✅ Error message is clear and descriptive
- **Root Cause:** MCP server calls `describe_db_clusters` API to fetch cluster properties during connection
- **Expected Behavior:** Connection should fail with DBClusterNotFoundFault when cluster doesn't exist
- **Error Handling:** Proper AWS SDK error propagation with clear message
- This is a negative test case demonstrating proper validation of cluster existence
- Validates that the MCP server performs cluster validation before attempting connection
- Error occurs during the cluster metadata fetch phase, before any connection attempt

**Conversation Log:**
```
User: connect to random-cluster with endpoint random-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com
Assistant: [Attempts connection]
Assistant: ❌ Error: "DBCluster random-cluster not found"
Assistant: The cluster doesn't exist in your AWS account

User: Document this as TC-016 as negative test case which tests what happens if the cluster does not exist
Assistant: [Documents test case]
```

**Suggested Improvements:**
1. Error message is already clear and helpful
2. Could add suggestion to verify cluster name and region
3. Could list available clusters in the error message (optional)

**Related Test Cases:**  
- TC-015: Similar negative test for missing Secrets Manager
- TC-001: Successful cluster creation
- TC-002: Successful express cluster creation

---

### TC-017: Connect with Valid Cluster Identifier but Incorrect Endpoint (Negative Test)
**Status:** ❌ Fail (Expected)  

**Objective:**  
Test connection behavior when cluster identifier is valid but the provided endpoint is incorrect, demonstrating that endpoint validation happens at query execution time rather than connection time

**Prompt:**  
```
connect to console-create-cluster with endpoint console111-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com
```

**Tool Calls - Connection:**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "APG",
    "database": "postgres",
    "port": 5432,
    "db_endpoint": "console111-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "region": "us-east-2",
    "cluster_identifier": "console-create-cluster",
    "connection_method": "pgwire"
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "console-create-cluster",
  "db_endpoint": "console111-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "postgres",
  "port": 5432
}
```

**Tool Calls - Query:**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "console111-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "postgres",
    "cluster_identifier": "console-create-cluster",
    "connection_method": "pgwire",
    "sql": "SELECT version()"
  }
}
```

**Query Response:**
```json
{
  "error": "run_query unexpected error"
}
```

**Duration:** < 10 seconds  

**Notes:** 
- ✅ Connection succeeds because cluster identifier "console-create-cluster" exists and passes `describe_db_clusters` validation
- ❌ Query fails as expected because endpoint "console111-create-cluster..." is incorrect and doesn't resolve to a valid database server
- **Root Cause:** MCP server validates cluster existence via cluster identifier but doesn't validate that the provided endpoint matches the actual cluster endpoint
- **Expected Behavior:** Connection metadata validation succeeds, but actual database connection fails at query execution time
- **Error Message:** Generic "run_query unexpected error" - could be more descriptive about network/endpoint issues
- This is a negative test case demonstrating the two-phase validation: metadata validation (cluster exists) vs. network validation (endpoint reachable)
- Highlights that endpoint validation is deferred until actual database communication is attempted

**Conversation Log:**
```
User: connect to console-create-cluster with endpoint console111-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com
Assistant: [Connects with mismatched endpoint]
Assistant: ✅ Connection established (metadata validation passed)

User: run query select version()
Assistant: [Attempts query]
Assistant: ❌ Error: "run_query unexpected error"
Assistant: Query failed - endpoint doesn't resolve to a valid database server

User: Document this as negative test case TC-017, where cluster identifier is valid but the endpoint is incorrect
Assistant: [Documents test case]
```

**Suggested Improvements:**
1. Add endpoint validation during connection to verify it matches the cluster's actual endpoint
2. Fetch actual endpoint from `describe_db_clusters` response and compare with provided endpoint
3. Return more descriptive error message indicating network/endpoint resolution failure
4. Consider warning user if provided endpoint doesn't match cluster's actual endpoint
5. Optionally auto-correct endpoint to use the actual cluster endpoint from AWS metadata

**Related Test Cases:**  
- TC-016: Cluster doesn't exist (fails at metadata validation)
- TC-015: Secrets Manager not configured (fails at authentication)
- TC-011: Successful connection with correct endpoint

---

### TC-018: Connect to Non-Existent Database in Valid Cluster (Negative Test)
**Status:** ❌ Fail (Expected)  

**Objective:**  
Test connection and query behavior when attempting to connect to a database that doesn't exist within a valid cluster

**Prompt:**  
```
connect and query random-db database in console-create-cluster with endpoint console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com. Database name is random-db
```

**Tool Calls - Connection:**
```json
{
  "tool": "connect_to_database",
  "params": {
    "database_type": "APG",
    "database": "random-db",
    "port": 5432,
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "region": "us-east-2",
    "cluster_identifier": "console-create-cluster",
    "connection_method": "pgwire"
  }
}
```

**Connection Response:**
```json
{
  "connection_method": "pgwire",
  "cluster_identifier": "console-create-cluster",
  "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
  "database": "random-db",
  "port": 5432
}
```

**Tool Calls - Query:**
```json
{
  "tool": "run_query",
  "params": {
    "db_endpoint": "console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com",
    "database": "random-db",
    "cluster_identifier": "console-create-cluster",
    "connection_method": "pgwire",
    "sql": "SELECT version()"
  }
}
```

**Query Response:**
```json
{
  "error": "run_query unexpected error"
}
```

**Duration:** < 10 seconds  

**Notes:** 
- ✅ Connection succeeds because cluster identifier "console-create-cluster" exists and endpoint is correct
- ❌ Query fails as expected because database "random-db" doesn't exist in the cluster
- **Root Cause:** MCP server validates cluster existence and endpoint correctness, but doesn't validate database existence until query execution
- **Expected Behavior:** Connection metadata validation succeeds (cluster exists, endpoint correct), but PostgreSQL connection fails when trying to connect to non-existent database
- **Error Message:** Generic "run_query unexpected error" - could be more descriptive about database not found
- This is a negative test case demonstrating three-phase validation: cluster validation → endpoint validation → database validation
- Database existence is only validated when PostgreSQL attempts to establish the actual connection
- Similar pattern to TC-017 (invalid endpoint) but this time the endpoint is correct and database name is invalid

**Conversation Log:**
```
User: connect and query random-db database in console-create-cluster with endpoint console-create-cluster.cluster-c4gbhisi7urs.us-east-2.rds.amazonaws.com. Database name is random-db
Assistant: [Connects to random-db database]
Assistant: ✅ Connection established (metadata validation passed)

User: [Query executed automatically]
Assistant: ❌ Error: "run_query unexpected error"
Assistant: Query failed - database "random-db" doesn't exist in the cluster

User: Document this negative test case where we try to query an invalid database (random-db) as TC-018
Assistant: [Documents test case]
```

**Suggested Improvements:**
1. Add database existence validation during connection by querying `pg_database` catalog
2. Return more descriptive error message indicating database not found (e.g., "database 'random-db' does not exist")
3. List available databases in the error message to help users
4. Consider adding a tool to list available databases in a cluster
5. Fail fast at connection time rather than during query execution

**Related Test Cases:**  
- TC-017: Invalid endpoint (fails at network validation)
- TC-016: Cluster doesn't exist (fails at metadata validation)
- TC-011: Successful connection with valid database (postgres)

---

## Test Summary

| Test ID | Test Name | Status | Duration | Notes |
|---------|-----------|--------|----------|-------|
| TC-001  | Create Aurora PostgreSQL Cluster | ✅ Pass | ~5-10 min | Async operation, requires polling |
| TC-002  | Create Express Configuration Cluster | ✅ Pass | < 1 min | Synchronous, uses preview endpoint |
| TC-003  | Connect to Cluster via RDS API | ✅ Pass | < 5 sec | Auto-detects connection method |
| TC-004  | Connect to Express Cluster (IAM Auth) | ✅ Pass | < 5 sec | Uses pgwire + IAM, not RDS API |
| TC-004a | Query Express Cluster via RDS API | ❌ Fail | < 5 sec | Cannot force RDS API on express clusters |
| TC-004b | Attempt pgwire Connection to Express Cluster | ❌ Fail | < 10 sec | Express clusters require pgwire_iam, not pgwire |
| TC-005  | List All Cached Connections | ✅ Pass | < 1 sec | Shows all active connections |
| TC-006  | Connect to Regular Cluster via Direct Connection | ✅ Pass | < 5 sec | Auto-selected RDS API method |
| TC-006a | Query Regular Cluster via PG Wire | ❌ Fail | < 5 sec | Cannot force pgwire on RDS API clusters |
| TC-006b | Query Regular Cluster via PG Wire with Public Access | ✅ Pass | < 10 sec | Requires RDS API disabled + public access |
| TC-007  | Reconnect to Express Cluster (Direct Method) | ✅ Pass | < 5 sec | Reconnect after expiration |
| TC-008  | Create Table and Insert Data in Multiple Clusters | ✅ Pass | < 10 sec | DDL/DML across both connection methods |
| TC-009  | Query Data from Multiple Clusters | ✅ Pass | < 10 sec | Multi-cluster queries work, Issue #1 resolved |
| TC-010  | Test Write Query Restriction Without allow_write_query Flag | ✅ Pass | < 10 sec | Blocks writes without flag, allows reads |
| TC-011  | Connect to Existing Cluster with Secrets Manager and Execute Queries | ✅ Pass | < 15 sec | Pgwire with Secrets Manager works correctly |
| TC-012  | Enable RDS Data API and Connect to Existing Cluster | ✅ Pass | ~5 min | Resolves pgwire query issues |
| TC-013  | Connect and Query Standalone RDS PostgreSQL Instance | ✅ Pass | < 15 sec | Requires empty cluster_identifier |
| TC-014  | Connect to RDS PostgreSQL Multi-AZ DB Cluster | ✅ Pass | < 10 sec | Multi-AZ clusters supported via pgwire |
| TC-015  | Query Cluster Without Secrets Manager Enabled (Negative Test) | ❌ Fail (Expected) | < 10 sec | Validates failure when Secrets Manager not configured |
| TC-016  | Connect to Non-Existent Cluster (Negative Test) | ❌ Fail (Expected) | < 5 sec | Validates cluster existence check with clear error |
| TC-017  | Connect with Valid Cluster ID but Incorrect Endpoint (Negative Test) | ❌ Fail (Expected) | < 10 sec | Connection succeeds, query fails due to invalid endpoint |
| TC-018  | Connect to Non-Existent Database in Valid Cluster (Negative Test) | ❌ Fail (Expected) | < 10 sec | Connection succeeds, query fails due to invalid database |

---


## Issues Found

### Issue #1: pgwire Connection Query Failure on Express Cluster (ufc-2)
**Date:** 2025-12-04  
**Severity:** High  
**Status:** Open  

**Description:**  
When attempting to query an express configuration cluster (ufc-2) using pgwire connection method (non-IAM), the connection appears to succeed but queries fail with "run_query unexpected error".

**Reproduction Steps:**
1. Create express cluster: `ufc-2` in `us-east-2` preview region
2. Connect using pgwire (not pgwire_iam):
   ```json
   {
     "tool": "connect_to_database",
     "params": {
       "database_type": "APG",
       "region": "us-east-2",
       "cluster_identifier": "ufc-2",
       "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
       "port": 5432,
       "database": "ufc-2",
       "connection_method": "pgwire",
       "with_express_configuration": true
     }
   }
   ```
3. Connection succeeds and returns connection info
4. Execute query: `SELECT version()`
5. Query fails with: `{"error": "run_query unexpected error"}`

**Expected Behavior:**  
Query should either:
- Fail at connection time with clear error message about authentication method
- Succeed if pgwire (Secrets Manager) is supported

**Actual Behavior:**  
- Connection succeeds silently
- Query execution fails with generic error message
- No indication that pgwire_iam is required

**Root Cause:**  
Express clusters are configured for IAM authentication only and do not have Secrets Manager secrets. The pgwire connection method requires Secrets Manager credentials, which don't exist for express clusters.

**Workaround:**  
Use `connection_method: "pgwire_iam"` instead of `"pgwire"` for express clusters.

**Suggested Fix:**
1. Detect express configuration during connection and validate authentication method compatibility
2. Return clear error message if incompatible method is requested
3. Auto-select pgwire_iam for express clusters when connection_method is not specified
4. Add validation in connect_to_database to reject pgwire for express clusters

**Related Test Cases:**  
- TC-004b: Documents this issue
- TC-004: Shows correct pgwire_iam usage

---

### Issue #2: RDS API Connection Query Failure on Express Cluster (ufc-2)
**Date:** 2025-12-04  
**Severity:** High  
**Status:** Open  

**Description:**  
When attempting to query an express configuration cluster (ufc-2) using RDS API connection method, the connection appears to succeed but queries fail with "run_query unexpected error".

**Reproduction Steps:**
1. Create express cluster: `ufc-2` in `us-east-2` preview region
2. Connect using rdsapi:
   ```json
   {
     "tool": "connect_to_database",
     "params": {
       "database_type": "APG",
       "region": "us-east-2",
       "cluster_identifier": "ufc-2",
       "db_endpoint": "ufc-2.cluster-cni82m4m0h5z.us-east-2.rds-preview.amazonaws.com",
       "port": 5432,
       "database": "ufc-2",
       "connection_method": "rdsapi",
       "with_express_configuration": true
     }
   }
   ```
3. Connection succeeds and returns connection info
4. Execute query: `SELECT version()`
5. Query fails with: `{"error": "run_query unexpected error"}`

**Expected Behavior:**  
Query should either:
- Fail at connection time with clear error message that RDS API is not supported
- Succeed if RDS API is enabled on the express cluster

**Actual Behavior:**  
- Connection succeeds silently
- Query execution fails with generic error message
- No indication that rdsapi is not supported for express clusters

**Root Cause:**  
Express clusters in preview regions may not have RDS Data API enabled or supported. The connection method accepts the rdsapi parameter but the underlying cluster doesn't support HTTP endpoint queries.

**Workaround:**  
Use `connection_method: "pgwire_iam"` instead of `"rdsapi"` for express clusters.

**Suggested Fix:**
1. Check if RDS Data API is enabled on the cluster during connection
2. Return clear error message if rdsapi is requested but not available
3. Auto-select pgwire_iam for express clusters when connection_method is not specified
4. Add validation in connect_to_database to reject rdsapi for express clusters without HTTP endpoint

**Pattern:**  
This issue mirrors Issue #1 - express clusters appear to only support pgwire_iam connection method, but the connection validation doesn't prevent other methods from being attempted.

**Related Test Cases:**  
- TC-004a: Documents similar issue with rdsapi on express clusters
- TC-004: Shows correct pgwire_iam usage

---

## Notes & Observations

- [General observations about MCP tool behavior]
- [Performance notes]
- [Suggestions for improvement]
