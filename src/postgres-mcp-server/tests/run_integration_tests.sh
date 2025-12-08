#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Integration Test Runner for Postgres MCP Server
# This script helps set up and run integration tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/integration_test_config.yaml"
LOCAL_CONFIG_FILE="$SCRIPT_DIR/integration_test_config.local.yaml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Postgres MCP Server Integration Tests"
echo "=========================================="
echo ""

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ] && [ ! -f "$LOCAL_CONFIG_FILE" ]; then
    echo -e "${RED}Error: Configuration file not found${NC}"
    echo "Please create either:"
    echo "  - $CONFIG_FILE"
    echo "  - $LOCAL_CONFIG_FILE (recommended for local testing)"
    echo ""
    echo "See INTEGRATION_TESTS_README.md for configuration details"
    exit 1
fi

# Check AWS credentials
if [ -z "$AWS_ACCESS_KEY_ID" ] && [ -z "$AWS_PROFILE" ]; then
    echo -e "${YELLOW}Warning: AWS credentials not detected${NC}"
    echo "Please configure AWS credentials using one of:"
    echo "  - AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables"
    echo "  - AWS_PROFILE environment variable"
    echo "  - AWS CLI configuration (~/.aws/credentials)"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Parse command line arguments
TEST_FILTER=""
VERBOSE=""
COVERAGE=""
SKIP_SLOW=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE="-v -s"
            shift
            ;;
        -c|--coverage)
            COVERAGE="--cov=awslabs.postgres_mcp_server --cov-report=html --cov-report=term"
            shift
            ;;
        --skip-slow)
            SKIP_SLOW="--skip-slow"
            shift
            ;;
        -k)
            TEST_FILTER="-k $2"
            shift 2
            ;;
        --cluster-creation)
            TEST_FILTER="TestClusterCreation"
            shift
            ;;
        --connection)
            TEST_FILTER="TestDatabaseConnection"
            shift
            ;;
        --query)
            TEST_FILTER="TestQueryExecution"
            shift
            ;;
        --ddl)
            TEST_FILTER="TestDDLOperations"
            shift
            ;;
        --dml)
            TEST_FILTER="TestDMLOperations"
            shift
            ;;
        --readonly)
            TEST_FILTER="TestReadonlyMode"
            shift
            ;;
        --security)
            TEST_FILTER="TestSQLInjectionProtection"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose          Verbose output"
            echo "  -c, --coverage         Generate coverage report"
            echo "  --skip-slow            Skip slow tests (cluster creation)"
            echo "  -k PATTERN             Run tests matching pattern"
            echo "  --cluster-creation     Run cluster creation tests only"
            echo "  --connection           Run connection tests only"
            echo "  --query                Run query execution tests only"
            echo "  --ddl                  Run DDL operation tests only"
            echo "  --dml                  Run DML operation tests only"
            echo "  --readonly             Run readonly mode tests only"
            echo "  --security             Run security tests only"
            echo "  -h, --help             Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                     # Run all integration tests"
            echo "  $0 -v                  # Run with verbose output"
            echo "  $0 --connection        # Run connection tests only"
            echo "  $0 -k test_select      # Run tests matching 'test_select'"
            echo "  $0 --coverage          # Run with coverage report"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Display configuration
echo -e "${GREEN}Configuration:${NC}"
if [ -f "$LOCAL_CONFIG_FILE" ]; then
    echo "  Using: $LOCAL_CONFIG_FILE"
else
    echo "  Using: $CONFIG_FILE"
fi
echo ""

# Display test plan
echo -e "${GREEN}Test Plan:${NC}"
if [ -n "$TEST_FILTER" ]; then
    echo "  Running filtered tests: $TEST_FILTER"
else
    echo "  Running all integration tests"
fi
if [ -n "$SKIP_SLOW" ]; then
    echo "  Skipping slow tests"
fi
if [ -n "$COVERAGE" ]; then
    echo "  Generating coverage report"
fi
echo ""

# Confirm before running
read -p "Start integration tests? (Y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo "Cancelled"
    exit 0
fi

# Run tests
echo ""
echo -e "${GREEN}Running integration tests...${NC}"
echo ""

cd "$SCRIPT_DIR/.."

if [ -n "$TEST_FILTER" ]; then
    pytest tests/test_integration.py::$TEST_FILTER -m integration $VERBOSE $COVERAGE $SKIP_SLOW
else
    pytest tests/test_integration.py -m integration $VERBOSE $COVERAGE $SKIP_SLOW $TEST_FILTER
fi

TEST_EXIT_CODE=$?

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    
    if [ -n "$COVERAGE" ]; then
        echo ""
        echo "Coverage report generated:"
        echo "  HTML: htmlcov/index.html"
    fi
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo "Check the output above for details"
fi

exit $TEST_EXIT_CODE
