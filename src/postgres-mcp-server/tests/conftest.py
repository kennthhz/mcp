import pytest
from typing import List, Dict, Any
from botocore.exceptions import ClientError

class Mock_boto3_client:
    def __init__(self, throw_client_error = False):
        self._responses: List[dict] = []
        self.throw_client_error = throw_client_error
        self._current_response_index = 0

    def execute_statement(self, **kwargs) -> dict:
        if self.throw_client_error:
            error_response = {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "User is not authorized to perform rds-data:ExecuteStatement"
                }
            }
            raise ClientError(error_response, operation_name="ExecuteStatement")

        if self._current_response_index < len(self._responses):
            response = self._responses[self._current_response_index]
            self._current_response_index += 1
            return response
        raise Exception("Mock_boto3_client.execute_statement mock response out of bound")

    def add_mock_response(self, response):
        self._responses.append(response)

class Mock_DBConnection:
    def __init__(self, reaodnly, throw_client_error = False):
        self.cluster_arn = 'dummy_cluster_arn'
        self.secret_arn = 'dummy_secret_arn'
        self.database = 'dummy_database'
        self.reaodnly = reaodnly
        self.throw_client_error = throw_client_error
        self._data_client = Mock_boto3_client(throw_client_error)

    @property
    def data_client(self):
        return self._data_client
    
    @property
    def readonly_query(self):
        return self.reaodnly

@pytest.fixture
def mock_DBConnection():
    return Mock_DBConnection()
