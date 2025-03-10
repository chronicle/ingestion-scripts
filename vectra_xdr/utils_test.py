# Copyright 2025 Google LLC
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
#
# pylint: disable=line-too-long
# pylint: disable=invalid-name
# pylint: disable=unused-argument
# pylint: disable=g-importing-member
# pylint: disable=g-import-not-at-top

import concurrent.futures
import unittest
from unittest import mock
from google.api_core import exceptions

import constant
import exception
import utils as vectar_utils

NotFound = exceptions.NotFound
patch = mock.patch
Mock = mock.Mock
MagicMock = mock.MagicMock

INGESTION_SCRIPTS_PATH = ""


class TestUtils(unittest.TestCase):

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.default", return_value=(MagicMock(), "project-id"))
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.get_environment_variable", return_value="env_gcp_project_number_value")
  def test_env_var_gcp_project_number(self, mock_env_var, mock_default):
    vectar_utils.SecretManagerClient()
    mock_env_var.assert_any_call(constant.ENV_GCP_PROJECT_NUMBER, is_required=True)

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.constant.DEFAULT_VALUES", {"EXISTING_VAR": "default_value"})
  @patch.dict("os.environ", {"EXISTING_VAR": " VALUE "})
  def test_env_var_exists_not_secret(self):
    """Test when the environment variable exists and is not a secret."""
    result = vectar_utils.get_environment_variable(
        "EXISTING_VAR", is_required=False, is_secret=False
    )
    self.assertEqual(
        result, "value"
    )  # Value should be lowercased and stripped.

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.constant.DEFAULT_VALUES", {"SECRET_VAR": "default_secret"})
  @patch.dict("os.environ", {"SECRET_VAR": " SECRET_VALUE "})
  def test_env_var_exists_secret(self):
    """Test when the environment variable exists and is marked as secret."""
    result = vectar_utils.get_environment_variable(
        "SECRET_VAR", is_required=False, is_secret=True
    )
    self.assertEqual(result, "SECRET_VALUE")  # Value should not be lowercased.

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.constant.DEFAULT_VALUES", {"DEFAULT_VAR": "default_value"})
  @patch.dict("os.environ", {})
  def test_env_var_missing_with_default(self):
    """Test when the environment variable is missing but a default value exists."""
    result = vectar_utils.get_environment_variable(
        "DEFAULT_VAR", is_required=False, is_secret=False
    )
    self.assertEqual(
        result, "default_value"
    )  # Default value should be returned and lowercased.

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.constant.DEFAULT_VALUES", {"REQUIRED_VAR": "required_default"})
  @patch.dict("os.environ", {})
  def test_env_var_missing_required(self):
    """Test when the environment variable is required but missing."""
    with self.assertRaises(RuntimeError) as context:
      vectar_utils.get_environment_variable(
          "REQUIRED_VAR", is_required=True, is_secret=False
      )
    self.assertEqual(
        str(context.exception), "Environment variable REQUIRED_VAR is required."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.constant.DEFAULT_VALUES", {})
  @patch.dict("os.environ", {})
  def test_env_var_no_default_value(self):
    """Test when the environment variable is missing and no default value exists."""
    result = vectar_utils.get_environment_variable(
        "MISSING_VAR", is_required=False, is_secret=False
    )
    self.assertEqual(
        result, ""
    )  # Should return an empty string if no default exists.

  @patch(
      f"{INGESTION_SCRIPTS_PATH}utils.constant.DEFAULT_VALUES", {"STRIPPED_VAR": " default_value_with_spaces "}
  )
  @patch.dict("os.environ", {"STRIPPED_VAR": "    SPACED_VALUE   "})
  def test_env_var_value_with_spaces(self):
    """Test when the environment variable value has leading/trailing spaces."""
    result = vectar_utils.get_environment_variable(
        "STRIPPED_VAR", is_required=False, is_secret=False
    )
    self.assertEqual(
        result, "spaced_value"
    )  # Value should be stripped and lowercased.

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.constant.METHOD_INTERVAL", 1)  # Mock METHOD_INTERVAL to 1
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utils.time.sleep", return_value=None
  )  # Mock time.sleep to avoid delay
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utils.delayed_execution"
  )
  def test_run_methods_with_intervals(
      self, mock_delayed_execution, mock_cloud_logging, mock_sleep
  ):

    mock_method_1 = MagicMock(return_value="result_1")
    mock_method_2 = MagicMock(return_value="result_2")

    methods = [mock_method_1, mock_method_2]

    vectar_utils.run_methods_with_intervals(methods)

    mock_delayed_execution.assert_any_call(mock_method_1)
    mock_delayed_execution.assert_any_call(mock_method_2)

    mock_cloud_logging.assert_called_with("Sleeping for 1 seconds")

    mock_sleep.assert_called_with(1)

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.constant.METHOD_INTERVAL", 1)
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.time.sleep", return_value=None)
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.delayed_execution")
  def test_run_methods_with_empty_method_list(
      self, mock_delayed_execution, mock_cloud_logging, mock_sleep
  ):
    """Test when the list of methods is empty."""

    vectar_utils.run_methods_with_intervals([])

    mock_delayed_execution.assert_not_called()
    mock_sleep.assert_not_called()
    mock_cloud_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_delayed_execution_successful(self, mock_cloud_logging):

    mock_method = Mock()
    mock_method.__name__ = "mock_method"

    vectar_utils.delayed_execution(mock_method)

    mock_method.assert_called_once()
    mock_cloud_logging.assert_any_call("Executing mock_method method")
    mock_cloud_logging.assert_any_call("Completed mock_method method")

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.default", return_value=(MagicMock(), "project-id"))
  @patch("google.cloud.secretmanager.SecretManagerServiceClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  @patch.dict("os.environ", {"GCP_PROJECT_NUMBER": "1234567890"})
  def test_get_secrets_success(
      self, mock_cloud_logging, mock_secret_manager, mock_default
  ):
    """Test retrieving a secret successfully."""

    mock_client = MagicMock()
    mock_secret_manager.return_value = mock_client
    mock_client.access_secret_version.return_value = MagicMock(
        payload=MagicMock(data=b'{"key": "value"}')
    )

    client = vectar_utils.SecretManagerClient()
    result = client.get_secrets("my-secret")
    self.assertEqual(
        result, {"key": "value"}
    )
    mock_cloud_logging.assert_called_with("Secret Manager Client Initialized.")

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.default", return_value=(MagicMock(), "project-id"))
  @patch("google.cloud.secretmanager.SecretManagerServiceClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  @patch.dict("os.environ", {"GCP_PROJECT_NUMBER": "1234567890"})
  def test_get_secrets_not_found(
      self, mock_cloud_logging, mock_secret_manager, mock_default
  ):
    """Test retrieving a secret when it's not found."""
    mock_client = MagicMock()
    mock_secret_manager.return_value = mock_client
    mock_client.access_secret_version.side_effect = NotFound("Secret not found")

    client = vectar_utils.SecretManagerClient()
    with self.assertRaisesRegex(exception.VectraException, "Secret not found"):
      client.get_secrets("non_existent_secret")
    mock_cloud_logging.assert_called_with(
        "Secret not found while retrieving the secret."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.default", return_value=(MagicMock(), "project-id"))
  @patch("google.cloud.secretmanager.SecretManagerServiceClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  @patch.dict("os.environ", {"GCP_PROJECT_NUMBER": "1234567890"})
  def test_get_secrets_exception(
      self, mock_cloud_logging, mock_secret_manager, mock_default
  ):
    """Test handling exceptions during secret retrieval."""
    mock_client = MagicMock()
    mock_secret_manager.return_value = mock_client
    mock_client.access_secret_version.side_effect = Exception(
        "Secret retrieval failed"
    )

    client = vectar_utils.SecretManagerClient()
    with self.assertRaisesRegex(exception.VectraException, "Secret retrieval failed"):
      client.get_secrets("my-secret")
    mock_cloud_logging.assert_called_with(
        "Unknown exception occurred while retrieving the secret. Error message:"
        " Secret retrieval failed"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.default", return_value=(MagicMock(), "project-id"))
  @patch("google.cloud.secretmanager.SecretManagerServiceClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  @patch.dict("os.environ", {"GCP_PROJECT_NUMBER": "1234567890"})
  def test_set_or_update_secrets_exception(
      self, mock_cloud_logging, mock_secret_manager, mock_default
  ):
    """Test handling exceptions during secret update/creation."""
    mock_client = mock_secret_manager.return_value
    mock_client.add_secret_version.side_effect = Exception(
        "Secret update failed"
    )

    client = vectar_utils.SecretManagerClient()
    with self.assertRaisesRegex(exception.VectraException, "Secret update failed"):
      client.set_or_update_secrets("my-secret", {"key": "value"})

    mock_cloud_logging.assert_called_with(
        "Unknown exception occurred while updating the secret. Error message:"
        " Secret update failed"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.default", return_value=(MagicMock(), "project-id"))
  @patch("google.cloud.secretmanager.SecretManagerServiceClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  @patch.dict("os.environ", {"GCP_PROJECT_NUMBER": "1234567890"})
  def test_set_or_update_secrets_not_found(
      self, mock_cloud_logging, mock_secret_manager, mock_default
  ):
    """Test setting a new secret when it doesn't exist."""
    mock_client = mock_secret_manager.return_value

    mock_client.add_secret_version.side_effect = [
        NotFound("Secret not found"),
        None,
    ]

    mock_client.create_secret.return_value = MagicMock(
        name="created_secret_path"
    )
    client = vectar_utils.SecretManagerClient()

    client.set_or_update_secrets("new-secret", {"key": "value"})

    mock_client.create_secret.assert_called_once()
    mock_client.add_secret_version.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.constant.METHOD_INTERVAL", 1)
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.time.sleep")
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utils.concurrent.futures.ThreadPoolExecutor"
  )
  def test_run_methods_with_intervals_exception(
      self, mock_executor, mock_logging, mock_sleep
  ):

    future1 = concurrent.futures.Future()
    future1.set_exception(Exception("Method 1 failed"))
    future2 = concurrent.futures.Future()
    future2.set_result("Method 2 success")

    mock_executor.return_value.__enter__.return_value.submit.side_effect = [
        future1,
        future2,
    ]

    methods = [lambda: None, lambda: None]

    vectar_utils.run_methods_with_intervals(methods)

    mock_logging.assert_any_call(
        "Exception occurred while executing a method: Method 1 failed",
        severity="ERROR",
    )

    mock_sleep.assert_called_with(1)

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_internal_server_error(self, mock_cloud_logging):
    """Test InternalServerError handling."""
    mock_response = Mock(status_code=500, content=b"Internal Server Error")
    with self.assertRaises(exception.InternalSeverError):
      vectar_utils.HandleExceptions("test_api", "Test Error", mock_response).do_process()
    mock_cloud_logging.assert_called_with(
        "It seems like the Vectra server is experiencing some issues,"
        " Status: 500"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_general_error(self, mock_cloud_logging):
    mock_response = Mock(
        status_code=404, content=b"Not Found"
    )
    with self.assertRaisesRegex(
        exception.VectraException, "An error occurred: Test Error - b'Not Found'"
    ):
      vectar_utils.HandleExceptions("test_api", "Test Error", mock_response).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_bad_request_empty_list(self, mock_cloud_logging):
    mock_response = Mock(status_code=400, json=lambda: ["An error occurred"])
    with self.assertRaisesRegex(exception.BadRequestException, "An error occurred"):
      vectar_utils.HandleExceptions("test_api", "Test Error", mock_response).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_bad_request_non_json(
      self, mock_cloud_logging
  ):
    mock_response = Mock(
        status_code=400, content=b"Invalid JSON"
    )
    with self.assertRaisesRegex(
        exception.VectraException, "An error occurred: Test Error - b'Invalid JSON'"
    ):
      vectar_utils.HandleExceptions(
          "test_api", "Test Error", mock_response
      ).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_bad_request_list(self, mock_cloud_logging):
    mock_response = Mock(status_code=400, json=lambda: ["Error 1", "Error 2"])
    with self.assertRaisesRegex(exception.BadRequestException, "Error 1"):
      vectar_utils.HandleExceptions("test_api", "Test Error", mock_response).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_bad_request_dict_with_meta(
      self, mock_cloud_logging
  ):
    mock_response = Mock(
        status_code=400,
        json=lambda: {"_meta": "meta", "error_field": "Error Value"},
    )
    with self.assertRaisesRegex(exception.BadRequestException, "Error Value"):
      vectar_utils.HandleExceptions("test_api", "Test Error", mock_response).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_bad_request_dict(self, mock_cloud_logging):
    mock_response = Mock(
        status_code=400, json=lambda: {"error_field": "Error Value"}
    )
    with self.assertRaisesRegex(exception.BadRequestException, "Error Value"):
      vectar_utils.HandleExceptions("test_api", "Test Error", mock_response).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_unauthorized(self, mock_cloud_logging):
    """Test UnauthorizedException handling."""
    mock_response = Mock(
        status_code=401, json=lambda: {"error": "unauthorized"}
    )
    with self.assertRaisesRegex(exception.UnauthorizeException, "UnauthorizeException"):
      vectar_utils.HandleExceptions("test_api", "Test Error", mock_response).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_auth_handle_exceptions_unauthorized(self, mock_cloud_logging):
    """Test UnauthorizedException handling for auth endpoint."""
    mock_response = Mock(
        status_code=402, json=lambda: {"error": "unauthorized"}
    )
    with self.assertRaisesRegex(exception.VectraException, r"An error occurred: Test Error - .*"):
      vectar_utils.HandleExceptions(constant.VECTRA_ACCESS_TOKEN_ENDPOINT, "Test Error", mock_response).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_unknown_auth_error(self, mock_cloud_logging):
    """Test exception.UnauthorizeException handling for other authentication errors."""
    mock_response = Mock(
        status_code=401, json=lambda: {"error": "some_other_auth_error"}
    )
    with self.assertRaisesRegex(exception.UnauthorizeException, "some_other_auth_error"):
      vectar_utils.HandleExceptions("oauth2/token", "Test Error", mock_response).do_process()

  def test_get_handler_auth(self):
    mock_response = Mock(status_code=400, json=lambda: {"error": "some_error"})
    handler_exception, _ = vectar_utils.HandleExceptions(
        "oauth2/token", "Test Error", mock_response
    ).get_handler()
    self.assertEqual(handler_exception, exception.RefreshTokenException)

  def test_get_handler_common(self):
    mock_response = Mock(status_code=400, json=lambda: {"error": "some_error"})
    handler_exception, _ = vectar_utils.HandleExceptions(
        "test_api", "Test Error", mock_response
    ).get_handler()
    self.assertEqual(handler_exception, exception.BadRequestException)

  def test_handle_bad_request_error_empty_list(self):
    """Test case for an empty list in bad request error."""
    mock_response = Mock(status_code=400)
    mock_response.json.return_value = []

    url = "test_url"
    error = Exception("Bad Request")
    handler = vectar_utils.HandleExceptions(url, error, mock_response)

    with self.assertRaises(Exception) as context:
      handler.do_process()
    self.assertIn("An error occurred", str(context.exception))

  def test_delayed_execution_not_callable_case(self):
    """Test delayed_execution when method is not callable."""
    non_callable = "not_a_function"

    with self.assertRaisesRegex(ValueError, "Method is not callable"):
      vectar_utils.delayed_execution(non_callable)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}utils.default",
      return_value=(MagicMock(), "project-id"),
  )
  @patch("google.cloud.secretmanager.SecretManagerServiceClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  @patch.dict("os.environ", {"GCP_PROJECT_NUMBER": "1234567890"})
  def test_set_or_update_secrets_existing_secret(
      self, mock_cloud_logging, mock_secret_manager, mock_default
  ):
    """Test updating an existing secret."""
    mock_client = mock_secret_manager.return_value
    mock_version = mock.Mock()
    mock_version.name = "projects/1234567890/secrets/existing-secret/versions/1"
    mock_client.list_secret_versions.return_value = [mock_version]

    client = vectar_utils.SecretManagerClient()
    client.set_or_update_secrets("existing-secret", {"key": "new_value"})

    mock_client.add_secret_version.assert_called_once()
    mock_client.disable_secret_version.assert_called_once_with(
        request={
            "name": "projects/1234567890/secrets/existing-secret/versions/1"
        }
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_common_error_non_json(
      self, mock_cloud_logging
  ):
    mock_response = Mock(
        status_code=400, content=b"Invalid JSON"
    )
    mock_response.json.side_effect = Exception("Invalid JSON")
    with self.assertRaises(Exception):
      vectar_utils.HandleExceptions(
          "oauth2/token", "Error Test", mock_response
      ).do_process()

  @patch(f"{INGESTION_SCRIPTS_PATH}utils.utils.cloud_logging")
  def test_handle_exceptions_auth_handle_refresh_token(
      self, mock_cloud_logging
  ):
    mock_response = Mock(status_code=401)
    mock_response.content = b'{"error": "Please try reauthenticating using API client credentials"}'
    mock_response.json.return_value = {"error": "Please try reauthenticating using API client credentials"}

    with self.assertRaisesRegex(
        exception.RefreshTokenException, "Please try reauthenticating using API client credentials"
    ):
      vectar_utils.HandleExceptions(
          "oauth2/token", "Error test", mock_response
      ).do_process()
