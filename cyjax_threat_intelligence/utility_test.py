# Copyright 2026 Google LLC
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

# pylint: disable=line-too-long
# pylint: disable=g-importing-member
# pylint: disable=invalid-name
# pylint: disable=g-multiple-import
# pylint: disable=unused-argument
# pylint: disable=g-import-not-at-top
# pylint: disable=g-bad-import-order
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=g-bad-exception-name
# pylint: disable=redefined-outer-name

"""Unit tests for utility module."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import datetime
from types import SimpleNamespace

REAL_DATETIME_CLASS = datetime.datetime


# Create proper exception classes for google.cloud.exceptions
class MockForbidden(Exception):
  """Mock for google.cloud.exceptions.Forbidden."""


class MockNotFound(Exception):
  """Mock for google.cloud.exceptions.NotFound."""


# Create a proper mock module for google.cloud.exceptions with real classes
class MockGoogleCloudExceptions:
  """Mock module for google.cloud.exceptions."""

  Forbidden = MockForbidden
  NotFound = MockNotFound


# Create proper mock structure for google modules before importing utility
mock_google = MagicMock()
mock_cloud = MagicMock()
mock_storage = MagicMock()
mock_resourcemanager = MagicMock()
mock_requests = MagicMock()

mock_google.cloud = mock_cloud
mock_cloud.storage = mock_storage
mock_cloud.resourcemanager_v3 = mock_resourcemanager
mock_cloud.exceptions = MockGoogleCloudExceptions
mock_storage.Client = MagicMock
mock_storage.retry = MagicMock()
mock_storage.retry.DEFAULT_RETRY = MagicMock()
mock_storage.retry.DEFAULT_RETRY.with_delay = MagicMock(
    return_value=MagicMock()
)
mock_storage.retry.DEFAULT_RETRY.with_delay.return_value.with_deadline = (
    MagicMock(return_value=MagicMock())
)

sys.modules["google"] = mock_google
sys.modules["google.cloud"] = mock_cloud
sys.modules["google.cloud.storage"] = mock_storage
sys.modules["google.cloud.resourcemanager_v3"] = mock_resourcemanager
sys.modules["google.cloud.exceptions"] = MockGoogleCloudExceptions
sys.modules["requests"] = mock_requests

# Mock common modules
mock_common = MagicMock()
mock_utils = MagicMock()
mock_env_constants = MagicMock()
mock_common.utils = mock_utils
mock_common.env_constants = mock_env_constants
INGESTION_SCRIPTS_PATH = ""
sys.modules["common"] = mock_common
sys.modules["common.utils"] = mock_utils
sys.modules["common.env_constants"] = mock_env_constants
import utility
import constant
from exception_handler import CyjaxException, GCPPermissionDeniedError


class TestUtilityFunctions(unittest.TestCase):
  """Test utility functions."""

  @patch.dict(os.environ, {"TEST_VAR": "test_value"})
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_regular(self, mock_get_env):
    """Test get_environment_variable for regular variable."""
    mock_get_env.return_value = "test_value"

    result = utility.get_environment_variable("TEST_VAR")

    self.assertEqual(result, "test_value")

  @patch.dict(os.environ, {"SECRET_VAR": "secret_path"})
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_value_from_secret_manager")
  def test_get_environment_variable_secret(self, mock_get_secret):
    """Test get_environment_variable for secret."""
    mock_get_secret.return_value = "secret_value"

    result = utility.get_environment_variable("SECRET_VAR", is_secret=True)

    self.assertEqual(result, "secret_value")

  @patch.dict(os.environ, {})
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_default(self, mock_get_env):
    """Test get_environment_variable with default."""
    mock_get_env.return_value = "default_value"

    result = utility.get_environment_variable("MISSING_VAR")

    self.assertEqual(result, "default_value")

  @patch.dict(os.environ, {"SECRET_VAR": "secret_path"})
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_value_from_secret_manager")
  def test_get_environment_variable_secret_with_versions(self, mock_get_secret):
    """Test get_environment_variable secret path with versions."""
    mock_get_secret.return_value = "secret_value"

    result = utility.get_environment_variable("SECRET_VAR", is_secret=True)

    self.assertEqual(result, "secret_value")
    mock_get_secret.assert_called_with("secret_path/versions/latest")

  @patch.dict(os.environ, {}, clear=True)
  def test_get_environment_variable_secret_required_missing(self):
    """Test get_environment_variable raises when secret required and missing."""
    with self.assertRaises(RuntimeError):
      utility.get_environment_variable(
          "SECRET_VAR", is_secret=True, is_required=True
      )

  @patch.dict(os.environ, {}, clear=True)
  def test_get_environment_variable_secret_optional_default(self):
    """Test get_environment_variable returns default when secret optional."""
    result = utility.get_environment_variable(
        constant.ENV_HISTORICAL_IOC_DURATION, is_secret=True
    )

    self.assertEqual(
        result,
        constant.DEFAULT_VALUES[constant.ENV_HISTORICAL_IOC_DURATION],
    )

  def test_parse_boolean_env_true(self):
    """Test parse_boolean_env with true."""
    result = utility.parse_boolean_env("true")
    self.assertTrue(result)

  def test_parse_boolean_env_false(self):
    """Test parse_boolean_env with false."""
    result = utility.parse_boolean_env("false")
    self.assertFalse(result)

  def test_parse_boolean_env_none(self):
    """Test parse_boolean_env with None."""
    result = utility.parse_boolean_env(None)
    self.assertFalse(result)

  def test_validate_integer_env_valid_int(self):
    """Test validate_integer_env with valid int."""
    result = utility.validate_integer_env(5, "test_param")
    self.assertEqual(result, 5)

  def test_validate_integer_env_valid_str(self):
    """Test validate_integer_env with valid string."""
    result = utility.validate_integer_env("10", "test_param")
    self.assertEqual(result, 10)

  def test_validate_integer_env_none_with_default(self):
    """Test validate_integer_env with None and default."""
    result = utility.validate_integer_env(None, "test_param", "7")
    self.assertEqual(result, 7)

  def test_validate_integer_env_none_no_default(self):
    """Test validate_integer_env with None and no default."""
    result = utility.validate_integer_env(None, "test_param")
    self.assertIsNone(result)

  def test_validate_integer_env_zero(self):
    """Test validate_integer_env with zero."""
    with self.assertRaises(CyjaxException):
      utility.validate_integer_env(0, "test_param")

  def test_validate_integer_env_negative(self):
    """Test validate_integer_env with negative."""
    with self.assertRaises(CyjaxException):
      utility.validate_integer_env(-1, "test_param")

  def test_validate_integer_env_invalid_str(self):
    """Test validate_integer_env with invalid string."""
    with self.assertRaises(CyjaxException):
      utility.validate_integer_env("abc", "test_param")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_last_checkpoint_success(self, mock_log, mock_client):
    """Test get_last_checkpoint successful."""
    mock_storage_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = '{"test_key": "test_value"}'

    result = utility.get_last_checkpoint("test-bucket", "test_key")

    self.assertEqual(result, "test_value")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_last_checkpoint_no_blob(self, mock_log, mock_client):
    """Test get_last_checkpoint with no blob."""
    mock_storage_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False

    result = utility.get_last_checkpoint("test-bucket", "test_key")

    self.assertIsNone(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_last_checkpoint_forbidden(self, mock_log, mock_client):
    """Test get_last_checkpoint when permissions are denied."""
    mock_storage_client = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.side_effect = utility.exceptions.Forbidden(
        "denied"
    )

    with self.assertRaises(GCPPermissionDeniedError):
      utility.get_last_checkpoint("test-bucket", "test_key")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_last_checkpoint_not_found(self, mock_log, mock_client):
    """Test get_last_checkpoint when bucket is missing."""
    mock_storage_client = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.side_effect = utility.exceptions.NotFound(
        "missing"
    )

    with self.assertRaises(RuntimeError):
      utility.get_last_checkpoint("test-bucket", "test_key")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_last_checkpoint_unknown_error(self, mock_log, mock_client):
    """Test get_last_checkpoint returns None on unknown errors."""
    mock_storage_client = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.side_effect = Exception("boom")

    result = utility.get_last_checkpoint("test-bucket", "test_key")

    self.assertIsNone(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_last_checkpoint_invalid_json(self, mock_log, mock_client):
    """Test get_last_checkpoint with invalid JSON."""
    mock_storage_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "invalid json"

    result = utility.get_last_checkpoint("test-bucket", "test_key")

    self.assertIsNone(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_set_last_checkpoint_success(self, mock_log, mock_client):
    """Test set_last_checkpoint successful."""
    mock_storage_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = '{"existing": "data"}'

    utility.set_last_checkpoint("test-bucket", "test_key", "test_value")

    mock_blob.upload_from_string.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_set_last_checkpoint_new_blob(self, mock_log, mock_client):
    """Test set_last_checkpoint with new blob."""
    mock_storage_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False

    utility.set_last_checkpoint("test-bucket", "test_key", "test_value")

    mock_blob.upload_from_string.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_set_last_checkpoint_invalid_json(self, mock_log, mock_client):
    """Test set_last_checkpoint with invalid existing JSON."""
    mock_storage_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "invalid json"

    utility.set_last_checkpoint("test-bucket", "test_key", "test_value")

    mock_blob.upload_from_string.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_set_last_checkpoint_forbidden(self, mock_log, mock_client):
    """Test set_last_checkpoint with forbidden error."""
    mock_storage_client = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.side_effect = utility.exceptions.Forbidden(
        "denied"
    )

    with self.assertRaises(GCPPermissionDeniedError):
      utility.set_last_checkpoint("test-bucket", "test_key", "value")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_set_last_checkpoint_not_found(self, mock_log, mock_client):
    """Test set_last_checkpoint with missing bucket."""
    mock_storage_client = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.side_effect = utility.exceptions.NotFound(
        "missing"
    )

    with self.assertRaises(RuntimeError):
      utility.set_last_checkpoint("test-bucket", "test_key", "value")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_set_last_checkpoint_unknown_error(self, mock_log, mock_client):
    """Test set_last_checkpoint propagates unexpected errors."""
    mock_storage_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_client.return_value = mock_storage_client
    mock_storage_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False
    mock_blob.upload_from_string.side_effect = Exception("failure")

    with self.assertRaises(Exception):
      utility.set_last_checkpoint("test-bucket", "test_key", "value")

  @patch.dict(os.environ, {"CHRONICLE_SERVICE_ACCOUNT": "test@test.com"})
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_check_sufficient_permissions_owner(
      self, mock_log, mock_get_env, mock_requests_get, mock_client_class
  ):
    """Test check_sufficient_permissions_on_service_account with owner role."""
    mock_get_env.return_value = "test_account"
    mock_client_instance = Mock()
    mock_client_class.return_value = mock_client_instance
    mock_policy = Mock()
    mock_policy.bindings = [
        {"role": "roles/owner", "members": ["serviceAccount:test@test.com"]}
    ]
    mock_client_instance.get_iam_policy.return_value = mock_policy

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_check_sufficient_permissions_logs_success(
      self,
      mock_log,
      mock_get_env_var,
      mock_get_environment_variable,
      mock_client_class,
      mock_requests_get,
  ):
    """Test sufficient permissions path logs success message."""
    mock_get_env_var.return_value = None
    mock_get_environment_variable.return_value = "123456789"
    mock_client = Mock()
    mock_client_class.return_value = mock_client
    service_account = "serviceAccount:test@test.com"
    bindings = []
    for role in constant.PERMISSION_DETAILS.values():
      bindings.append(SimpleNamespace(role=role, members=[service_account]))
    mock_policy = Mock()
    mock_policy.bindings = bindings
    mock_client.get_iam_policy.return_value = mock_policy
    mock_response = Mock()
    mock_response.text = "test@test.com"
    mock_requests_get.return_value = mock_response

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)
    mock_log.assert_any_call("Service account has sufficient permissions.")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_check_sufficient_permissions_owner_binding(
      self,
      mock_log,
      mock_get_env_var,
      mock_get_environment_variable,
      mock_client_class,
      mock_requests_get,
  ):
    """Test owner binding short-circuits permission checks."""
    mock_get_env_var.return_value = None
    mock_get_environment_variable.return_value = "123456789"
    mock_client = Mock()
    mock_client_class.return_value = mock_client
    binding = Mock()
    binding.role = "roles/owner"
    binding.members = ["serviceAccount:test@test.com"]
    mock_policy = Mock()
    mock_policy.bindings = [binding]
    mock_client.get_iam_policy.return_value = mock_policy
    mock_response = Mock()
    mock_response.text = "test@test.com"
    mock_requests_get.return_value = mock_response

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_check_sufficient_permissions_metadata_error(
      self,
      mock_log,
      mock_get_env_var,
      mock_get_environment_variable,
      mock_client_class,
      mock_requests_get,
  ):
    """Test metadata failure raises RuntimeError."""
    mock_get_env_var.return_value = None
    mock_get_environment_variable.return_value = "123456789"
    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_policy = Mock()
    mock_policy.bindings = []
    mock_client.get_iam_policy.return_value = mock_policy
    mock_requests_get.side_effect = Exception("metadata")

    with self.assertRaises(RuntimeError):
      utility.check_sufficient_permissions_on_service_account()

  @patch.dict(os.environ, {"CHRONICLE_PROJECT_NUMBER": "123456789"})
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_check_sufficient_permissions_sufficient(
      self, mock_log, mock_get_env, mock_requests_get, mock_client_class
  ):
    """Test sufficient permissions on service account."""
    mock_get_env.side_effect = ["test_account", "123456789"]
    mock_client_instance = Mock()
    mock_client_class.return_value = mock_client_instance
    mock_policy = Mock()
    mock_policy.bindings = [
        {
            "role": "roles/storage.admin",
            "members": ["serviceAccount:test@test.com"],
        },
        {
            "role": "roles/secretmanager.secretAccessor",
            "members": ["serviceAccount:test@test.com"],
        },
    ]
    mock_client_instance.get_iam_policy.return_value = mock_policy
    mock_response = Mock()
    mock_response.text = "test@test.com"
    mock_requests_get.return_value = mock_response

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)

  @patch.dict(os.environ, {"CHRONICLE_PROJECT_NUMBER": "123456789"})
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_check_sufficient_permissions_insufficient(
      self, mock_log, mock_get_env, mock_requests_get, mock_client_class
  ):
    """Test check_sufficient_permissions with insufficient permissions."""
    mock_get_env.side_effect = [
        None,
        "123456789",
    ]  # service_account None, project_number
    mock_client_instance = Mock()
    mock_client_class.return_value = mock_client_instance
    mock_policy = Mock()
    mock_policy.bindings = []
    mock_client_instance.get_iam_policy.return_value = mock_policy
    mock_response = Mock()
    mock_response.text = "test@test.com"
    mock_requests_get.return_value = mock_response

    with self.assertRaises(GCPPermissionDeniedError):
      utility.check_sufficient_permissions_on_service_account()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_check_sufficient_permissions_insufficient_no_sa(
      self,
      mock_log,
      mock_get_env_var,
      mock_get_environment_variable,
      mock_client_class,
      mock_requests_get,
  ):
    """Test insufficient permissions with no service account provided."""
    mock_get_env_var.return_value = ""  # No service account
    mock_get_environment_variable.return_value = "123456789"
    mock_client_instance = Mock()
    mock_client_class.return_value = mock_client_instance
    mock_policy = Mock()
    mock_policy.bindings = []
    mock_client_instance.get_iam_policy.return_value = mock_policy
    mock_response = Mock()
    mock_response.text = "test@test.com"
    mock_requests_get.return_value = mock_response

    with self.assertRaises(GCPPermissionDeniedError):
      utility.check_sufficient_permissions_on_service_account()
    mock_get_env_var.assert_called_once_with(
        utility.env_constants.ENV_CHRONICLE_SERVICE_ACCOUNT, required=False
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_check_sufficient_permissions_static_account(
      self, mock_log, mock_get_env
  ):
    """Test sufficient permissions with static account."""
    mock_get_env.return_value = "static_account"

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch("time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_acquire_process_lock_success(
      self, mock_log, mock_time, mock_set_checkpoint, mock_get_checkpoint
  ):
    """Test acquire_process_lock successful."""
    mock_get_checkpoint.return_value = "false"
    mock_time.return_value = 1000000

    result = utility.acquire_process_lock("test-bucket")

    self.assertTrue(result)
    mock_set_checkpoint.assert_any_call(
        "test-bucket", constant.CHECKPOINT_KEY_PROCESS_LOCK, "true"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_acquire_process_lock_already_running(
      self, mock_log, mock_get_checkpoint
  ):
    """Test acquire_process_lock when already running."""
    mock_get_checkpoint.return_value = "true"

    result = utility.acquire_process_lock("test-bucket")

    self.assertFalse(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch("time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_acquire_process_lock_timeout_reset(
      self, mock_log, mock_time, mock_set_checkpoint, mock_get_checkpoint
  ):
    """Test acquire_process_lock timeout reset."""
    current_time = 1000000
    past_time = current_time - 60 * 60  # 1 hour ago
    mock_get_checkpoint.side_effect = [
        "true",
        str(past_time),
    ]
    mock_time.return_value = current_time

    result = utility.acquire_process_lock("test-bucket")

    self.assertTrue(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch("time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_acquire_process_lock_recent_run(
      self, mock_log, mock_time, mock_get_checkpoint
  ):
    """Test acquire_process_lock returns False when lock still valid."""
    current_time = 1000000
    allowed_minutes = max(1, constant.MAX_EXECUTION_TIME_MINUTES - 1)
    past_time = current_time - allowed_minutes * 60
    mock_get_checkpoint.side_effect = ["true", str(past_time)]
    mock_time.return_value = current_time

    result = utility.acquire_process_lock("test-bucket")

    self.assertFalse(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_acquire_process_lock_missing_timestamp(
      self, mock_log, mock_get_checkpoint
  ):
    """Test acquire_process_lock returns False when timestamp missing."""
    mock_get_checkpoint.side_effect = ["true", None]

    result = utility.acquire_process_lock("test-bucket")

    self.assertFalse(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_acquire_process_lock_invalid_timestamp(
      self, mock_log, mock_get_checkpoint
  ):
    """Test acquire_process_lock handles invalid timestamp format."""
    mock_get_checkpoint.side_effect = ["true", "invalid"]

    result = utility.acquire_process_lock("test-bucket")

    self.assertFalse(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch("time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_acquire_process_lock_set_checkpoint_failure(
      self, mock_log, mock_time, mock_get_checkpoint, mock_set_checkpoint
  ):
    """Test acquire_process_lock propagates errors from set_last_checkpoint."""
    mock_get_checkpoint.return_value = "false"
    mock_time.return_value = 1000000
    mock_set_checkpoint.side_effect = Exception("failure")

    with self.assertRaises(Exception):
      utility.acquire_process_lock("test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_release_process_lock(self, mock_log, mock_set_checkpoint):
    """Test release_process_lock."""
    utility.release_process_lock("test-bucket")

    mock_set_checkpoint.assert_called_once_with(
        "test-bucket", constant.CHECKPOINT_KEY_PROCESS_LOCK, "false"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_release_process_lock_error_logged(
      self, mock_log, mock_set_checkpoint
  ):
    """Test release_process_lock logs when checkpoint update fails."""
    mock_set_checkpoint.side_effect = Exception("failure")

    utility.release_process_lock("test-bucket")

    mock_log.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch("datetime.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_checkpoints_and_config_first_run(
      self, mock_log, mock_datetime, mock_set_checkpoint, mock_get_checkpoint
  ):
    """Test get_checkpoints_and_config first run."""
    mock_get_checkpoint.side_effect = [None, None, None, None, None]
    mock_now = datetime.datetime.now(datetime.timezone.utc)
    mock_datetime.now.return_value = mock_now
    mock_datetime.timezone.utc = datetime.timezone.utc
    mock_datetime.fromisoformat = Mock(
        side_effect=lambda x: datetime.datetime.fromisoformat(
            x.replace("Z", "+00:00")
        )
    )

    _, _, starting_page, _ = utility.get_checkpoints_and_config(
        "test-bucket", 30, "test_query", "test_type"
    )

    self.assertEqual(starting_page, 1)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch("datetime.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_checkpoints_and_config_resume(
      self, mock_log, mock_datetime, mock_set_checkpoint, mock_get_checkpoint
  ):
    """Test get_checkpoints_and_config resume incomplete."""
    mock_get_checkpoint.side_effect = [
        "2023-01-01T00:00:00Z",
        "2023-01-02T00:00:00Z",
        "5",
        None,
        None,
    ]
    mock_now = Mock()
    mock_now.strftime.return_value = "2023-01-01T00:00:00"
    mock_datetime.now.return_value = mock_now

    _, _, starting_page, _ = utility.get_checkpoints_and_config(
        "test-bucket", 30, "test_query", "test_type"
    )

    self.assertEqual(starting_page, 1)  # Since config changed, it resets to 1

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch("datetime.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_checkpoints_and_config_config_changed(
      self, mock_log, mock_datetime, mock_set_checkpoint, mock_get_checkpoint
  ):
    """Test get_checkpoints_and_config when config changed."""
    mock_get_checkpoint.side_effect = [
        "2023-01-01T00:00:00Z",
        "2023-01-02T00:00:00Z",
        "5",
        "old_query",
        "old_type",
    ]
    mock_now = Mock()
    mock_now.strftime.side_effect = [
        "2023-01-01T00:00:00Z",
        "2023-01-01T00:00:00Z",
    ]
    mock_datetime.now.return_value = mock_now
    mock_datetime.timezone.utc = datetime.timezone.utc
    mock_datetime.fromisoformat = Mock(
        return_value=datetime.datetime.now(datetime.timezone.utc)
    )

    _, _, starting_page, _ = utility.get_checkpoints_and_config(
        "test-bucket", 30, "new_query", "new_type"
    )

    self.assertEqual(starting_page, 1)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_checkpoints_and_config_resume_window(
      self, mock_log, mock_set_checkpoint, mock_get_checkpoint
  ):
    """Test get_checkpoints_and_config resumes existing window."""
    mock_get_checkpoint.side_effect = [
        "2023-01-01T00:00:00Z",
        "2023-01-02T00:00:00Z",
        "5",
        "test_query",
        "test_type",
    ]

    since, until, starting_page, params_config = (
        utility.get_checkpoints_and_config(
            "test-bucket", 30, "test_query", "test_type"
        )
    )

    self.assertEqual(since, "2023-01-01T00:00:00Z")
    self.assertEqual(until, "2023-01-02T00:00:00Z")
    self.assertEqual(starting_page, 5)
    self.assertEqual(params_config["query"], "test_query")
    mock_set_checkpoint.assert_not_called()

  @patch("datetime.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_checkpoints_and_config_use_last_until(
      self,
      mock_log,
      mock_set_checkpoint,
      mock_get_checkpoint,
      mock_datetime,
  ):
    """Test get_checkpoints_and_config uses last until timestamp."""
    mock_get_checkpoint.side_effect = [
        None,
        "2023-01-02T00:00:00Z",
        0,
        None,
        None,
    ]
    mock_now = Mock()
    mock_now.strftime.side_effect = [
        "2023-01-03T00:00:00",
        "2023-01-03T00:00:00",
    ]
    mock_datetime.now.return_value = mock_now
    mock_datetime.fromisoformat.side_effect = REAL_DATETIME_CLASS.fromisoformat

    since, _, starting_page, _ = utility.get_checkpoints_and_config(
        "test-bucket", 30, None, None
    )

    self.assertEqual(since, "2023-01-02T00:00:01Z")
    self.assertEqual(starting_page, 1)
    mock_set_checkpoint.assert_called()


if __name__ == "__main__":
  unittest.main()
