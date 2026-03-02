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
# pylint: disable=g-docstring-first-line-too-long

"""Unit tests for utility module."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import json


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

# Mock common modules
mock_common = MagicMock()
mock_utils = MagicMock()
mock_env_constants = MagicMock()
mock_common.utils = mock_utils
mock_common.env_constants = mock_env_constants
# Provide concrete values for env constant attributes used in tests.
mock_env_constants.ENV_CHRONICLE_SERVICE_ACCOUNT = (
    "ENV_CHRONICLE_SERVICE_ACCOUNT"
)
mock_env_constants.ENV_CHRONICLE_PROJECT_NUMBER = "ENV_CHRONICLE_PROJECT_NUMBER"
INGESTION_SCRIPTS_PATH = ""
sys.modules["common"] = mock_common
sys.modules["common.utils"] = mock_utils
sys.modules["common.env_constants"] = mock_env_constants

# Mock requests
mock_requests = MagicMock()
sys.modules["requests"] = mock_requests

import utility  # noqa: E402
import constant  # noqa: E402
from exception_handler import (  # noqa: E402
    GCPPermissionDeniedError,
    CywareCTIXException,
)

# Patch the exception classes in utility module so they can be caught
utility.exceptions.Forbidden = MockForbidden
utility.exceptions.NotFound = MockNotFound


class TestGetEnvironmentVariable(unittest.TestCase):
  """Test cases for get_environment_variable function."""

  def _make_env_fetch_validator(
      self, expected_default, *, expected_required=False
  ):
    def validate(name, *, required=True, is_secret=False, default=""):
      self.assertEqual(default, expected_default)
      self.assertEqual(required, expected_required)
      self.assertFalse(is_secret)
      return "  TEST_VALUE  "

    return validate

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_non_secret_variable(self, mock_get_env):
    """Test getting a non-secret environment variable."""
    mock_get_env.side_effect = self._make_env_fetch_validator("")
    result = utility.get_environment_variable("TEST_VAR")
    self.assertEqual(result, "test_value")
    mock_get_env.assert_called_once()

  @patch.dict(os.environ, {"SECRET_VAR": "projects/123/secrets/key"})
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_value_from_secret_manager")
  def test_get_secret_variable(self, mock_get_secret):
    """Test getting a secret environment variable."""
    mock_get_secret.return_value = "secret_api_key"
    result = utility.get_environment_variable("SECRET_VAR", is_secret=True)
    self.assertEqual(result, "secret_api_key")
    mock_get_secret.assert_called_once_with(
        "projects/123/secrets/key/versions/latest"
    )

  @patch.dict(os.environ, {"SECRET_VAR": "projects/123/secrets/key/versions/1"})
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_value_from_secret_manager")
  def test_get_secret_with_version(self, mock_get_secret):
    """Test secret path already has version specified."""
    mock_get_secret.return_value = "secret_value"
    result = utility.get_environment_variable("SECRET_VAR", is_secret=True)
    self.assertEqual(result, "secret_value")
    mock_get_secret.assert_called_once_with(
        "projects/123/secrets/key/versions/1"
    )

  @patch.dict(os.environ, {}, clear=True)
  def test_required_secret_missing(self):
    """Test that missing required secret raises error."""
    with self.assertRaises(RuntimeError) as context:
      utility.get_environment_variable(
          "MISSING_SECRET", is_required=True, is_secret=True
      )
    self.assertIn("required", str(context.exception).lower())

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_default_value_used(self, mock_get_env):
    """Test that default value from constant is used."""
    constant.DEFAULT_VALUES = {constant.ENV_ENRICHMENT_ENABLED: "false"}
    mock_get_env.side_effect = self._make_env_fetch_validator("false")
    _ = utility.get_environment_variable(constant.ENV_ENRICHMENT_ENABLED)
    mock_get_env.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_lowercase_conversion(self, mock_get_env):
    """Test that non-secret values are converted to lowercase."""
    mock_get_env.return_value = "  UPPERCASE  "
    result = utility.get_environment_variable("TEST_VAR")
    self.assertEqual(result, "uppercase")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_label_name_not_lowercased(self, mock_get_env):
    """Test label env variable keeps original casing/spaces."""
    mock_get_env.return_value = "  MixedCase Label  "
    result = utility.get_environment_variable(constant.ENV_LABEL_NAME)
    self.assertEqual(result, "MixedCase Label")
    mock_get_env.assert_called_once()


class TestParseBooleanEnv(unittest.TestCase):
  """Test cases for parse_boolean_env function."""

  def test_parse_true_string(self):
    """Test parsing 'true' string."""
    self.assertTrue(utility.parse_boolean_env("true"))

  def test_parse_false_string(self):
    """Test parsing 'false' string."""
    self.assertFalse(utility.parse_boolean_env("false"))

  def test_parse_uppercase_true(self):
    """Test parsing uppercase TRUE."""
    self.assertTrue(utility.parse_boolean_env("TRUE"))

  def test_parse_empty_string(self):
    """Test parsing empty string."""
    self.assertFalse(utility.parse_boolean_env(""))

  def test_parse_none(self):
    """Test parsing None."""
    self.assertFalse(utility.parse_boolean_env(None))


class TestValidateIntegerEnv(unittest.TestCase):
  """Test cases for validate_integer_env function."""

  def test_valid_integer_string(self):
    """Test with valid integer string."""
    result = utility.validate_integer_env("30", "test_param")
    self.assertEqual(result, 30)

  def test_valid_integer(self):
    """Test with valid integer."""
    result = utility.validate_integer_env(30, "test_param")
    self.assertEqual(result, 30)

  def test_none_with_default(self):
    """Test None value with default."""
    result = utility.validate_integer_env(None, "test_param", "15")
    self.assertEqual(result, 15)

  def test_none_without_default(self):
    """Test None value without default."""
    result = utility.validate_integer_env(None, "test_param", None)
    self.assertIsNone(result)

  def test_invalid_string(self):
    """Test with invalid string."""
    with self.assertRaises(CywareCTIXException) as context:
      utility.validate_integer_env("abc", "test_param")
    self.assertIn("must be an integer", str(context.exception))

  def test_negative_integer(self):
    """Test with negative integer."""
    with self.assertRaises(CywareCTIXException) as context:
      utility.validate_integer_env(-5, "test_param")
    self.assertIn("non-negative", str(context.exception))

  def test_zero_integer(self):
    """Test with zero integer."""
    with self.assertRaises(CywareCTIXException) as context:
      utility.validate_integer_env(0, "test_param")
    self.assertIn("greater than zero", str(context.exception))


class TestGetTenantCheckpointKey(unittest.TestCase):
  """Test cases for get_tenant_checkpoint_key function."""

  def test_simple_tenant_name(self):
    """Test with simple tenant name."""
    result = utility.get_tenant_checkpoint_key("tenant1", "last_timestamp")
    self.assertEqual(result, "tenant1_last_timestamp")

  def test_tenant_name_with_special_chars(self):
    """Test with tenant name containing special characters."""
    result = utility.get_tenant_checkpoint_key("tenant@#$1", "last_timestamp")
    self.assertEqual(result, "tenant___1_last_timestamp")

  def test_tenant_name_with_spaces(self):
    """Test with tenant name containing spaces."""
    result = utility.get_tenant_checkpoint_key("my tenant", "key")
    self.assertEqual(result, "my_tenant_key")


class TestGetLastCheckpoint(unittest.TestCase):
  """Test cases for get_last_checkpoint function."""

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_successful_load(self, mock_storage_client, mock_log):
    """Test successfully loading checkpoint from GCS."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = (
        '{"tenant1_last_timestamp": "1234567890"}'
    )

    result = utility.get_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp"
    )

    self.assertEqual(result, "1234567890")
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_blob_does_not_exist(self, mock_storage_client, mock_log):
    """Test loading when blob doesn't exist."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False

    result = utility.get_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp"
    )

    self.assertIsNone(result)
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_key_not_in_checkpoint(self, mock_storage_client, mock_log):
    """Test when checkpoint key doesn't exist in file."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = '{"other_key": "value"}'

    result = utility.get_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp"
    )

    self.assertIsNone(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_invalid_json_content(self, mock_storage_client, mock_log):
    """Test loading invalid JSON content."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "not valid json {"

    result = utility.get_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp"
    )

    self.assertIsNone(result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_forbidden_exception(self, mock_storage_client, mock_log):
    """Test Forbidden exception handling."""
    mock_client = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.side_effect = MockForbidden("Access denied")

    with self.assertRaises(GCPPermissionDeniedError):
      utility.get_last_checkpoint("tenant1", "test-bucket", "last_timestamp")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_not_found_exception(self, mock_storage_client, mock_log):
    """Test NotFound exception handling."""
    mock_client = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.side_effect = MockNotFound("Bucket not found")

    with self.assertRaises(RuntimeError) as ctx:
      utility.get_last_checkpoint("tenant1", "test-bucket", "last_timestamp")
    self.assertIn("does not exist", str(ctx.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_generic_exception(self, mock_storage_client, mock_log):
    """Test generic exception handling."""
    mock_client = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.side_effect = ValueError("Unexpected error")

    result = utility.get_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp"
    )
    self.assertIsNone(result)


class TestSetLastCheckpoint(unittest.TestCase):
  """Test cases for set_last_checkpoint function."""

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_successful_save_new_file(self, mock_storage_client, mock_log):
    """Test successfully saving checkpoint to new GCS file."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False

    result = utility.set_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp", "1234567890"
    )

    self.assertIsNone(result)
    mock_blob.upload_from_string.assert_called_once()
    call_args = mock_blob.upload_from_string.call_args
    uploaded_data = json.loads(call_args[0][0])
    self.assertEqual(uploaded_data["tenant1_last_timestamp"], "1234567890")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_successful_save_existing_file(self, mock_storage_client, mock_log):
    """Test successfully updating checkpoint in existing GCS file."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = '{"other_tenant_key": "value"}'

    result = utility.set_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp", "1234567890"
    )

    self.assertIsNone(result)
    mock_blob.upload_from_string.assert_called_once()
    call_args = mock_blob.upload_from_string.call_args
    uploaded_data = json.loads(call_args[0][0])
    self.assertEqual(uploaded_data["tenant1_last_timestamp"], "1234567890")
    self.assertEqual(uploaded_data["other_tenant_key"], "value")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_existing_file_invalid_json(self, mock_storage_client, mock_log):
    """Test when existing file has invalid JSON."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "invalid json"

    result = utility.set_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp", "1234567890"
    )

    self.assertIsNone(result)
    mock_blob.upload_from_string.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_forbidden_exception(self, mock_storage_client, mock_log):
    """Test Forbidden exception handling."""
    mock_client = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.side_effect = MockForbidden("Access denied")

    with self.assertRaises(GCPPermissionDeniedError):
      utility.set_last_checkpoint(
          "tenant1", "test-bucket", "last_timestamp", "1234567890"
      )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_not_found_exception(self, mock_storage_client, mock_log):
    """Test NotFound exception handling."""
    mock_client = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.side_effect = MockNotFound("Bucket not found")

    with self.assertRaises(RuntimeError) as ctx:
      utility.set_last_checkpoint(
          "tenant1", "test-bucket", "last_timestamp", "1234567890"
      )
    self.assertIn("does not exist", str(ctx.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_generic_exception_logs_and_re_raises(
      self, mock_storage_client, mock_log
  ):
    """Ensure unexpected errors are logged and propagated."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False
    mock_blob.upload_from_string.side_effect = ValueError("boom")

    with self.assertRaisesRegex(ValueError, "boom"):
      utility.set_last_checkpoint(
          "tenant1", "test-bucket", "last_timestamp", "value"
      )

    log_messages = [str(call.args[0]) for call in mock_log.call_args_list]
    self.assertTrue(
        any("Error updating checkpoint" in message for message in log_messages)
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_skip_when_service_account_present(self, mock_log, mock_get_env):
    """Should skip IAM check when static service account key provided."""
    mock_get_env.return_value = "service-account-json"
    result = utility.check_sufficient_permissions_on_service_account()
    # Function returns True when service account is provided
    self.assertTrue(result)
    mock_log.assert_called()
    # Verify get_env_var was called (constant value may vary)
    self.assertTrue(mock_get_env.called)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_service_account_env_var_uses_required_false(
      self, mock_log, mock_get_env
  ):
    """Verify that ENV_CHRONICLE_SERVICE_ACCOUNT is fetched with required=False."""
    mock_get_env.return_value = ""

    with patch(
        f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
    ) as mock_client_class:
      mock_client_class.side_effect = Exception("Should not reach IAM check")

      with self.assertRaises(Exception):
        utility.check_sufficient_permissions_on_service_account()

      # Verify get_env_var was called with required=False
      mock_get_env.assert_called_once_with(
          mock_env_constants.ENV_CHRONICLE_SERVICE_ACCOUNT, required=False
      )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_owner_role_short_circuits_permission_check(
      self,
      mock_log,
      mock_get_env,
      mock_client_class,
      mock_get_env_var,
      mock_requests,
  ):
    """Service account with roles/owner should bypass detailed checks."""
    mock_get_env.return_value = ""
    mock_get_env_var.return_value = "123456"
    mock_response = Mock()
    mock_response.text = "owner-sa@project.iam.gserviceaccount.com"
    mock_requests.return_value = mock_response

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_policy = Mock()
    owner_binding = Mock()
    owner_binding.role = "roles/owner"
    owner_binding.members = [
        "serviceAccount:owner-sa@project.iam.gserviceaccount.com"
    ]
    mock_policy.bindings = [owner_binding]
    mock_client.get_iam_policy.return_value = mock_policy

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)
    log_calls = [str(call) for call in mock_log.call_args_list]
    self.assertTrue(any("roles/owner" in call for call in log_calls))
    self.assertTrue(mock_get_env.called)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_all_permissions_present(
      self,
      mock_log,
      mock_get_env,
      mock_client_class,
      mock_get_env_var,
      mock_requests,
  ):
    """Test when service account has all required permissions."""
    mock_get_env.return_value = ""
    mock_get_env_var.return_value = "123456"
    mock_response = Mock()
    mock_response.text = "test-sa@project.iam.gserviceaccount.com"
    mock_requests.return_value = mock_response

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_policy = Mock()
    mock_policy.bindings = []

    for role in constant.PERMISSION_DETAILS.values():
      binding = Mock()
      binding.role = role
      binding.members = [
          "serviceAccount:test-sa@project.iam.gserviceaccount.com"
      ]
      mock_policy.bindings.append(binding)

    mock_client.get_iam_policy.return_value = mock_policy

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)
    mock_client.get_iam_policy.assert_called_once()
    # Verify get_env_var was called (constant value may vary)
    self.assertTrue(mock_get_env.called)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.requests.get")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_missing_permissions(
      self,
      mock_log,
      mock_get_env,
      mock_client_class,
      mock_get_env_var,
      mock_requests,
  ):
    """Test when service account has missing permissions."""
    mock_get_env.return_value = ""
    mock_get_env_var.return_value = "123456"
    mock_response = Mock()
    mock_response.text = "test-sa@project.iam.gserviceaccount.com"
    mock_requests.return_value = mock_response

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_policy = Mock()
    mock_policy.bindings = []
    mock_client.get_iam_policy.return_value = mock_policy

    with self.assertRaises(GCPPermissionDeniedError):
      utility.check_sufficient_permissions_on_service_account()

    # Verify get_env_var was called (constant value may vary)
    self.assertTrue(mock_get_env.called)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.google.cloud.resourcemanager_v3.ProjectsClient"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_generic_exception_logs_and_raises(
      self,
      mock_log,
      mock_get_env,
      mock_client_class,
  ):
    """Test generic exception handling when IAM call fails."""
    mock_get_env.return_value = ""
    mock_client_class.side_effect = Exception("API error")

    with self.assertRaises(RuntimeError):
      utility.check_sufficient_permissions_on_service_account()

    # Verify get_env_var was called (constant value may vary)
    self.assertTrue(mock_get_env.called)
    mock_log.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_release_lock_success(self, mock_log, mock_set):
    """Test successfully releasing lock."""
    utility.release_process_lock("tenant1", "test-bucket")

    mock_set.assert_called_once()
    args, _ = mock_set.call_args
    self.assertEqual(args[0], "tenant1")
    self.assertEqual(args[1], "test-bucket")
    self.assertEqual(args[2], constant.CHECKPOINT_KEY_PROCESS_LOCK)
    self.assertEqual(args[3], "false")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_release_lock_failure_logs_error(self, mock_log, mock_set):
    """Test that lock release failure is logged."""
    mock_set.side_effect = RuntimeError("GCS error")

    utility.release_process_lock("tenant1", "test-bucket")

    log_calls = [str(call) for call in mock_log.call_args_list]
    has_error = any("Failed to release" in str(call) for call in log_calls)
    self.assertTrue(has_error)


class TestClearCheckpointIfExists(unittest.TestCase):
  """Test cases for clear_checkpoint_if_exists function."""

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_clear_checkpoint_exists(self, mock_log, mock_get, mock_set):
    """Test clearing existing checkpoint."""
    mock_get.return_value = "some_value"

    utility.clear_checkpoint_if_exists(
        "test_key", "test_name", "tenant1", "test-bucket"
    )

    mock_set.assert_called_once_with(
        "tenant1", "test-bucket", "test_key", None)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_clear_checkpoint_does_not_exist(self, mock_log, mock_get, mock_set):
    """Test when checkpoint doesn't exist."""
    mock_get.return_value = None

    utility.clear_checkpoint_if_exists(
        "test_key", "test_name", "tenant1", "test-bucket"
    )

    mock_set.assert_not_called()


class TestValidateIntegerEnvEdgeCases(unittest.TestCase):
  """Test cases for validate_integer_env edge cases."""

  def test_validate_large_integer(self):
    """Test with very large integer."""
    result = utility.validate_integer_env("9999999999", "test_param")
    self.assertEqual(result, 9999999999)

  def test_validate_integer_one(self):
    """Test with integer value of 1 (boundary)."""
    result = utility.validate_integer_env(1, "test_param")
    self.assertEqual(result, 1)

  def test_validate_string_with_trailing_space(self):
    """Test with string containing trailing space - will convert successfully."""
    result = utility.validate_integer_env("30 ", "test_param")
    # Python's int() function strips whitespace, so "30 " converts to 30
    self.assertEqual(result, 30)


class TestGetTenantCheckpointKeyEdgeCases(unittest.TestCase):
  """Test cases for get_tenant_checkpoint_key edge cases."""

  def test_tenant_with_dots(self):
    """Test tenant name with dots."""
    result = utility.get_tenant_checkpoint_key("tenant.example.com", "key")
    self.assertEqual(result, "tenant_example_com_key")

  def test_tenant_with_slashes(self):
    """Test tenant name with slashes."""
    result = utility.get_tenant_checkpoint_key("tenant/sub", "key")
    self.assertEqual(result, "tenant_sub_key")

  def test_empty_tenant_name(self):
    """Test with empty tenant name."""
    result = utility.get_tenant_checkpoint_key("", "key")
    self.assertEqual(result, "_key")


class TestSetLastCheckpointEdgeCases(unittest.TestCase):
  """Test cases for set_last_checkpoint edge cases."""

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_set_checkpoint_with_none_value(self, mock_storage_client, mock_log):
    """Test setting checkpoint with None value."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False

    result = utility.set_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp", None
    )

    self.assertIsNone(result)
    call_args = mock_blob.upload_from_string.call_args
    uploaded_data = json.loads(call_args[0][0])
    self.assertIsNone(uploaded_data["tenant1_last_timestamp"])

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_set_checkpoint_preserves_other_tenants(
      self, mock_storage_client, mock_log
  ):
    """Test that setting checkpoint preserves other tenants' data."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_storage_client.return_value = mock_client
    mock_client.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = json.dumps(
        {"tenant2_last_timestamp": "9999999", "tenant3_other_key": "data"}
    )

    utility.set_last_checkpoint(
        "tenant1", "test-bucket", "last_timestamp", "1234567890"
    )

    call_args = mock_blob.upload_from_string.call_args
    uploaded_data = json.loads(call_args[0][0])

    self.assertEqual(uploaded_data["tenant1_last_timestamp"], "1234567890")
    self.assertEqual(uploaded_data["tenant2_last_timestamp"], "9999999")
    self.assertEqual(uploaded_data["tenant3_other_key"], "data")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_lowercase_conversion(self, mock_get_env):
    """Test that non-secret, non-label, non-tenant env vars are lowercased."""
    mock_get_env.return_value = "UPPERCASE_VALUE"
    result = utility.get_environment_variable("SOME_VAR")
    self.assertEqual(result, "uppercase_value")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_label_name_with_escapes(self, mock_get_env):
    """Test label name with escaped characters - covers line 61."""
    mock_get_env.return_value = "label\\\\with\\'escapes"
    result = utility.get_environment_variable(constant.ENV_LABEL_NAME)
    # The function should process the label name
    self.assertIsNotNone(result)

  def test_validate_integer_env_zero_value(self):
    """Test validate_integer_env raises error for zero value."""
    with self.assertRaises(CywareCTIXException) as context:
      utility.validate_integer_env(0, "test_param")
    self.assertIn("must be greater than zero", str(context.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.storage.Client")
  def test_get_last_checkpoint_blob_not_exists(self, mock_storage_client):
    """Test get_last_checkpoint when blob does not exist."""
    mock_client = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()
    mock_blob.exists.return_value = False
    mock_bucket.blob.return_value = mock_blob
    mock_client.bucket.return_value = mock_bucket
    mock_storage_client.return_value = mock_client

    result = utility.get_last_checkpoint("tenant", "bucket", "key")
    self.assertIsNone(result)


class TestAcquireProcessLock(unittest.TestCase):
  """Tests for acquire_process_lock control flow."""

  def _setup_time(self, mock_time, current_time=5000.0):
    mock_time.return_value = current_time
    return current_time

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.time.time")
  def test_acquire_lock_when_available(
      self, mock_time, mock_get_checkpoint, mock_set_checkpoint, mock_log
  ):
    current_time = self._setup_time(mock_time, 2000.0)
    mock_get_checkpoint.return_value = None

    result = utility.acquire_process_lock("tenant", "bucket")

    self.assertTrue(result)
    self.assertEqual(mock_set_checkpoint.call_count, 2)
    mock_set_checkpoint.assert_any_call(
        "tenant", "bucket", constant.CHECKPOINT_KEY_PROCESS_LOCK, "true"
    )
    mock_set_checkpoint.assert_any_call(
        "tenant",
        "bucket",
        constant.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
        current_time,
    )
    mock_log.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.time.time")
  def test_acquire_lock_resets_stuck_lock(
      self, mock_time, mock_get_checkpoint, mock_set_checkpoint, mock_log
  ):
    current_time = self._setup_time(mock_time, 6000.0)
    stale_time = current_time - (constant.MAX_EXECUTION_TIME_MINUTES + 1) * 60
    mock_get_checkpoint.side_effect = ["true", str(stale_time)]

    result = utility.acquire_process_lock("tenant", "bucket")

    self.assertTrue(result)
    self.assertEqual(mock_set_checkpoint.call_count, 2)
    mock_set_checkpoint.assert_any_call(
        "tenant", "bucket", constant.CHECKPOINT_KEY_PROCESS_LOCK, "true"
    )
    mock_set_checkpoint.assert_any_call(
        "tenant",
        "bucket",
        constant.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
        current_time,
    )
    warning_messages = [str(call.args[0]) for call in mock_log.call_args_list]
    self.assertTrue(
        any("exceeds the limit" in message for message in warning_messages)
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.time.time")
  def test_acquire_lock_recent_run_returns_false(
      self, mock_time, mock_get_checkpoint, mock_set_checkpoint, mock_log
  ):
    current_time = self._setup_time(mock_time, 4000.0)
    recent_time = current_time - (constant.MAX_EXECUTION_TIME_MINUTES - 1) * 60
    mock_get_checkpoint.side_effect = ["true", str(recent_time)]

    result = utility.acquire_process_lock("tenant", "bucket")

    self.assertFalse(result)
    mock_set_checkpoint.assert_not_called()
    warning_messages = [str(call.args[0]) for call in mock_log.call_args_list]
    self.assertTrue(
        any(
            "Another process is already running" in msg
            for msg in warning_messages
        )
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.time.time")
  def test_acquire_lock_invalid_timestamp_returns_false(
      self, mock_time, mock_get_checkpoint, mock_set_checkpoint, mock_log
  ):
    self._setup_time(mock_time, 7000.0)
    mock_get_checkpoint.side_effect = ["true", "not-a-number"]

    result = utility.acquire_process_lock("tenant", "bucket")

    self.assertFalse(result)
    mock_set_checkpoint.assert_not_called()
    warning_messages = [str(call.args[0]) for call in mock_log.call_args_list]
    self.assertTrue(
        any(
            "Invalid last_run_initiation_time" in msg
            for msg in warning_messages
        )
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.time.time")
  def test_acquire_lock_missing_last_run_returns_false(
      self, mock_time, mock_get_checkpoint, mock_set_checkpoint, mock_log
  ):
    self._setup_time(mock_time, 8000.0)
    mock_get_checkpoint.side_effect = ["true", None]

    result = utility.acquire_process_lock("tenant", "bucket")

    self.assertFalse(result)
    mock_set_checkpoint.assert_not_called()
    warning_messages = [str(call.args[0]) for call in mock_log.call_args_list]
    self.assertTrue(
        any("Lock status: true" in msg for msg in warning_messages))

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.time.time")
  def test_acquire_lock_propagates_unexpected_errors(
      self, mock_time, mock_get_checkpoint, mock_set_checkpoint, mock_log
  ):
    _ = self._setup_time(mock_time, 9000.0)
    mock_get_checkpoint.return_value = None
    mock_set_checkpoint.side_effect = RuntimeError("failure")

    with self.assertRaises(RuntimeError):
      utility.acquire_process_lock("tenant", "bucket")

    error_messages = [str(call.args[0]) for call in mock_log.call_args_list]
    self.assertTrue(
        any("Failed to acquire process lock" in msg for msg in error_messages)
    )
    mock_set_checkpoint.assert_called_once_with(
        "tenant", "bucket", constant.CHECKPOINT_KEY_PROCESS_LOCK, "true"
    )


if __name__ == "__main__":
  unittest.main()
