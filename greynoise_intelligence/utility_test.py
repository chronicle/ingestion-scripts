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
# pylint: disable=unused-variable
# pylint: disable=g-import-not-at-top
# pylint: disable=g-bad-import-order
# pylint: disable=g-bad-exception-name

"""Unit tests for utility module."""

import unittest
from unittest import mock
import sys


# Create proper exception classes for google.cloud.exceptions
class MockForbidden(Exception):
  """mock.Mock for google.cloud.exceptions.Forbidden."""


class MockNotFound(Exception):
  """Mock for google.cloud.exceptions.NotFound."""


class MockRequestException(Exception):
  """mock.Mock for requests.exceptions.RequestException."""


# Create a proper mock module for google.cloud.exceptions with real classes
class MockGoogleCloudExceptions:
  """Mock module for google.cloud.exceptions."""

  Forbidden = MockForbidden
  NotFound = MockNotFound


class MockRequestsExceptions:
  """Mock module for requests.exceptions."""

  RequestException = MockRequestException


# Create proper mock structure for google modules before importing utility
mock_google = mock.MagicMock()
mock_cloud = mock.MagicMock()
mock_storage = mock.MagicMock()
mock_resourcemanager = mock.MagicMock()
mock_auth = mock.MagicMock()
mock_auth_transport = mock.MagicMock()

mock_google.cloud = mock_cloud
mock_google.auth = mock_auth
mock_auth.transport = mock_auth_transport
mock_auth_transport.requests = mock.MagicMock()
mock_cloud.storage = mock_storage
mock_cloud.resourcemanager_v3 = mock_resourcemanager
# Use the class-based mock for exceptions so they can be caught
mock_cloud.exceptions = MockGoogleCloudExceptions
mock_storage.Client = mock.MagicMock()

sys.modules["google"] = mock_google
sys.modules["google.cloud"] = mock_cloud
sys.modules["google.cloud.storage"] = mock_storage
sys.modules["google.cloud.resourcemanager_v3"] = mock_resourcemanager
sys.modules["google.cloud.exceptions"] = MockGoogleCloudExceptions
sys.modules["google.auth"] = mock_auth
sys.modules["google.auth.transport"] = mock_auth_transport
sys.modules["google.auth.transport.requests"] = mock_auth_transport.requests

# Set up requests mock with proper exception class
mock_requests_module = mock.MagicMock()
mock_requests_module.exceptions = MockRequestsExceptions
mock_requests_module.get = mock.MagicMock()
sys.modules["requests"] = mock_requests_module
sys.modules["requests.exceptions"] = MockRequestsExceptions

import json
import os
import requests
from common import utils
import utility
import constant
from exception_handler import GCPPermissionDeniedError
INGESTION_SCRIPTS_PATH = ""

# Patch the exception classes in utility module so they can be caught
utility.google.cloud.exceptions.Forbidden = MockForbidden
utility.google.cloud.exceptions.NotFound = MockNotFound
utility.requests.exceptions.RequestException = MockRequestException


class TestGetEnvironmentVariable(unittest.TestCase):
  """Test cases for get_environment_variable function."""

  @mock.patch.object(utils, "get_env_var")
  def test_get_non_secret_variable(self, mock_get_env):
    """Test getting a non-secret environment variable."""
    mock_get_env.return_value = "  TEST_VALUE  "
    result = utility.get_environment_variable("TEST_VAR")
    self.assertEqual(result, "test_value")
    mock_get_env.assert_called_once()

  @mock.patch.dict(os.environ, {"SECRET_VAR": "projects/123/secrets/key"})
  @mock.patch.object(utils, "get_value_from_secret_manager")
  def test_get_secret_variable(self, mock_get_secret):
    """Test getting a secret environment variable."""
    mock_get_secret.return_value = "secret_api_key"
    result = utility.get_environment_variable("SECRET_VAR", is_secret=True)
    self.assertEqual(result, "secret_api_key")
    mock_get_secret.assert_called_once_with(
        "projects/123/secrets/key/versions/latest"
    )

  @mock.patch.dict(
      os.environ, {"SECRET_VAR": "projects/123/secrets/key/versions/1"}
  )
  @mock.patch.object(utils, "get_value_from_secret_manager")
  def test_get_secret_with_version(self, mock_get_secret):
    """Test secret path already has version specified."""
    mock_get_secret.return_value = "secret_value"
    result = utility.get_environment_variable("SECRET_VAR", is_secret=True)
    self.assertEqual(result, "secret_value")
    # Should not append /versions/latest
    mock_get_secret.assert_called_once_with(
        "projects/123/secrets/key/versions/1"
    )

  @mock.patch.dict(os.environ, {}, clear=True)
  def test_required_secret_missing(self):
    """Test that missing required secret raises error."""
    with self.assertRaises(RuntimeError) as context:
      utility.get_environment_variable(
          "MISSING_SECRET", is_required=True, is_secret=True
      )
    self.assertIn("required", str(context.exception).lower())

  @mock.patch.object(utils, "get_env_var")
  def test_default_value_used(self, mock_get_env):
    """Test that default value from constant is used."""
    constant.DEFAULT_VALUES["TEST_VAR"] = "default_val"
    mock_get_env.return_value = "default_val"
    result = utility.get_environment_variable("TEST_VAR")
    mock_get_env.assert_called_once()


class TestGetGCSClient(unittest.TestCase):
  """Test cases for _get_gcs_client function."""

  @mock.patch.object(utility.google.cloud.storage, "Client")
  def test_successful_client_creation(self, mock_client):
    """Test successful GCS client creation."""
    mock_instance = mock.Mock(spec=True)
    mock_client.return_value = mock_instance
    result = utility._get_gcs_client()
    self.assertEqual(result, mock_instance)
    mock_client.assert_called_once()

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utility.google.cloud.storage, "Client")
  def test_permission_denied_error(self, mock_client, mock_log):
    """Test GCS client creation with permission denied."""
    mock_client.side_effect = Exception("403 Permission denied")
    with self.assertRaises(GCPPermissionDeniedError):
      utility._get_gcs_client()

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utility.google.cloud.storage, "Client")
  def test_generic_error(self, mock_client, mock_log):
    """Test GCS client creation with generic error."""
    mock_client.side_effect = Exception("Network error")
    with self.assertRaises(Exception) as context:
      utility._get_gcs_client()
    self.assertIn("Failed to initialize GCS client", str(context.exception))


class TestLoadStateFromGCS(unittest.TestCase):
  """Test cases for load_state_from_gcs function."""

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_successful_load(self, mock_get_client, mock_env, mock_log):
    """Test successfully loading state from GCS."""
    mock_env.return_value = "test-bucket"
    mock_client = mock.Mock()
    mock_bucket = mock.Mock()
    mock_blob = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = '{"last_seen": "2024-01-01"}'

    result = utility.load_state_from_gcs("state.json")

    self.assertEqual(result, {"last_seen": "2024-01-01"})
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_called_once()

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_blob_does_not_exist(self, mock_get_client, mock_env, mock_log):
    """Test loading when blob doesn't exist."""
    mock_env.return_value = "test-bucket"
    mock_client = mock.Mock()
    mock_bucket = mock.Mock()
    mock_blob = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False

    result = utility.load_state_from_gcs("state.json")

    self.assertIsNone(result)
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_not_called()

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_empty_content(self, mock_get_client, mock_env, mock_log):
    """Test loading empty content from GCS."""
    mock_env.return_value = "test-bucket"
    mock_client = mock.Mock()
    mock_bucket = mock.Mock()
    mock_blob = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = ""

    result = utility.load_state_from_gcs("state.json")

    self.assertIsNone(result)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_blob_exists_error(self, mock_get_client, mock_env, mock_log):
    """Test error when checking if blob exists (lines 129-134)."""
    mock_env.return_value = "test-bucket"
    mock_client = mock.Mock()
    mock_bucket = mock.Mock()
    mock_blob = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.side_effect = Exception("Timeout checking blob")

    with self.assertRaises(Exception) as ctx:
      utility.load_state_from_gcs("state.json")
    self.assertIn("Failed to check if blob", str(ctx.exception))

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_invalid_json_content(self, mock_get_client, mock_env, mock_log):
    """Test loading invalid JSON content (lines 152-157)."""
    mock_env.return_value = "test-bucket"
    mock_client = mock.Mock()
    mock_bucket = mock.Mock()
    mock_blob = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "not valid json {"

    # JSONDecodeError is caught and re-raised as Exception
    with self.assertRaises(Exception) as ctx:
      utility.load_state_from_gcs("state.json")
    self.assertIn("Invalid JSON", str(ctx.exception))

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_forbidden_exception(self, mock_get_client, mock_env, mock_log):
    """Test Forbidden exception handling (lines 158-170)."""
    mock_env.return_value = "test-bucket"
    # Raise at _get_gcs_client level to trigger outer except
    mock_get_client.side_effect = MockForbidden("Access denied")

    with self.assertRaises(GCPPermissionDeniedError):
      utility.load_state_from_gcs("state.json")

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_not_found_exception(self, mock_get_client, mock_env, mock_log):
    """Test NotFound exception handling (lines 171-174)."""
    mock_env.return_value = "test-bucket"
    # Raise at _get_gcs_client level to trigger outer except
    mock_get_client.side_effect = MockNotFound("Bucket not found")

    with self.assertRaises(RuntimeError) as ctx:
      utility.load_state_from_gcs("state.json")
    self.assertIn("does not exist", str(ctx.exception))

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_generic_exception_outer(self, mock_get_client, mock_env, mock_log):
    """Test generic exception handling (lines 177-180)."""
    mock_env.return_value = "test-bucket"
    # Use a non-Forbidden/NotFound exception to trigger outer except
    mock_get_client.side_effect = ValueError("Unexpected error")

    with self.assertRaises(Exception) as ctx:
      utility.load_state_from_gcs("state.json")
    self.assertIn("Failed to load state from GCS", str(ctx.exception))

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_gcp_permission_denied_reraise(
      self, mock_get_client, mock_env, mock_log
  ):
    """Test GCPPermissionDeniedError re-raise (line 175-176)."""
    mock_env.return_value = "test-bucket"
    # Raise GCPPermissionDeniedError directly from _get_gcs_client
    mock_get_client.side_effect = GCPPermissionDeniedError(
        message="Permission denied", permissions=["Storage Admin"]
    )

    with self.assertRaises(GCPPermissionDeniedError):
      utility.load_state_from_gcs("state.json")


class TestSaveStateToGCS(unittest.TestCase):
  """Test cases for save_state_to_gcs function."""

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_successful_save(self, mock_get_client, mock_env, mock_log):
    """Test successfully saving state to GCS."""
    mock_env.return_value = "test-bucket"
    mock_client = mock.Mock()
    mock_bucket = mock.Mock()
    mock_blob = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob

    state = {"last_seen": "2024-01-01"}
    utility.save_state_to_gcs("state.json", state)

    mock_blob.upload_from_string.assert_called_once()
    call_args = mock_blob.upload_from_string.call_args
    self.assertEqual(json.loads(call_args[0][0]), state)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_json_serialization_error(
      self, mock_get_client, mock_env, mock_log
  ):
    """Test JSON serialization error (lines 204-207)."""
    mock_env.return_value = "test-bucket"
    mock_client = mock.Mock()
    mock_bucket = mock.Mock()
    mock_blob = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob

    # Create an object that can't be serialized to JSON
    class NonSerializable:
      pass

    state = {"obj": NonSerializable()}

    # ValueError is caught and re-raised as Exception
    with self.assertRaises(Exception) as ctx:
      utility.save_state_to_gcs("state.json", state)
    self.assertIn("Failed to serialize state", str(ctx.exception))

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_upload_error(self, mock_get_client, mock_env, mock_log):
    """Test upload error (lines 218-223)."""
    mock_env.return_value = "test-bucket"
    mock_client = mock.Mock()
    mock_bucket = mock.Mock()
    mock_blob = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.upload_from_string.side_effect = Exception("Upload failed")

    with self.assertRaises(Exception) as ctx:
      utility.save_state_to_gcs("state.json", {"key": "value"})
    self.assertIn("Failed to save state to", str(ctx.exception))

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_forbidden_exception(self, mock_get_client, mock_env, mock_log):
    """Test Forbidden exception handling (lines 225-237)."""
    mock_env.return_value = "test-bucket"
    # Forbidden must be raised at outer level to trigger the except
    mock_get_client.side_effect = MockForbidden("Access denied")

    with self.assertRaises(GCPPermissionDeniedError):
      utility.save_state_to_gcs("state.json", {"key": "value"})

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_not_found_exception(self, mock_get_client, mock_env, mock_log):
    """Test NotFound exception handling (lines 238-241)."""
    mock_env.return_value = "test-bucket"
    # NotFound must be raised before upload to trigger the outer except
    mock_get_client.side_effect = MockNotFound("Bucket not found")

    with self.assertRaises(RuntimeError) as ctx:
      utility.save_state_to_gcs("state.json", {"key": "value"})
    self.assertIn("does not exist", str(ctx.exception))

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_generic_exception_outer(self, mock_get_client, mock_env, mock_log):
    """Test generic exception handling (lines 244-247)."""
    mock_env.return_value = "test-bucket"
    # Use a non-Forbidden/NotFound exception to trigger outer except
    mock_get_client.side_effect = ValueError("Unexpected value error")

    with self.assertRaises(Exception) as ctx:
      utility.save_state_to_gcs("state.json", {"key": "value"})
    self.assertIn("Unexpected error", str(ctx.exception))

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(utils, "get_env_var")
  @mock.patch.object(utility, "_get_gcs_client")
  def test_gcp_permission_denied_reraise(
      self, mock_get_client, mock_env, mock_log
  ):
    """Test GCPPermissionDeniedError re-raise (line 242-243)."""
    mock_env.return_value = "test-bucket"
    # Raise GCPPermissionDeniedError directly from _get_gcs_client
    mock_get_client.side_effect = GCPPermissionDeniedError(
        message="Permission denied", permissions=["Storage Admin"]
    )

    with self.assertRaises(GCPPermissionDeniedError):
      utility.save_state_to_gcs("state.json", {"key": "value"})


class TestCheckSufficientPermissions(unittest.TestCase):
  """Test cases for check_sufficient_permissions_on_service_account."""

  @mock.patch("requests.get")
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(
      utility.google.cloud.resourcemanager_v3, "ProjectsClient"
  )
  @mock.patch.object(utils, "cloud_logging")
  def test_all_permissions_present(
      self, mock_log, mock_client_class, mock_get_env, mock_requests
  ):
    """Test when service account has all required permissions."""
    mock_get_env.return_value = "123456"
    mock_response = mock.Mock()
    mock_response.text = "test-sa@project.iam.gserviceaccount.com"
    mock_requests.return_value = mock_response

    mock_client = mock.Mock()
    mock_client_class.return_value = mock_client
    mock_policy = mock.Mock()
    mock_policy.bindings = []

    # Create bindings for all required permissions
    for role in constant.PERMISSION_DETAILS.values():
      binding = mock.Mock()
      binding.role = role
      binding.members = [
          "serviceAccount:test-sa@project.iam.gserviceaccount.com"
      ]
      mock_policy.bindings.append(binding)

    mock_client.get_iam_policy.return_value = mock_policy

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)
    mock_client.get_iam_policy.assert_called_once()

  @mock.patch("requests.get")
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(
      utility.google.cloud.resourcemanager_v3, "ProjectsClient"
  )
  @mock.patch.object(utils, "cloud_logging")
  def test_metadata_server_error(
      self, mock_log, mock_client_class, mock_get_env, mock_requests
  ):
    """Test metadata server request error (lines 285-291)."""
    mock_get_env.return_value = "123456"
    mock_client = mock.Mock()
    mock_client_class.return_value = mock_client
    mock_policy = mock.Mock()
    mock_policy.bindings = []
    mock_client.get_iam_policy.return_value = mock_policy

    # Simulate metadata server error using our mock exception
    mock_requests.side_effect = MockRequestException("Connection refused")

    with self.assertRaises(Exception) as ctx:
      utility.check_sufficient_permissions_on_service_account()
    self.assertIn("Failed to retrieve service account", str(ctx.exception))

  @mock.patch.object(requests, "get")
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(
      utility.google.cloud.resourcemanager_v3, "ProjectsClient"
  )
  @mock.patch.object(utils, "cloud_logging")
  def test_missing_permissions(
      self, mock_log, mock_client_class, mock_get_env, mock_requests
  ):
    """Test when service account has missing permissions (lines 298-308)."""
    mock_get_env.return_value = "123456"
    mock_response = mock.Mock()
    mock_response.text = "test-sa@project.iam.gserviceaccount.com"
    mock_requests.return_value = mock_response

    mock_client = mock.Mock()
    mock_client_class.return_value = mock_client
    mock_policy = mock.Mock()
    # Empty bindings - no permissions
    mock_policy.bindings = []
    mock_client.get_iam_policy.return_value = mock_policy

    # The GCPPermissionDeniedError is caught and re-raised as Exception
    with self.assertRaises(Exception) as ctx:
      utility.check_sufficient_permissions_on_service_account()
    self.assertIn("does not have sufficient", str(ctx.exception))

  @mock.patch.object(requests, "get")
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(
      utility.google.cloud.resourcemanager_v3, "ProjectsClient"
  )
  @mock.patch.object(utils, "cloud_logging")
  def test_generic_exception(
      self, mock_log, mock_client_class, mock_get_env, mock_requests
  ):
    """Test generic exception handling (lines 312-314)."""
    mock_get_env.return_value = "123456"
    mock_client_class.side_effect = Exception("API error")

    with self.assertRaises(Exception) as ctx:
      utility.check_sufficient_permissions_on_service_account()
    self.assertIn("Unexpected error", str(ctx.exception))

  @mock.patch("requests.get")
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(
      utility.google.cloud.resourcemanager_v3, "ProjectsClient"
  )
  @mock.patch.object(utils, "cloud_logging")
  def test_service_account_has_owner_role(
      self, mock_log, mock_client_class, mock_get_env, mock_requests
  ):
    """Test when service account has roles/owner (lines 308-311)."""
    mock_get_env.return_value = "123456"
    mock_response = mock.Mock()
    mock_response.text = "test-sa@project.iam.gserviceaccount.com"
    mock_requests.return_value = mock_response

    mock_client = mock.Mock()
    mock_client_class.return_value = mock_client
    mock_policy = mock.Mock()
    mock_policy.bindings = []

    binding = mock.Mock()
    binding.role = "roles/owner"
    binding.members = [
        "serviceAccount:test-sa@project.iam.gserviceaccount.com"
    ]
    mock_policy.bindings.append(binding)

    mock_client.get_iam_policy.return_value = mock_policy

    result = utility.check_sufficient_permissions_on_service_account()

    self.assertTrue(result)
    mock_log.assert_any_call(
        "Service account has roles/owner, which includes all necessary permissions."
    )


if __name__ == "__main__":
  unittest.main()
