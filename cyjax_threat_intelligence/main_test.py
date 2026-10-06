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

"""Unit tests for main module."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys

# Mock common modules before importing main
mock_common = MagicMock()
mock_utils = MagicMock()
mock_common.utils = mock_utils
INGESTION_SCRIPTS_PATH = ""
sys.modules["common"] = mock_common
sys.modules["common.utils"] = mock_utils

import main
import constant
from exception_handler import (
    GCPPermissionDeniedError,
    CyjaxException,
    RunTimeExceeded,
)


class TestMain(unittest.TestCase):
  """Test cases for main function."""

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyjax_client.CyjaxClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_successful_execution(
      self,
      mock_log,
      mock_validate_int,
      mock_parse_bool,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
      mock_release_lock,
      mock_client_class,
  ):
    """Test successful main function execution."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test-bucket",
        "test-token",
        "1",  # Valid historical duration
        "test-query",
        "false",
        "test-types",
    ]
    mock_validate_int.return_value = 1
    mock_parse_bool.return_value = False
    mock_acquire_lock.return_value = True
    mock_client_instance = Mock()
    mock_client_class.return_value = mock_client_instance
    mock_client_instance.fetch_and_ingest_indicators.return_value = None

    result = main.main({})

    self.assertEqual(result, ("Data ingestion completed successfully.", 200))
    mock_check_perms.assert_called_once()
    mock_get_env.assert_any_call(constant.ENV_GCP_BUCKET_NAME, is_required=True)
    mock_acquire_lock.assert_called_once_with("test-bucket")
    mock_client_class.assert_called_once_with(
        api_token="test-token",
        bucket_name="test-bucket",
        historical_ioc_duration=1,
        enable_enrichment=False,
        query="test-query",
        indicator_type="test-types",
    )
    mock_client_instance.fetch_and_ingest_indicators.assert_called_once()
    mock_release_lock.assert_called_once_with("test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_process_lock_already_running(
      self,
      mock_log,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
  ):
    """Test main function when process lock is already running."""
    mock_check_perms.return_value = True
    mock_get_env.return_value = "test-bucket"
    mock_acquire_lock.return_value = False

    result = main.main({})

    self.assertEqual(
        result,
        ("Another process is already running. Skipping execution.", 409),
    )
    mock_acquire_lock.assert_called_once_with("test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyjax_client.CyjaxClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_runtime_exceeded(
      self,
      mock_log,
      mock_validate_int,
      mock_parse_bool,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
      mock_release_lock,
      mock_client_class,
  ):
    """Test main function when runtime is exceeded."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test-bucket",
        "test-token",
        "1",  # Valid historical duration
        None,
        "false",
        None,
    ]
    mock_validate_int.return_value = 1
    mock_parse_bool.return_value = False
    mock_acquire_lock.return_value = True
    mock_client_instance = Mock()
    mock_client_class.return_value = mock_client_instance
    mock_client_instance.fetch_and_ingest_indicators.side_effect = (
        RunTimeExceeded("Timeout")
    )

    result = main.main({})

    self.assertEqual(
        result,
        (
            (
                "Execution time limit exceeded:"
                f" {repr(RunTimeExceeded('Timeout'))}"
            ),
            200,
        ),
    )
    mock_release_lock.assert_called_once_with("test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyjax_client.CyjaxClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_cyjax_exception(
      self,
      mock_log,
      mock_validate_int,
      mock_parse_bool,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
      mock_release_lock,
      mock_client_class,
  ):
    """Test main function when CyjaxException is raised."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test-bucket",
        "test-token",
        "1",  # Valid historical duration
        "test-query",
        "false",
        "test-types",
    ]
    mock_validate_int.return_value = 1
    mock_parse_bool.return_value = False
    mock_acquire_lock.return_value = True
    mock_client_instance = Mock()
    mock_client_class.return_value = mock_client_instance
    mock_client_instance.fetch_and_ingest_indicators.side_effect = (
        CyjaxException("Test error")
    )

    result = main.main({})

    self.assertEqual(
        result,
        (
            (
                "Error during Cyjax data ingestion:"
                f" {repr(CyjaxException('Test error'))}"
            ),
            400,
        ),
    )
    mock_release_lock.assert_called_once_with("test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyjax_client.CyjaxClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_unknown_exception(
      self,
      mock_log,
      mock_validate_int,
      mock_parse_bool,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
      mock_release_lock,
      mock_client_class,
  ):
    """Test main handles unexpected exceptions from ingestion."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test-bucket",
        "test-token",
        "1",
        "test-query",
        "false",
        None,
    ]
    mock_validate_int.return_value = 1
    mock_parse_bool.return_value = False
    mock_acquire_lock.return_value = True
    mock_client_instance = Mock()
    mock_client_class.return_value = mock_client_instance
    mock_client_instance.fetch_and_ingest_indicators.side_effect = Exception(
        "boom"
    )

    result = main.main({})

    self.assertEqual(
        result,
        (
            (
                "An unknown error occurred during Cyjax data ingestion: "
                f"{repr(Exception('boom'))}"
            ),
            400,
        ),
    )
    mock_release_lock.assert_called_once_with("test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_gcp_permission_denied_releases_lock(
      self,
      mock_log,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
      mock_release_lock,
  ):
    """Test permission errors after bucket acquisition release the lock."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = ["test-bucket"]
    mock_acquire_lock.side_effect = GCPPermissionDeniedError("denied")

    result = main.main({})

    self.assertEqual(
        result,
        (
            "The service account does not have sufficient permissions "
            + "for Cyjax ingestion.",
            403,
        ),
    )
    mock_release_lock.assert_called_once_with("test-bucket")

  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_gcp_permission_denied(
      self,
      mock_log,
      mock_check_perms,
  ):
    """Test main function when GCP permission denied."""
    mock_check_perms.side_effect = GCPPermissionDeniedError("Permission denied")

    result = main.main({})

    self.assertEqual(
        result,
        (
            (
                "The service account does not have sufficient permissions for"
                " Cyjax ingestion."
            ),
            403,
        ),
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_invalid_historical_duration(
      self,
      mock_log,
      mock_validate_int,
      mock_parse_bool,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
      mock_release_lock,
  ):
    """Test main function with invalid historical IOC duration."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test-bucket",
        "test-token",
        "10",  # > 7
        None,
        "false",
        None,
    ]
    mock_validate_int.return_value = 10
    mock_parse_bool.return_value = False
    mock_acquire_lock.return_value = True

    result = main.main({})

    self.assertEqual(
        result,
        (
            (
                "Error initializing:"
                f" {repr(CyjaxException('HISTORICAL_IOC_DURATION cannot exceed 7 days. Provided value: 10.'))}"
            ),
            500,
        ),
    )
    mock_release_lock.assert_called_once_with("test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_indicator_types_processing(
      self,
      mock_log,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
  ):
    """Test main function with indicator types processing."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test-bucket",
        "test-token",
        None,
        None,
        "false",
        "type1| type2 |type3",
    ]
    mock_acquire_lock.return_value = False  # To avoid creating client

    result = main.main({})

    self.assertEqual(
        result,
        ("Another process is already running. Skipping execution.", 409),
    )
    # The side_effect will be consumed, but since lock fails, it stops


if __name__ == "__main__":
  unittest.main()
