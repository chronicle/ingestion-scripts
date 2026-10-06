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
# pylint: disable=g-docstring-first-line-too-long


import unittest
from unittest.mock import Mock, patch, MagicMock
import sys

# Mock common modules before importing main
mock_common = MagicMock()
mock_utils = MagicMock()
mock_common.utils = mock_utils
sys.modules["common"] = mock_common
sys.modules["common.utils"] = mock_utils

INGESTION_SCRIPTS_PATH = ""
from exception_handler import (
    GCPPermissionDeniedError,
    CywareCTIXException,
    RunTimeExceeded,
)
import constant
import main


class TestMain(unittest.TestCase):
  """Test cases for main function."""

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
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
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    result, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    self.assertIn("success", result.lower())
    mock_client.fetch_indicators_by_labels.assert_called_once()
    mock_release_lock.assert_called_once_with("test_tenant", "test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_runtime_exceeded_exception(
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
    """Test main function with RunTimeExceeded exception."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.side_effect = RunTimeExceeded(
        "Execution time limit exceeded"
    )

    result, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    self.assertIn("Execution time limit exceeded", result)
    mock_release_lock.assert_called_once_with("test_tenant", "test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_with_enrichment_enabled(
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
    """Test main function with enrichment enabled."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "true",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = True
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicator_data.return_value = []
    mock_client.ingest_indicators.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    mock_client_class.assert_called_once()
    call_kwargs = mock_client_class.call_args[1]
    self.assertTrue(call_kwargs["enrichment_enabled"])

  @patch(f"{INGESTION_SCRIPTS_PATH}main.urllib.parse.urlparse")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_without_tenant_name(
      self,
      mock_log,
      mock_validate_int,
      mock_parse_bool,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
      mock_release_lock,
      mock_client_class,
      mock_urlparse,
  ):
    """Test main function extracts tenant from base_url when not provided."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_parsed = Mock()
    mock_parsed.netloc = "example.com"
    mock_urlparse.return_value = mock_parsed

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    mock_urlparse.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_gcp_permission_denied(
      self, mock_log, mock_check_perms, mock_get_env
  ):
    """Test main function with GCP permission denied error."""
    mock_check_perms.side_effect = GCPPermissionDeniedError(
        "Permission denied",
        resource="gs://bucket",
        permissions=["Storage Admin"],
    )

    result, status_code = main.main(None)

    self.assertEqual(status_code, 403)
    self.assertIn("permission", result.lower())

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_gcp_permission_denied_after_bucket_loaded(
      self,
      mock_log,
      mock_check_perms,
      mock_get_env,
      mock_acquire_lock,
      mock_release_lock,
  ):
    """Test GCP permission denied after tenant and bucket are loaded."""
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
    ]
    # Raise error after tenant and bucket are set
    mock_acquire_lock.side_effect = GCPPermissionDeniedError(
        "Permission denied",
        resource="gs://bucket",
        permissions=["Storage Admin"],
    )

    result, status_code = main.main(None)

    self.assertEqual(status_code, 403)
    self.assertIn("permission", result.lower())
    mock_release_lock.assert_called_once_with("test_tenant", "test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_initialization_error(
      self, mock_log, mock_check_perms, mock_get_env, mock_release_lock
  ):
    """Test main function with initialization error after tenant/bucket loaded."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        RuntimeError("Environment variable error"),
    ]

    result, status_code = main.main(None)

    self.assertEqual(status_code, 500)
    self.assertIn("Error initializing", result)
    mock_release_lock.assert_called_once_with("test_tenant", "test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_cyware_exception_during_ingestion(
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
    """Test main function with CywareCTIXException during ingestion."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.side_effect = CywareCTIXException(
        "API error occurred"
    )

    result, status_code = main.main(None)

    self.assertEqual(status_code, 400)
    self.assertIn("Error during CTIX data ingestion", result)

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_generic_exception_during_ingestion(
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
    """Test main function with generic exception during ingestion."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.side_effect = ValueError(
        "Unexpected error"
    )

    result, status_code = main.main(None)

    self.assertEqual(status_code, 400)
    self.assertIn("unknown error", result.lower())

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_all_parameters_passed_to_client(
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
    """Test that all parameters are correctly passed to CTIXClient."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "bucket_value",
        "access_id_value",
        "secret_key_value",
        "true",
        "45",
        "label_value",
    ]
    mock_parse_bool.return_value = True
    mock_validate_int.return_value = 45
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    main.main(None)

    mock_client_class.assert_called_once_with(
        base_url="https://example.com",
        access_id="access_id_value",
        secret_key="secret_key_value",
        tenant_name="test_tenant",
        enrichment_enabled=True,
        label_name="label_value",
        bucket_name="bucket_value",
        lookback_days=45,
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_configuration_logging(
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
    """Test that configuration is logged correctly."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "true",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = True
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    main.main(None)

    log_calls = [str(call) for call in mock_log.call_args_list]
    config_logged = any(
        "Configuration loaded" in str(call) for call in log_calls
    )
    self.assertTrue(config_logged)

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_empty_tenant_name_with_urlparse(
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
    """Test main with empty tenant name triggers URL parsing."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "",
        "https://tenant.example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    call_kwargs = mock_client_class.call_args[1]
    self.assertEqual(call_kwargs["tenant_name"], "tenant.example.com")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_ingest_indicators_called_with_data(
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
    """Test that ingest_indicators is called with fetched data."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    mock_client.fetch_indicators_by_labels.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_permission_check_called_first(self, mock_log, mock_check_perms):
    """Test that permission check is called before anything else."""
    mock_check_perms.side_effect = GCPPermissionDeniedError(
        "Permission denied")

    _, status_code = main.main(None)

    self.assertEqual(status_code, 403)
    mock_check_perms.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_lookback_days_validation(
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
    """Test that lookback_days is validated."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "45",
        "",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 45
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    mock_validate_int.assert_called_once_with(
        "45", constant.ENV_INDICATOR_LOOKBACK_DAYS
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_fetch_and_ingest_flow(
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
    """Test the complete fetch and ingest flow."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "test_label",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    mock_client.fetch_indicators_by_labels.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_error_message_format(
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
    """Test that error messages are formatted correctly."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "access_id",
        "secret_key",
        "false",
        "30",
        "",
        "test-bucket",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    test_exception = CywareCTIXException("Test error message")
    mock_client.fetch_indicators_by_labels.side_effect = test_exception

    result, status_code = main.main(None)

    self.assertEqual(status_code, 400)
    self.assertIsInstance(result, str)
    self.assertIn("Error during CTIX data ingestion", result)


class TestMainLockHandling(unittest.TestCase):
  """Test cases for process lock handling in main."""

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_lock_acquisition_fails(
      self, mock_log, mock_get_env, mock_check_perms, mock_acquire_lock
  ):
    """Test main when lock acquisition fails."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
    ]
    mock_acquire_lock.return_value = False

    result, status_code = main.main(None)

    self.assertEqual(status_code, 409)
    self.assertIn("already running", result)

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_lock_released_on_success(
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
    """Test that lock is released on successful completion."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    mock_release_lock.assert_called_once_with("test_tenant", "test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_lock_released_on_ctix_exception(
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
    """Test that lock is released on CywareCTIXException."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.side_effect = CywareCTIXException(
        "API error"
    )

    _, status_code = main.main(None)

    self.assertEqual(status_code, 400)
    mock_release_lock.assert_called_once_with("test_tenant", "test-bucket")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_lock_released_on_generic_exception(
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
    """Test that lock is released on generic exception."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.side_effect = ValueError("Error")

    _, status_code = main.main(None)

    self.assertEqual(status_code, 400)
    mock_release_lock.assert_called_once_with("test_tenant", "test-bucket")


class TestMainTenantNameExtraction(unittest.TestCase):
  """Test cases for tenant name extraction logic."""

  @patch(f"{INGESTION_SCRIPTS_PATH}main.urllib.parse.urlparse")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_tenant_extracted_from_complex_url(
      self,
      mock_log,
      mock_validate_int,
      mock_parse_bool,
      mock_check_perms,
      mock_get_env,
      mock_release_lock,
      mock_acquire_lock,
      mock_client_class,
      mock_urlparse,
  ):
    """Test tenant extraction from complex URL."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "",
        "https://subdomain.tenant.example.com:8080/path",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_parsed = Mock()
    mock_parsed.netloc = "subdomain.tenant.example.com:8080"
    mock_urlparse.return_value = mock_parsed

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    call_kwargs = mock_client_class.call_args[1]
    self.assertEqual(
        call_kwargs["tenant_name"], "subdomain.tenant.example.com:8080"
    )


class TestMainNoIndicatorsFlow(unittest.TestCase):
  """Test cases for handling no indicators scenario."""

  @patch(f"{INGESTION_SCRIPTS_PATH}main.cyware_client.CTIXClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.release_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.acquire_process_lock")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.check_sufficient_permissions_on_service_account")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.parse_boolean_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.validate_integer_env")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_no_indicators_fetched_still_succeeds(
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
    """Test that no indicators fetched still returns success."""
    mock_check_perms.return_value = True
    mock_get_env.side_effect = [
        "test_tenant",
        "https://example.com",
        "test-bucket",
        "access_id",
        "secret_key",
        "false",
        "30",
        "",
    ]
    mock_parse_bool.return_value = False
    mock_validate_int.return_value = 30
    mock_acquire_lock.return_value = True

    mock_client = Mock()
    mock_client_class.return_value = mock_client
    mock_client.fetch_indicators_by_labels.return_value = None

    _, status_code = main.main(None)

    self.assertEqual(status_code, 200)
    mock_client.fetch_indicators_by_labels.assert_called_once()


if __name__ == "__main__":
  unittest.main()
