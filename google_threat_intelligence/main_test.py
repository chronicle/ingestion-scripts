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

"""Unit tests for main.py module."""

import sys
import unittest
from unittest import mock
# Mock common modules to avoid import errors
INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest_v1"] = mock.Mock()
sys.modules["common.utils"] = mock.Mock()
# Mock problematic imports before importing the actual modules
mock_google_cloud = mock.Mock()
mock_exceptions = mock.Mock()
mock_exceptions.NotFound = (
    Exception  # Mock NotFound as a proper exception class
)
mock_google_cloud.exceptions = mock_exceptions
sys.modules["google.cloud"] = mock_google_cloud
sys.modules["google.cloud.storage"] = mock.Mock()
sys.modules["google.cloud.exceptions"] = mock_exceptions

MagicMock = mock.MagicMock
patch = mock.patch

import constant
import main


class TestMainFunction(unittest.TestCase):
  """Test cases for main.py module."""

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.gti_client.GoogleThreatIntelligenceUtility"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.run_methods_in_parallel")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_successful_execution_both_methods_enabled(
      self,
      mock_cloud_logging,
      mock_run_methods,
      mock_gti_client_class,
      mock_get_env_var,
  ):
    """Test successful execution when both IOC stream and threat lists are enabled."""
    # Arrange
    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_VAR_GTI_API_TOKEN: "test_api_key",
        constant.ENV_VAR_GCP_BUCKET_NAME: "test_bucket",
        constant.ENV_VAR_FETCH_IOC_STREAM_ENABLED: "true",
        constant.ENV_VAR_THREAT_LISTS: "malware,phishing",
    }.get(
        key
    )

    mock_gti_instance = MagicMock()
    mock_gti_client_class.return_value = mock_gti_instance

    # Set method names for logging
    mock_gti_instance.get_and_ingest_ioc_stream_events.__name__ = (
        "get_and_ingest_ioc_stream_events"
    )
    mock_gti_instance.get_and_ingest_threat_list_events.__name__ = (
        "get_and_ingest_threat_list_events"
    )

    # Act
    result = main.main(MagicMock())

    # Assert
    mock_gti_client_class.assert_called_once_with("test_api_key", "test_bucket")

    expected_enabled_methods = [
        mock_gti_instance.get_and_ingest_ioc_stream_events,
        mock_gti_instance.get_and_ingest_threat_list_events,
    ]
    mock_run_methods.assert_called_once_with(expected_enabled_methods)

    mock_cloud_logging.assert_any_call(
        "Enabled methods: get_and_ingest_ioc_stream_events,"
        " get_and_ingest_threat_list_events"
    )
    mock_cloud_logging.assert_any_call("Methods execution completed.")

    self.assertEqual(result, "data ingestion completed")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.gti_client.GoogleThreatIntelligenceUtility"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.run_methods_in_parallel")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_successful_execution_only_ioc_stream_enabled(
      self,
      mock_cloud_logging,
      mock_run_methods,
      mock_gti_client_class,
      mock_get_env_var,
  ):
    """Test successful execution when only IOC stream is enabled."""
    # Arrange
    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_VAR_GTI_API_TOKEN: "test_api_key",
        constant.ENV_VAR_GCP_BUCKET_NAME: "test_bucket",
        constant.ENV_VAR_FETCH_IOC_STREAM_ENABLED: "true",
        constant.ENV_VAR_THREAT_LISTS: None,
    }.get(
        key
    )

    mock_gti_instance = MagicMock()
    mock_gti_client_class.return_value = mock_gti_instance
    mock_gti_instance.get_and_ingest_ioc_stream_events.__name__ = (
        "get_and_ingest_ioc_stream_events"
    )

    # Act
    result = main.main(MagicMock())

    # Assert
    expected_enabled_methods = [
        mock_gti_instance.get_and_ingest_ioc_stream_events
    ]
    mock_run_methods.assert_called_once_with(expected_enabled_methods)
    self.assertEqual(result, "data ingestion completed")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.gti_client.GoogleThreatIntelligenceUtility"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.run_methods_in_parallel")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_successful_execution_only_threat_lists_enabled(
      self,
      mock_cloud_logging,
      mock_run_methods,
      mock_gti_client_class,
      mock_get_env_var,
  ):
    """Test successful execution when only threat lists are enabled."""
    # Arrange
    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_VAR_GTI_API_TOKEN: "test_api_key",
        constant.ENV_VAR_GCP_BUCKET_NAME: "test_bucket",
        constant.ENV_VAR_FETCH_IOC_STREAM_ENABLED: "false",
        constant.ENV_VAR_THREAT_LISTS: "malware",
    }.get(
        key
    )

    mock_gti_instance = MagicMock()
    mock_gti_client_class.return_value = mock_gti_instance
    mock_gti_instance.get_and_ingest_threat_list_events.__name__ = (
        "get_and_ingest_threat_list_events"
    )

    # Act
    result = main.main(MagicMock())

    # Assert
    expected_enabled_methods = [
        mock_gti_instance.get_and_ingest_threat_list_events
    ]
    mock_run_methods.assert_called_once_with(expected_enabled_methods)
    self.assertEqual(result, "data ingestion completed")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.gti_client.GoogleThreatIntelligenceUtility"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_no_methods_enabled(
      self, mock_cloud_logging, mock_gti_client_class, mock_get_env_var
  ):
    """Test when no methods are enabled."""
    # Arrange
    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_VAR_GTI_API_TOKEN: "test_api_key",
        constant.ENV_VAR_GCP_BUCKET_NAME: "test_bucket",
        constant.ENV_VAR_FETCH_IOC_STREAM_ENABLED: "false",
        constant.ENV_VAR_THREAT_LISTS: None,
    }.get(
        key
    )

    mock_gti_instance = MagicMock()
    mock_gti_client_class.return_value = mock_gti_instance

    # Act
    result = main.main(MagicMock())

    # Assert
    mock_cloud_logging.assert_called_with(
        "No methods enabled. Please set proper environment variables.",
        severity="ERROR",
    )
    self.assertEqual(
        result,
        ("No methods enabled. Please set proper environment variables.", 400),
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_error_in_environment_variable_retrieval(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test error during environment variable retrieval."""
    # Arrange
    mock_get_env_var.side_effect = Exception(
        "Environment variable retrieval error"
    )

    # Act
    result = main.main(MagicMock())

    # Assert
    mock_cloud_logging.assert_called_with(
        "Unknown exception occurred while retrieving the environment"
        " credentials. Error message: Exception('Environment variable retrieval error')",
        severity="ERROR",
    )
    self.assertEqual(
        result,
        ("Error initializing: Exception('Environment variable retrieval error')", 500),
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.gti_client.GoogleThreatIntelligenceUtility"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_error_in_gti_client_initialization(
      self, mock_cloud_logging, mock_gti_client_class, mock_get_env_var
  ):
    """Test error during GTI client initialization."""
    # Arrange
    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_VAR_GTI_API_TOKEN: "test_api_key",
        constant.ENV_VAR_GCP_BUCKET_NAME: "test_bucket",
    }.get(
        key
    )

    mock_gti_client_class.side_effect = Exception(
        "GTI client initialization error"
    )

    # Act
    result = main.main(MagicMock())

    # Assert
    mock_cloud_logging.assert_called_with(
        "Unknown exception occurred while retrieving the environment"
        " credentials. Error message: Exception('GTI client initialization error')",
        severity="ERROR",
    )
    self.assertEqual(
        result, ("Error initializing: Exception('GTI client initialization error')", 500)
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.get_environment_variable")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}main.gti_client.GoogleThreatIntelligenceUtility"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utility.run_methods_in_parallel")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_run_methods_error(
      self,
      mock_cloud_logging,
      mock_run_methods,
      mock_gti_client_class,
      mock_get_env_var,
  ):
    """Test error during method execution."""
    # Arrange
    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_VAR_GTI_API_TOKEN: "test_api_key",
        constant.ENV_VAR_GCP_BUCKET_NAME: "test_bucket",
        constant.ENV_VAR_FETCH_IOC_STREAM_ENABLED: "true",
        constant.ENV_VAR_THREAT_LISTS: None,
    }.get(
        key
    )

    mock_gti_instance = MagicMock()
    mock_gti_client_class.return_value = mock_gti_instance
    mock_gti_instance.get_and_ingest_ioc_stream_events.__name__ = (
        "get_and_ingest_ioc_stream_events"
    )

    mock_run_methods.side_effect = Exception("Error running methods")

    # Act
    result = main.main(MagicMock())

    # Assert
    mock_cloud_logging.assert_called_with(
        "Unknown exception occurred while executing methods parallel. Error"
        " message: Exception('Error running methods')",
        severity="ERROR",
    )
    self.assertEqual(result, "Error executing methods: Exception('Error running methods')")
