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
# pylint: disable=unused-variable
# pylint: disable=g-doc-args


"""Comprehensive unit tests for cyware_client module - 100% coverage."""

import unittest
from unittest.mock import Mock, patch
import sys
import datetime
from urllib.parse import parse_qs, urlparse
from absl.testing import parameterized

# Mock common modules before importing cyware_client
# Create proper mock modules to support autospec


class MockUtils:
  """Mock utils module."""

  @classmethod
  def cloud_logging(cls, message: str, severity: str = "INFO") -> None:
    """Mock cloud logging function."""

  @classmethod
  def get_env_var(cls, name: str, required: bool = True, default=None, is_secret: bool = False):
    """Mock get_env_var function."""
    return "mock_customer_id"

  @classmethod
  def get_value_from_secret_manager(cls, path: str) -> str:
    """Mock secret manager."""
    return "mock_secret"


class MockIngestV1:
  """Mock ingest_v1 module."""

  @classmethod
  def ingest(cls, data, **kwargs):
    """Mock ingest function."""


class MockEnvConstants:
  """Mock env_constants module."""
  ENV_CHRONICLE_CUSTOMER_ID = "CHRONICLE_CUSTOMER_ID"
  ENV_CHRONICLE_SERVICE_ACCOUNT = "CHRONICLE_SERVICE_ACCOUNT"
  ENV_CHRONICLE_PROJECT_NUMBER = "CHRONICLE_PROJECT_NUMBER"
  ENV_POLL_INTERVAL = "POLL_INTERVAL"


class MockCommon:
  """Mock common module."""
  utils = MockUtils()
  ingest_v1 = MockIngestV1()
  env_constants = MockEnvConstants()


mock_common = MockCommon()
mock_utils = MockUtils()
mock_ingest_v1 = MockIngestV1()
mock_env_constants = MockEnvConstants()
INGESTION_SCRIPTS_PATH = ""
sys.modules["common"] = mock_common
sys.modules["common.utils"] = mock_utils
sys.modules["common.ingest_v1"] = mock_ingest_v1
sys.modules["common.env_constants"] = mock_env_constants

from exception_handler import (  # noqa: E402
        CywareCTIXException,
        RunTimeExceeded,
)
import constant  # noqa: E402
import cyware_client  # noqa: E402


class TestCTIXClientInit(unittest.TestCase):
  """Test CTIXClient initialization."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_init_all_params(self, mock_log):
    """Test initialization with all parameters."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com/",
        access_id="test_id",
        secret_key="test_key",
        tenant_name="test_tenant",
        enrichment_enabled=True,
        label_name="test_label",
        bucket_name="test-bucket",
        lookback_days="30",
    )
    self.assertEqual(client.base_url, "https://example.com")
    self.assertEqual(client.access_id, "test_id")
    self.assertEqual(client.enrichment_enabled, True)
    self.assertEqual(client.label_name, "test_label")
    # Autospec creates a new mock, so we just verify client was created
    self.assertIsNotNone(client)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_init_strips_trailing_slash(self, mock_log):
    """Test that trailing slash is removed from base_url."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com/////",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )
    self.assertEqual(client.base_url, "https://example.com")


class TestAuthParams(unittest.TestCase):
  """Test get_ctix_auth_params method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_auth_params_generation(self, mock_log, mock_time):
    """Test authentication parameter generation."""
    mock_time.return_value = 1000000
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="test_id",
        secret_key="test_key",
        tenant_name="tenant",
    )
    params = client.get_ctix_auth_params("test_id", "test_key")

    self.assertIn("AccessID", params)
    self.assertIn("Signature", params)
    self.assertIn("Expires", params)
    self.assertEqual(params["AccessID"], "test_id")
    self.assertEqual(
        params["Expires"], 1000000 + constant.SIGNATURE_EXPIRY_SECONDS
    )


class TestGetStartTime(unittest.TestCase):
  """Test get_start_time method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_get_start_time_with_lookback(self, mock_log):
    """Test get_start_time with lookback days."""
    result = cyware_client.get_start_time("7")
    self.assertIsInstance(result, int)
    self.assertGreater(result, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_get_start_time_default(self, mock_log):
    """Test get_start_time with default lookback."""
    result = cyware_client.get_start_time(None)
    self.assertIsInstance(result, int)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_get_start_time_invalid_lookback(self, mock_log):
    """Test get_start_time with invalid lookback value."""
    result = cyware_client.get_start_time("invalid")
    self.assertIsInstance(result, int)
    # Should fall back to default
    log_calls = [str(c) for c in mock_log.call_args_list]
    has_warning = any(
        "Error parsing lookback_days" in str(c) for c in log_calls
    )
    self.assertTrue(has_warning)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_get_start_time_negative_days(self, mock_log):
    """Test get_start_time with negative days."""
    result = cyware_client.get_start_time("-5")
    self.assertIsInstance(result, int)
    # Should fall back to default due to ValueError
    log_calls = [str(c) for c in mock_log.call_args_list]
    has_warning = any(
        "Error parsing lookback_days" in str(c) for c in log_calls
    )
    self.assertTrue(has_warning)


class TestExtractIOCValues(unittest.TestCase):
  """Test extract_ioc_values method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_extract_ioc_values_success(self, mock_log):
    """Test extracting IOC values from indicators."""
    indicators = [
        {"sdo_name": "1.2.3.4"},
        {"sdo_name": "example.com"},
        {"sdo_name": "1.2.3.4"},  # duplicate
    ]
    result = cyware_client.extract_ioc_values(indicators)
    self.assertEqual(len(result), 2)  # deduplicated

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_extract_ioc_values_empty(self, mock_log):
    """Test with empty indicator list."""
    result = cyware_client.extract_ioc_values([])
    self.assertEqual(result, [])


class TestDeduplicateIndicators(unittest.TestCase):
  """Test _deduplicate_indicators method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_deduplicate_keeps_latest(self, mock_log):
    """Test deduplication keeps latest by ctix_modified."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )
    indicators = [
        {"sdo_name": "ioc1", "ctix_modified": 1000},
        {"sdo_name": "ioc1", "ctix_modified": 2000},
        {"sdo_name": "ioc2", "ctix_modified": 1500},
    ]
    result = client._deduplicate_indicators(indicators)
    self.assertEqual(len(result), 2)
    ioc1 = [i for i in result if i["sdo_name"] == "ioc1"][0]
    self.assertEqual(ioc1["ctix_modified"], 2000)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_deduplicate_empty_list(self, mock_log):
    """Test deduplication with empty list."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )
    result = client._deduplicate_indicators([])
    self.assertEqual(result, [])


class TestCheckpointsAndTimestamps(unittest.TestCase):
  """Test _get_checkpoints_and_timestamps with all validation logic."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.datetime.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_invalid_from_timestamp_non_positive(
      self, mock_log, mock_dt, mock_get, mock_set
  ):
    """Test from_timestamp validation - non-positive value."""
    current_time = 2000000
    mock_now = datetime.datetime.fromtimestamp(
        current_time, tz=datetime.timezone.utc
    )
    mock_dt.now.return_value = mock_now
    mock_dt.timezone = datetime.timezone
    mock_dt.timedelta = datetime.timedelta
    mock_dt.datetime = datetime.datetime

    # Return 0 for from_timestamp (non-positive)
    mock_get.side_effect = ["0", None, None]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        lookback_days="7",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()

    # Should reset to default based on lookback days
    self.assertGreater(from_ts, 0)
    self.assertLess(from_ts, current_time)
    # Verify warning logged
    log_calls = [str(c) for c in mock_log.call_args_list]
    has_warning = any(
        "Invalid from_timestamp" in str(c) and "non-positive" in str(c)
        for c in log_calls
    )
    self.assertTrue(has_warning)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_invalid_from_timestamp_value_error(self, mock_log, mock_get):
    """Test from_timestamp validation - ValueError."""
    mock_get.side_effect = ["not_a_number", None, None]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        lookback_days="7",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()

    self.assertGreater(from_ts, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.datetime.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_invalid_to_timestamp_non_positive(
      self, mock_log, mock_dt, mock_get, mock_set
  ):
    """Test to_timestamp validation - non-positive."""
    mock_now = Mock()
    current_time = 2000000
    mock_now.timestamp.return_value = current_time
    mock_dt.now.return_value = mock_now
    mock_dt.timezone = datetime.timezone
    mock_dt.timedelta = datetime.timedelta

    mock_get.side_effect = ["1000000", "0", None]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()

    self.assertEqual(to_ts, current_time)
    mock_set.assert_called()  # Should clear invalid checkpoint
    log_calls = [str(c) for c in mock_log.call_args_list]
    has_warning = any(
        "Invalid to_timestamp" in str(c) and "non-positive" in str(c)
        for c in log_calls
    )
    self.assertTrue(has_warning)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.datetime.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_invalid_to_timestamp_future(
      self, mock_log, mock_dt, mock_get, mock_set
  ):
    """Test to_timestamp validation - future timestamp."""
    mock_now = Mock()
    current_time = 2000000
    mock_now.timestamp.return_value = current_time
    mock_dt.now.return_value = mock_now
    mock_dt.timezone = datetime.timezone
    mock_dt.timedelta = datetime.timedelta

    future_time = current_time + 100000
    mock_get.side_effect = ["1000000", str(future_time), None]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()

    self.assertEqual(to_ts, current_time)
    mock_set.assert_called()
    log_calls = [str(c) for c in mock_log.call_args_list]
    has_warning = any(
        "Invalid to_timestamp" in str(c) and "future timestamp" in str(c)
        for c in log_calls
    )
    self.assertTrue(has_warning)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.datetime.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_invalid_to_timestamp_value_error(
      self, mock_log, mock_dt, mock_get, mock_set
  ):
    """Test to_timestamp validation - ValueError."""
    mock_now = Mock()
    current_time = 2000000
    mock_now.timestamp.return_value = current_time
    mock_dt.now.return_value = mock_now
    mock_dt.timezone = datetime.timezone
    mock_dt.timedelta = datetime.timedelta

    mock_get.side_effect = ["1000000", "invalid", None]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()

    self.assertEqual(to_ts, current_time)
    mock_set.assert_called()


class TestGetSavedResultSetPage(unittest.TestCase):
  """Test get_saved_result_set_page method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_get_saved_result_set_page_success(self, mock_log):
    """Test successful page retrieval."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        label_name="test_label",
    )

    with patch.object(client, "make_api_call") as mock_api:
      mock_api.return_value = {
          "status": True,
          "data": {"results": [{"data": [{"id": "1"}]}]},
      }
      result = client.get_saved_result_set_page(1000000, 2000000, 1)

    self.assertIn("results", result)
    # Verify label_name is in params
    call_args = mock_api.call_args
    self.assertIn("label_name", call_args[1]["params"])


class TestExtractIndicatorsFromPageData(unittest.TestCase):
  """Test _extract_indicators_from_page_data method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_extract_with_deduplication(self, mock_log):
    """Test extraction with deduplication."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    data = {
        "results": [{
            "data": [
                {
                    "id": "1",
                    "sdo_type": "indicator",
                    "sdo_name": "ioc1",
                    "ctix_modified": 1000,
                },
                {
                    "id": "2",
                    "sdo_type": "indicator",
                    "sdo_name": "ioc1",
                    "ctix_modified": 2000,
                },
                {"id": "3", "sdo_type": "malware", "sdo_name": "mal1"},
            ]
        }]
    }

    result = client._extract_indicators_from_page_data(data)

    # Should have 1 indicator (deduplicated, latest version kept)
    self.assertEqual(len(result), 1)
    self.assertEqual(result[0]["ctix_modified"], 2000)


class TestFilterIndicators(unittest.TestCase):
  """Test _filter_indicators method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_filter_sorts_by_ctix_modified(self, mock_log, mock_checkpoint):
    """Test indicators are sorted by ctix_modified."""
    mock_checkpoint.return_value = None

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [
        {"sdo_name": "ioc3", "ctix_modified": 3000},
        {"sdo_name": "ioc1", "ctix_modified": 1000},
        {"sdo_name": "ioc2", "ctix_modified": 2000},
    ]

    result = client._filter_indicators(indicators)

    self.assertEqual(result[0]["ctix_modified"], 1000)
    self.assertEqual(result[1]["ctix_modified"], 2000)
    self.assertEqual(result[2]["ctix_modified"], 3000)


class TestIngestIndicators(unittest.TestCase):
  """Test _ingest_indicators method and runtime checks."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ingest_empty_list_returns_zero(
      self, mock_log, mock_get, mock_ingest, mock_time
  ):
    """Test ingesting empty list returns 0."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    result = client._ingest_indicators([], 1000, 2000, 1)

    self.assertEqual(result, 0)
    mock_ingest.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ingest_success(self, mock_log, mock_get, mock_ingest, mock_time):
    """Test successful ingestion."""
    mock_get.return_value = None
    mock_time.return_value = 1000000

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1"}]
    result = client._ingest_indicators(indicators, 1000, 2000, 1)

    self.assertEqual(result, 1)
    mock_ingest.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ingest_runtime_exceeded(
      self, mock_log, mock_get, mock_ingest, mock_time
  ):
    """Test RunTimeExceeded is raised when time limit exceeded."""
    # Set last run time to 60 minutes ago
    current_time = 1000000
    last_run_time = current_time - (
        constant.INGESTION_TIME_CHECK_MINUTES * 60 + 100
    )

    mock_get.return_value = str(last_run_time)
    mock_time.return_value = current_time

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1"}]

    with self.assertRaises(RunTimeExceeded):
      client._ingest_indicators(indicators, 1000, 2000, 1)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ingest_runtime_check_value_error(
      self, mock_log, mock_get, mock_ingest, mock_time
  ):
    """Test ingestion continues when runtime check has ValueError."""
    mock_get.return_value = "invalid_float"
    mock_time.return_value = 1000000

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1"}]
    result = client._ingest_indicators(indicators, 1000, 2000, 1)

    # Should continue despite error
    self.assertEqual(result, 1)
    log_calls = [str(c) for c in mock_log.call_args_list]
    has_error = any(
        "Error checking execution time" in str(c) for c in log_calls
    )
    self.assertTrue(has_error)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ingest_with_chunk_info(
      self, mock_log, mock_get, mock_ingest, mock_time
  ):
    """Test ingestion with chunk_info in logging."""
    mock_get.return_value = None
    mock_time.return_value = 1000000

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1"}]
    result = client._ingest_indicators(indicators, 1000, 2000, 1, "Batch 1")

    self.assertEqual(result, 1)
    # Verify chunk_info in logs
    log_calls = [str(c) for c in mock_log.call_args_list]
    has_chunk = any("Batch 1" in str(c) for c in log_calls)
    self.assertTrue(has_chunk)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ingest_exception_saves_checkpoint(
      self, mock_log, mock_get, mock_ingest, mock_time
  ):
    """Test ingestion exception triggers checkpoint save."""
    mock_get.return_value = None
    mock_time.return_value = 1000000
    mock_ingest.side_effect = Exception("Ingestion error")

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    with patch.object(client, "_save_error_checkpoint") as mock_save:
      indicators = [{"sdo_name": "ioc1"}]

      with self.assertRaisesRegex(Exception, "Ingestion error"):
        client._ingest_indicators(indicators, 1000, 2000, 1)

      mock_save.assert_called_once()


class TestSaveErrorCheckpoint(unittest.TestCase):
  """Test _save_error_checkpoint method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_save_error_checkpoint(self, mock_log, mock_set):
    """Test error checkpoint is saved with correct values."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    error = Exception("Test error")
    client._save_error_checkpoint(1000, 2000, 5, error)

    # Should save from_timestamp, to_timestamp, and page_number
    self.assertGreaterEqual(mock_set.call_count, 3)


class TestFetchIndicatorData(unittest.TestCase):
  """Test fetch_indicator_data main loop."""

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_fetch_runtime_exceeded_exception(
      self, mock_log, mock_set, mock_clear
  ):
    """Test RunTimeExceeded exception in fetch - covers lines 1026-1030."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000, 2000, 1)
      with patch.object(client, "get_saved_result_set_page") as mock_page:
        # Raise RunTimeExceeded
        mock_page.side_effect = RunTimeExceeded("Time limit exceeded")
        with patch.object(client, "_save_error_checkpoint") as mock_save:
          with self.assertRaises(RunTimeExceeded):
            client.fetch_indicator_data(1000000, 2000000)
          mock_save.assert_called_once()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_fetch_cyware_exception(self, mock_log, mock_set, mock_clear):
    """Test CywareCTIXException in fetch - covers lines 1031-1035."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000, 2000, 1)
      with patch.object(client, "get_saved_result_set_page") as mock_page:
        # Raise CywareCTIXException
        mock_page.side_effect = CywareCTIXException("API error")
        with patch.object(client, "_save_error_checkpoint") as mock_save:
          with self.assertRaises(CywareCTIXException):
            client.fetch_indicator_data(1000000, 2000000)
          mock_save.assert_called_once()


class TestCtixRestApi(unittest.TestCase):
  """Test _ctix_rest_api method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ctix_rest_api_success(self, mock_log, mock_request):
    """Test successful API call."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_request.return_value = mock_response

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    result = client._ctix_rest_api("GET", "https://example.com/api", {})

    self.assertTrue(result["status"])
    self.assertEqual(result["response"], mock_response)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ctix_rest_api_return_dict_retry_false(self, mock_log, mock_request):
    """Test that return_dict initializes with retry=False.

    This test will FAIL if retry is changed to True in line 74.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_request.return_value = mock_response

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    result = client._ctix_rest_api("GET", "https://example.com/api", {})

    # Verify retry is False in successful response
    self.assertFalse(result["retry"])
    # Also verify the initial state is preserved
    self.assertIn("retry", result)
    self.assertEqual(result["retry"], False)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ctix_rest_api_verify_true_in_request(self, mock_log, mock_request):
    """Test that requests.request is called with verify=True.

    This test will FAIL if verify is changed to False in line 82.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_request.return_value = mock_response

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    test_url = "https://example.com/api"
    test_params = {"param1": "value1"}
    test_json_body = {"key": "value"}

    client._ctix_rest_api("POST", test_url, test_params, test_json_body)

    # Verify requests.request was called with verify=True
    mock_request.assert_called_once()
    call_kwargs = mock_request.call_args[1]
    self.assertIn("verify", call_kwargs)
    self.assertTrue(call_kwargs["verify"])

    # Also verify other critical parameters
    self.assertEqual(call_kwargs["method"], "POST")
    # URL should have encoded params appended
    self.assertIn("param1=value1", call_kwargs["url"])
    self.assertTrue(call_kwargs["url"].startswith(test_url))
    self.assertEqual(call_kwargs["json"], test_json_body)
    self.assertEqual(
        call_kwargs["timeout"],
        (constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ctix_rest_api_label_name_encoding(self, mock_log, mock_request):
    """Test that label_name is properly encoded in URL.

    This test covers lines 93-97 and 100 in cyware_client.py.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_request.return_value = mock_response

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    test_url = "https://example.com/api"
    unsafe_label = "weird label/with spaces & symbols #?"
    test_params = {"param1": "value1", "label_name": unsafe_label}

    client._ctix_rest_api("GET", test_url, test_params)

    # Verify requests.request was called
    mock_request.assert_called_once()
    call_kwargs = mock_request.call_args[1]

    # Verify label_name+safe chars encoded correctly and removed from params
    parsed_url = urlparse(call_kwargs["url"])
    query = parse_qs(parsed_url.query)
    self.assertEqual(query.get("param1"), ["value1"])
    self.assertEqual(query.get("label_name"), [unsafe_label])
    # Safe characters (spaces, slash) should remain, but unsafe ones must be encoded.
    raw_query = parsed_url.query
    self.assertIn("label_name=", raw_query)
    label_segment = raw_query.split("label_name=")[1]
    self.assertIn("weird label/with spaces ", label_segment)
    # '&' and '#' must be encoded because they would otherwise break query structure.
    self.assertIn("%26 symbols %23?", label_segment)
    self.assertNotIn("& symbols", label_segment)
    self.assertNotIn("%2F", label_segment)
    self.assertNotIn("label_name", call_kwargs.get("params", {}))
    self.assertTrue(call_kwargs["url"].startswith(test_url))

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ctix_rest_api_user_agent_header(self, mock_log, mock_request):
    """Test that User-Agent header is included in requests.

    This test covers line 110 in cyware_client.py.
    This test will FAIL if User-Agent header is removed or changed.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_request.return_value = mock_response

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    test_url = "https://example.com/api"
    test_params = {"param1": "value1"}
    test_json_body = {"key": "value"}

    client._ctix_rest_api("POST", test_url, test_params, test_json_body)

    # Verify requests.request was called with User-Agent header
    mock_request.assert_called_once()
    call_kwargs = mock_request.call_args[1]

    # Verify headers exist and contain User-Agent
    self.assertIn("headers", call_kwargs)
    headers = call_kwargs["headers"]
    self.assertIn("User-Agent", headers)
    self.assertEqual(headers["User-Agent"], constant.USER_AGENT_NAME)

    # Verify the User-Agent value matches the constant
    self.assertEqual(
        headers["User-Agent"], "cyware/intel-exchange (GoogleSecopsSIEM/1.0.0)"
    )


class TestParseAndHandleResponse(parameterized.TestCase):
  """Test _parse_and_handle_response method."""

  @parameterized.named_parameters(
      ("success_200", 200, {"data": "test"}, True, True, False),
      ("unauthorized_401", 401, "Unauthorized", False, False, False),
      ("forbidden_403", 403, "Forbidden", False, False, False),
      ("rate_limit_429", 429, "Rate limited", False, False, True),
      ("server_error_500", 500, "Server error", False, False, True),
      ("not_found_404", 404, "Not found", False, False, False),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_parse_status_codes(
      self,
      status_code,
      response_data,
      expected_status,
      has_data,
      has_retry,
      mock_log,
  ):
    """Test parsing various HTTP status codes."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    mock_response = Mock()
    mock_response.status_code = status_code
    if isinstance(response_data, dict):
      mock_response.json.return_value = response_data
    else:
      mock_response.text = response_data

    return_dict = {}
    result_dict = {"response": mock_response}
    result = client._parse_and_handle_response(
        return_dict, result_dict, "test")

    self.assertEqual(result["status"], expected_status)
    if has_data:
      self.assertIn("data", result)
    if not expected_status:
      if status_code in [401, 403, 404]:
        self.assertIn("error", result)
    if has_retry:
      self.assertTrue(result.get("retry", False))

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_parse_value_error(self, mock_log):
    """Test ValueError handling."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "invalid json"
    mock_response.json.side_effect = ValueError("JSON decode error")

    return_dict = {}
    result_dict = {"response": mock_response}
    client._parse_and_handle_response(return_dict, result_dict, "test")

    mock_log.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging", autospec=True)
  def test_parse_general_exception(self, mock_log):
    """Test general exception handling."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    return_dict = {}
    result_dict = {"response": Mock()}
    result_dict["response"].text = "test"

    with patch.object(
        result_dict["response"],
        "status_code",
        side_effect=Exception("test"),
    ):
      client._parse_and_handle_response(return_dict, result_dict, "test")

    mock_log.assert_called()


class TestMakeApiCall(unittest.TestCase):
  """Test make_api_call method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_make_api_call_success(self, mock_log):
    """Test successful API call."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    with patch.object(client, "_ctix_rest_api") as mock_api:
      with patch.object(client, "_parse_and_handle_response") as mock_parse:
        mock_api.return_value = {"status": True, "response": Mock()}
        mock_parse.return_value = {
            "status": True,
            "data": {"result": "success"},
        }

        result = client.make_api_call("GET", "https://example.com/api", {})

        self.assertTrue(result["status"])

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.sleep")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_make_api_call_retry_success(self, mock_log, mock_sleep):
    """Test retry on rate limit then success."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    call_count = [0]

    def parse_side_effect(*args):
      call_count[0] += 1
      if call_count[0] == 1:
        return {"status": False, "retry": True}
      return {"status": True, "data": {"result": "success"}}

    with patch.object(client, "_ctix_rest_api") as mock_api:
      with patch.object(client, "_parse_and_handle_response") as mock_parse:
        mock_api.return_value = {"status": True, "response": Mock()}
        mock_parse.side_effect = parse_side_effect

        result = client.make_api_call("GET", "https://example.com/api", {})

        self.assertEqual(call_count[0], 2)
        mock_sleep.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.sleep")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_make_api_call_max_retries(self, mock_log, mock_sleep):
    """Test max retries reached."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    with patch.object(client, "_ctix_rest_api") as mock_api:
      with patch.object(client, "_parse_and_handle_response") as mock_parse:
        mock_api.return_value = {"status": True, "response": Mock()}
        mock_parse.return_value = {"status": False, "retry": True}

        result = client.make_api_call("GET", "https://example.com/api", {})

        self.assertFalse(result["status"])
        self.assertGreater(mock_sleep.call_count, 0)


class TestEnrichmentMethods(unittest.TestCase):
  """Test enrichment methods."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_process_enrichment_chunk_success(self, mock_log, mock_set):
    """Test successful enrichment chunk processing."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1", "ctix_modified": 1500}]

    with patch.object(client, "make_api_call") as mock_api:
      mock_api.return_value = {
          "status": True,
          "data": {"results": [{"name": "ioc1", "threat_score": "high"}]},
      }
      with patch.object(client, "_ingest_indicators") as mock_ingest:
        mock_ingest.return_value = 1

        result = client._process_enrichment_chunk(
            0, indicators, 1500, 1000, 2000, 1
        )

        self.assertEqual(result, 1)
        mock_set.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_process_enrichment_chunk_empty(self, mock_log):
    """Test empty batch."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    result = client._process_enrichment_chunk(0, [], 0, 1000, 2000, 1)
    self.assertEqual(result, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_process_enrichment_chunk_no_ioc_values(self, mock_log):
    """Test no IOC values in batch."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    indicators = [{"other_field": "value"}]
    result = client._process_enrichment_chunk(0, indicators, 0, 1000, 2000, 1)
    self.assertEqual(result, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_process_enrichment_chunk_api_error(self, mock_log):
    """Test API error during enrichment."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1"}]

    with patch.object(client, "make_api_call") as mock_api:
      mock_api.return_value = {"status": False, "error": "API failed"}
      with patch.object(client, "_save_error_checkpoint") as mock_save:
        with self.assertRaises(CywareCTIXException):
          client._process_enrichment_chunk(0, indicators, 0, 1000, 2000, 1)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_process_enrichment_chunk_runtime_exceeded(self, mock_log):
    """Test RunTimeExceeded in enrichment."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1"}]

    with patch.object(client, "make_api_call") as mock_api:
      mock_api.side_effect = RunTimeExceeded("Time exceeded")
      with patch.object(client, "_save_error_checkpoint") as mock_save:
        with self.assertRaises(RunTimeExceeded):
          client._process_enrichment_chunk(0, indicators, 0, 1000, 2000, 1)
        mock_save.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ingest_without_enrichment(self, mock_log):
    """Test ingestion without enrichment."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    indicators = [{"sdo_name": "ioc1"}]

    with patch.object(client, "_ingest_indicators") as mock_ingest:
      mock_ingest.return_value = 1

      result = client._ingest_without_enrichment(indicators, 1000, 2000, 1)
      self.assertEqual(result, 1)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_ingest_without_enrichment_runtime_exceeded(self, mock_log):
    """Test RunTimeExceeded in non-enrichment ingestion."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1"}]

    with patch.object(client, "_ingest_indicators") as mock_ingest:
      mock_ingest.side_effect = RunTimeExceeded("Time exceeded")
      with patch.object(client, "_save_error_checkpoint") as mock_save:
        with self.assertRaises(RunTimeExceeded):
          client._ingest_without_enrichment(indicators, 1000, 2000, 1)
        mock_save.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_enrich_and_ingest_by_chunks(self, mock_log, mock_ingest):
    """Test enrichment by chunks."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    indicators = [
        {"sdo_name": f"ioc{i}", "ctix_modified": 1000 + i} for i in range(10)
    ]

    with patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.extract_ioc_values") as mock_extract:
      mock_extract.return_value = [f"ioc{i}" for i in range(10)]
      with patch.object(client, "_process_enrichment_chunk") as mock_process:
        mock_process.return_value = 5

        result = client._enrich_and_ingest_by_chunks(indicators, 1000, 2000, 1)
        self.assertGreater(result, 0)


class TestFilterIndicatorsCheckpoint(unittest.TestCase):
  """Test _filter_indicators with checkpoint logic."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_filter_with_checkpoint_filtering(self, mock_log, mock_get):
    """Test filtering based on checkpoint."""
    mock_get.return_value = "1500"

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [
        {"sdo_name": "ioc1", "ctix_modified": 1400},
        {"sdo_name": "ioc2", "ctix_modified": 1600},
    ]

    result = client._filter_indicators(indicators)
    self.assertEqual(len(result), 1)
    self.assertEqual(result[0]["ctix_modified"], 1600)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_filter_max_ioc_length(self, mock_log, mock_get):
    """Test filtering IOCs exceeding max length."""
    mock_get.return_value = None

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    long_ioc = "a" * 5000
    indicators = [
        {"sdo_name": long_ioc, "ctix_modified": 1400},
        {"sdo_name": "valid_ioc", "ctix_modified": 1600},
    ]

    result = client._filter_indicators(indicators)
    self.assertGreater(len(result), 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_filter_empty_list(self, mock_log):
    """Test filtering empty list."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    result = client._filter_indicators([])
    self.assertEqual(len(result), 0)


class TestLogAndSleepBeforeRetry(unittest.TestCase):
  """Test _log_and_sleep_before_retry method."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.sleep")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_log_and_sleep(self, mock_log, mock_sleep):
    """Test logging and sleeping before retry."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    client._log_and_sleep_before_retry()

    mock_log.assert_called()
    mock_sleep.assert_called()


class TestAdditionalFetchFlows(unittest.TestCase):
  """Test additional fetch indicator data flows."""

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_fetch_no_results(self, mock_log, mock_set, mock_clear):
    """Test fetch with no results."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000, 2000, 1)
      with patch.object(client, "get_saved_result_set_page") as mock_page:
        mock_page.return_value = {"results": [], "next": None}

        client.fetch_indicator_data(1000, 2000)
        mock_log.assert_called()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_fetch_with_pagination_and_filtering(
      self, mock_log, mock_set, mock_clear
  ):
    """Test fetch with pagination and filtering."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    page_count = [0]

    def get_page_effect(*args):
      page_count[0] += 1
      if page_count[0] == 1:
        return {
            "results": [{
                "data": [{
                    "id": "1",
                    "sdo_type": "indicator",
                    "sdo_name": "ioc1",
                }]
            }],
            "next": "page2",
        }
      return {"results": [], "next": None}

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000, 2000, 1)
      with patch.object(client, "get_saved_result_set_page") as mock_page:
        mock_page.side_effect = get_page_effect
        with patch.object(
            client, "_extract_indicators_from_page_data"
        ) as mock_extract:
          mock_extract.return_value = [
              {"sdo_name": "ioc1", "ctix_modified": 1500}
          ]
          with patch.object(client, "_filter_indicators") as mock_filter:
            mock_filter.return_value = [{"sdo_name": "ioc1"}]
            with patch.object(
                client, "_enrich_and_ingest_by_chunks"
            ) as mock_ingest:
              mock_ingest.return_value = 1

              client.fetch_indicator_data(1000, 2000)
              self.assertEqual(mock_page.call_count, 2)


class TestGetSavedResultSetPageErrors(unittest.TestCase):
  """Test get_saved_result_set_page error handling."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_get_saved_result_set_page_api_error(self, mock_log):
    """Test API error in get_saved_result_set_page."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    with patch.object(client, "make_api_call") as mock_api:
      mock_api.return_value = {"status": False, "error": "API failed"}

      with self.assertRaises(CywareCTIXException):
        client.get_saved_result_set_page(1000, 2000, 1)


class TestEnrichAndIngestByChunksAdvanced(unittest.TestCase):
  """Test _enrich_and_ingest_by_chunks advanced scenarios."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_enrich_empty_list(self, mock_log):
    """Test enrichment with empty list."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    result = client._enrich_and_ingest_by_chunks([], 1000, 2000, 1)
    self.assertEqual(result, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_enrich_disabled_path(self, mock_log):
    """Test enrichment disabled path."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        enrichment_enabled=False,
    )

    indicators = [{"sdo_name": "ioc1"}]

    with patch.object(client, "_ingest_without_enrichment") as mock_ingest:
      mock_ingest.return_value = 1

      result = client._enrich_and_ingest_by_chunks(indicators, 1000, 2000, 1)
      self.assertEqual(result, 1)
      mock_ingest.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_enrich_with_filtered_indicators(self, mock_log):
    """Test enrichment with filtered indicators."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        enrichment_enabled=True,
    )

    indicators = [
        {"sdo_name": f"ioc{i}", "ctix_modified": 1000 + i} for i in range(5)
    ]

    with patch.object(client, "_filter_indicators") as mock_filter:
      mock_filter.return_value = indicators
      with patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.extract_ioc_values") as mock_extract:
        mock_extract.return_value = [f"ioc{i}" for i in range(5)]
        with patch.object(client, "_process_enrichment_chunk") as mock_process:
          mock_process.return_value = 5

          result = client._enrich_and_ingest_by_chunks(
              indicators, 1000, 2000, 1
          )
          self.assertEqual(result, 5)


class TestProcessEnrichmentChunkExceptionPaths(unittest.TestCase):
  """Test _process_enrichment_chunk exception paths."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_process_enrichment_general_exception(self, mock_log):
    """Test general exception during enrichment."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    indicators = [{"sdo_name": "ioc1"}]

    with patch.object(client, "make_api_call") as mock_api:
      mock_api.side_effect = Exception("Unexpected error")
      with patch.object(client, "_save_error_checkpoint") as mock_save:
        with self.assertRaisesRegex(Exception, "Unexpected error"):
          client._process_enrichment_chunk(0, indicators, 0, 1000, 2000, 1)
        mock_save.assert_called()


class TestMakeApiCallEdgeCases(unittest.TestCase):
  """Test make_api_call edge cases."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_make_api_call_ctix_rest_api_retry(self, mock_log):
    """Test retry from _ctix_rest_api failure."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    call_count = [0]

    def api_side_effect(*args, **kwargs):
      call_count[0] += 1
      if call_count[0] == 1:
        return {"status": False, "retry": True}
      return {"status": True, "response": Mock()}

    with patch.object(client, "_ctix_rest_api") as mock_api:
      with patch.object(client, "_parse_and_handle_response") as mock_parse:
        with patch.object(client, "_log_and_sleep_before_retry") as mock_sleep:
          mock_api.side_effect = api_side_effect
          mock_parse.return_value = {"status": True, "data": {}}

          result = client.make_api_call("GET", "https://example.com/api", {})
          self.assertTrue(result["status"])
          mock_sleep.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_make_api_call_ctix_rest_api_no_retry(self, mock_log):
    """Test early return when _ctix_rest_api fails without retry."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    with patch.object(client, "_ctix_rest_api") as mock_api:
      mock_api.return_value = {"status": False, "retry": False}

      result = client.make_api_call("GET", "https://example.com/api", {})
      self.assertFalse(result["status"])

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_make_api_call_parse_no_retry(self, mock_log):
    """Test when parse returns no retry."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    with patch.object(client, "_ctix_rest_api") as mock_api:
      with patch.object(client, "_parse_and_handle_response") as mock_parse:
        mock_api.return_value = {"status": True, "response": Mock()}
        mock_parse.return_value = {"status": False, "retry": False}

        result = client.make_api_call("GET", "https://example.com/api", {})
        self.assertFalse(result["status"])


class TestCheckpointsValidationEdgeCases(unittest.TestCase):
  """Test _get_checkpoints_and_timestamps edge cases."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_future_from_timestamp(self, mock_log, mock_get):
    """Test future from_timestamp gets reset - covers lines 404-409."""
    # Use a timestamp far in the future (year 3000)
    future_time = 32503680000  # Jan 1, 3000

    mock_get.side_effect = [str(future_time), None, None]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        lookback_days="7",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()
    # Should detect future timestamp and reset it
    self.assertGreater(from_ts, 0)
    self.assertLess(from_ts, future_time)
    # Verify warning was logged about future timestamp
    mock_log.assert_called()
    log_calls_str = " ".join(str(call) for call in mock_log.call_args_list)
    self.assertIn("future", log_calls_str.lower())

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_no_checkpoints_default_path(self, mock_log, mock_get):
    """Test default path when no checkpoints exist."""
    mock_get.return_value = None

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        lookback_days="7",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()
    self.assertGreater(from_ts, 0)
    self.assertGreater(to_ts, 0)
    self.assertEqual(page, 1)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_from_ge_to_timestamp(self, mock_log, mock_time, mock_get, mock_set):
    """Test from_timestamp >= to_timestamp gets corrected."""
    mock_time.return_value = 3000
    mock_get.side_effect = ["2500", "2000", None]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()
    self.assertLess(from_ts, to_ts)
    mock_set.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_valid_page_number_resume(self, mock_log, mock_get):
    """Test resuming with valid positive page number - covers lines 500-504."""
    mock_get.side_effect = ["1000", "2000", "5"]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()
    self.assertEqual(page, 5)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_page_number_non_positive(self, mock_log, mock_get):
    """Test non-positive page number gets reset - covers lines 494-499."""
    mock_get.side_effect = ["1000", "2000", "0"]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()
    self.assertEqual(page, 1)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_page_number_invalid_type(self, mock_log, mock_get):
    """Test invalid page number type - covers lines 505-511."""
    mock_get.side_effect = ["1000", "2000", "not_a_number"]

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()
    self.assertEqual(page, 1)


class TestExtractIndicatorsEdgeCases(unittest.TestCase):
  """Test _extract_indicators_from_page_data edge cases."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_extract_missing_sdo_name(self, mock_log):
    """Test extracting indicators missing sdo_name."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    data = {
        "results": [{
            "data": [
                {
                    "id": "1",
                    "sdo_type": "indicator",
                    "ctix_modified": 1000,
                },
                {
                    "id": "2",
                    "sdo_type": "indicator",
                    "sdo_name": "ioc2",
                    "ctix_modified": 2000,
                },
            ]
        }]
    }

    result = client._extract_indicators_from_page_data(data)
    self.assertEqual(len(result), 1)
    mock_log.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_extract_missing_ctix_modified(self, mock_log):
    """Test extracting indicators missing ctix_modified."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    data = {
        "results": [{
            "data": [
                {
                    "id": "1",
                    "sdo_type": "indicator",
                    "sdo_name": "ioc1",
                },
                {
                    "id": "2",
                    "sdo_type": "indicator",
                    "sdo_name": "ioc2",
                    "ctix_modified": 2000,
                },
            ]
        }]
    }

    result = client._extract_indicators_from_page_data(data)
    self.assertEqual(len(result), 2)


class TestMakeApiCallRetryEdgeCases(unittest.TestCase):
  """Test make_api_call retry edge cases."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_make_api_call_max_retry_from_ctix_api(self, mock_log):
    """Test max retries reached from _ctix_rest_api."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    call_count = [0]

    def api_effect(*args, **kwargs):
      call_count[0] += 1
      if call_count[0] >= constant.RETRY_COUNT:
        return {"status": False, "retry": True}
      return {"status": False, "retry": True}

    with patch.object(client, "_ctix_rest_api") as mock_api:
      with patch.object(client, "_log_and_sleep_before_retry"):
        mock_api.side_effect = api_effect

        result = client.make_api_call("GET", "https://example.com/api", {})
        self.assertFalse(result["status"])


class TestEnrichAndIngestByChunksNoFiltered(unittest.TestCase):
  """Test _enrich_and_ingest_by_chunks with no filtered indicators."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_no_indicators_after_filtering(self, mock_log):
    """Test when all indicators are filtered out."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        enrichment_enabled=True,
    )

    indicators = [{"sdo_name": "ioc1"}]

    with patch.object(client, "_filter_indicators") as mock_filter:
      mock_filter.return_value = []

      result = client._enrich_and_ingest_by_chunks(indicators, 1000, 2000, 1)
      self.assertEqual(result, 0)


class TestFetchIndicatorDataPaginationEdgeCases(unittest.TestCase):
  """Test fetch_indicator_data pagination edge cases."""

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_fetch_empty_page_with_next(self, mock_log, mock_set, mock_clear):
    """Test fetch with empty page but next page exists."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    page_count = [0]

    def page_effect(*args):
      page_count[0] += 1
      if page_count[0] == 1:
        return {"results": [], "next": "page2"}
      return {"results": [], "next": None}

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000, 2000, 1)
      with patch.object(client, "get_saved_result_set_page") as mock_page:
        mock_page.side_effect = page_effect

        client.fetch_indicator_data(1000000, 2000000)
        self.assertEqual(mock_page.call_count, 2)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_fetch_completion_clears_checkpoints(
      self, mock_log, mock_set, mock_clear
  ):
    """Test fetch clears checkpoints on completion."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000, 2000, 1)
      with patch.object(client, "get_saved_result_set_page") as mock_page:
        mock_page.return_value = {"results": [], "next": None}

        client.fetch_indicator_data(1000000, 2000000)
        mock_clear.assert_called()


class TestExtractIOCValuesEdgeCase(unittest.TestCase):
  """Test extract_ioc_values edge case."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_extract_indicators_from_page_data_none(self, mock_log):
    """Test extracting indicators from None data - covers line 547."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    # Call _extract_indicators_from_page_data with None to cover line 547
    result = client._extract_indicators_from_page_data(None)
    self.assertEqual(result, [])


class TestCoverRemainingLines(unittest.TestCase):
  """Tests specifically targeting remaining uncovered lines."""

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_line_244_245_retry_max_from_ctix_api(self, mock_log):
    """Cover lines 244-245: max retry from _ctix_rest_api."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    call_count = [0]

    def api_effect(*args, **kwargs):
      call_count[0] += 1
      return {"status": False, "retry": True}

    with patch.object(client, "_ctix_rest_api") as mock_api:
      with patch.object(client, "_log_and_sleep_before_retry"):
        mock_api.side_effect = api_effect

        result = client.make_api_call("GET", "https://example.com/api", {})
        self.assertFalse(result.get("status", False))
        # Should have hit max retries
        self.assertEqual(call_count[0], constant.RETRY_COUNT)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_line_324_to_363_extract_warnings(self, mock_log):
    """Cover lines 324-330, 333-340, 353, 358, 363: extraction warnings."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    data = {
        "results": [{
            "data": [
                {
                    "id": "1",
                    "sdo_type": "indicator",
                },  # Missing sdo_name
                {
                    "id": "2",
                    "sdo_type": "indicator",
                    "sdo_name": "ioc2",
                },  # Missing ctix_modified
                {
                    "id": "3",
                    "sdo_type": "indicator",
                    "sdo_name": "ioc3",
                    "ctix_modified": 3000,
                },
            ]
        }]
    }

    result = client._extract_indicators_from_page_data(data)
    # Should log warnings for missing fields
    self.assertGreater(mock_log.call_count, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_line_423_no_from_checkpoint(self, mock_log, mock_time, mock_get):
    """Cover line 423: no from_timestamp checkpoint."""
    mock_time.return_value = 2000
    mock_get.return_value = None

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        lookback_days="7",
    )

    from_ts, to_ts, page = client._get_checkpoints_and_timestamps()
    self.assertGreater(from_ts, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_line_530_extract_ioc_values_called(self, mock_log, mock_get):
    """Cover line 530: extract_ioc_values in get_saved_result_set_page."""
    mock_get.return_value = None

    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
    )

    # Call the module-level function, not an instance method
    indicators = [{"sdo_name": "ioc1", "pattern": "test"}]
    result = cyware_client.extract_ioc_values(indicators)
    self.assertEqual(len(result), 1)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_line_1036_1040_general_exception_in_fetch(self, mock_log):
    """Cover lines 1036-1040: general Exception in fetch_indicator_data."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000, 2000, 1)
      with patch.object(client, "get_saved_result_set_page") as mock_page:
        # Trigger a general exception (not RunTimeExceeded or
        # CywareCTIXException)
        mock_page.side_effect = KeyError("Unexpected key error")
        with patch.object(client, "_save_error_checkpoint") as mock_save:
          with self.assertRaises(KeyError):
            client.fetch_indicator_data(1000000, 2000000)
          # Verify error checkpoint was saved
          mock_save.assert_called_once()
          args = mock_save.call_args[0]
          self.assertEqual(args[0], 1000000)
          self.assertEqual(args[1], 2000000)
          self.assertEqual(args[2], 1)


class TestFetchIndicatorsByLabels(unittest.TestCase):
  """Test fetch_indicators_by_labels method."""

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_no_label_provided(self, mock_log, mock_get, mock_set, mock_clear):
    """Test when no label is provided."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name=None,
    )

    client.fetch_indicators_by_labels()

    log_calls = [str(call) for call in mock_log.call_args_list]
    has_warning = any(
        "No saved result set list provided" in str(call) for call in log_calls
    )
    self.assertTrue(has_warning)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_empty_label_after_parsing(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test when label list is empty after parsing."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="   ,  ,  ",
    )

    client.fetch_indicators_by_labels()

    log_calls = [str(call) for call in mock_log.call_args_list]
    has_warning = any(
        "Saved result set list is empty after parsing" in str(call)
        for call in log_calls
    )
    self.assertTrue(has_warning)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_single_label_success(self, mock_log, mock_get, mock_set, mock_clear):
    """Test successful processing of single label."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="test_label",
    )

    mock_get.return_value = None

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000000, 2000000, 1)
      with patch.object(client, "fetch_indicator_data") as mock_fetch:
        mock_fetch.return_value = None

        client.fetch_indicators_by_labels()

        mock_fetch.assert_called_once_with(
            from_timestamp=1000000, to_timestamp=2000000
        )
        mock_set.assert_called()
        mock_clear.assert_called()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_multiple_labels_success(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test successful processing of multiple labels."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="label1,label2,label3",
    )

    mock_get.return_value = None

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000000, 2000000, 1)
      with patch.object(client, "fetch_indicator_data") as mock_fetch:
        mock_fetch.return_value = None

        client.fetch_indicators_by_labels()

        self.assertEqual(mock_fetch.call_count, 3)
        mock_clear.assert_called()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_resume_from_saved_label(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test resuming from saved current label."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="label1,label2,label3",
    )

    def get_checkpoint_side_effect(tenant, bucket, key):
      if key == constant.CHECKPOINT_KEY_LABEL_LIST:
        return "label1,label2,label3"
      elif key == constant.CHECKPOINT_KEY_CURRENT_LABEL:
        return "label2"
      return None

    mock_get.side_effect = get_checkpoint_side_effect

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000000, 2000000, 1)
      with patch.object(client, "fetch_indicator_data") as mock_fetch:
        mock_fetch.return_value = None

        client.fetch_indicators_by_labels()

        # Should process label2 and label3 only
        self.assertEqual(mock_fetch.call_count, 2)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_label_list_changed(self, mock_log, mock_get, mock_set, mock_clear):
    """Test when label list has changed."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="label1,label2",
    )

    def get_checkpoint_side_effect(tenant, bucket, key):
      if key == constant.CHECKPOINT_KEY_LABEL_LIST:
        return "old_label1,old_label2"
      elif key == constant.CHECKPOINT_KEY_CURRENT_LABEL:
        return "old_label1"
      return None

    mock_get.side_effect = get_checkpoint_side_effect

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000000, 2000000, 1)
      with patch.object(client, "fetch_indicator_data") as mock_fetch:
        mock_fetch.return_value = None
        with patch.object(
            client, "_clear_label_error_checkpoints"
        ) as mock_clear_labels:
          client.fetch_indicators_by_labels()

          # Should clear checkpoints and process all new labels
          mock_clear_labels.assert_called()
          self.assertEqual(mock_fetch.call_count, 2)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_saved_label_not_in_new_list(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test when saved current label is not in new list."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="label1,label2",
    )

    def get_checkpoint_side_effect(tenant, bucket, key):
      if key == constant.CHECKPOINT_KEY_LABEL_LIST:
        return "label1,label2"
      elif key == constant.CHECKPOINT_KEY_CURRENT_LABEL:
        return "label3"
      return None

    mock_get.side_effect = get_checkpoint_side_effect

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000000, 2000000, 1)
      with patch.object(client, "fetch_indicator_data") as mock_fetch:
        mock_fetch.return_value = None
        with patch.object(
            client, "_clear_label_error_checkpoints"
        ) as mock_clear_labels:
          client.fetch_indicators_by_labels()

          mock_clear_labels.assert_called()
          self.assertEqual(mock_fetch.call_count, 2)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_runtime_exceeded_during_label_processing(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test RunTimeExceeded exception during label processing."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="label1,label2",
    )

    mock_get.return_value = None

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000000, 2000000, 1)
      with patch.object(client, "fetch_indicator_data") as mock_fetch:
        mock_fetch.side_effect = RunTimeExceeded("Time exceeded")

        with self.assertRaises(RunTimeExceeded):
          client.fetch_indicators_by_labels()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_general_exception_during_label_processing(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test general exception during label processing."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="label1,label2",
    )

    mock_get.return_value = None

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000000, 2000000, 1)
      with patch.object(client, "fetch_indicator_data") as mock_fetch:
        mock_fetch.side_effect = ValueError("Test error")

        with self.assertRaisesRegex(ValueError, "Test error"):
          client.fetch_indicators_by_labels()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_no_saved_current_label(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test when saved_label_list matches but saved_current_label is None."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
        label_name="label1,label2",
    )

    def get_checkpoint_side_effect(tenant, bucket, key):
      if key == constant.CHECKPOINT_KEY_LABEL_LIST:
        return "label1,label2"
      elif key == constant.CHECKPOINT_KEY_CURRENT_LABEL:
        return None
      return None

    mock_get.side_effect = get_checkpoint_side_effect

    with patch.object(client, "_get_checkpoints_and_timestamps") as mock_ckpt:
      mock_ckpt.return_value = (1000000, 2000000, 1)
      with patch.object(client, "fetch_indicator_data") as mock_fetch:
        mock_fetch.return_value = None
        with patch.object(
            client, "_clear_label_error_checkpoints"
        ) as mock_clear_labels:
          client.fetch_indicators_by_labels()

          # Should continue without clearing checkpoints and process all labels
          mock_clear_labels.assert_not_called()
          self.assertEqual(mock_fetch.call_count, 2)

          log_calls = [str(call) for call in mock_log.call_args_list]
          has_resume_log = any(
              "Resuming ingestion from label" in str(call)
              and "label1" in str(call)
              for call in log_calls
          )
          self.assertTrue(has_resume_log)


class TestClearLabelErrorCheckpoints(unittest.TestCase):
  """Test _clear_label_error_checkpoints method."""

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_clear_label_error_checkpoints(self, mock_log, mock_clear):
    """Test clearing label error checkpoints."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    client._clear_label_error_checkpoints()

    # Should clear 6 checkpoints: label_list, current_label, from_timestamp, to_timestamp, ctix_modified, page_number
    self.assertEqual(mock_clear.call_count, 6)
    calls = mock_clear.call_args_list
    # Verify all checkpoints are cleared
    checkpoint_keys = [call[0][0] for call in calls]
    self.assertIn(constant.CHECKPOINT_KEY_LABEL_LIST, checkpoint_keys)
    self.assertIn(constant.CHECKPOINT_KEY_CURRENT_LABEL, checkpoint_keys)
    self.assertIn(constant.CHECKPOINT_KEY_FROM_TIMESTAMP, checkpoint_keys)
    self.assertIn(constant.CHECKPOINT_KEY_TO_TIMESTAMP, checkpoint_keys)
    self.assertIn(constant.CHECKPOINT_KEY_CTIX_MODIFIED, checkpoint_keys)
    self.assertIn(constant.CHECKPOINT_KEY_PAGE_NUMBER, checkpoint_keys)


class TestFetchIndicatorDataPageResume(unittest.TestCase):
  """Test fetch_indicator_data page resume logic."""

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_resume_from_saved_page(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test resuming from saved page number."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    mock_get.return_value = "5"

    with patch.object(client, "get_saved_result_set_page") as mock_page:
      mock_page.return_value = {"results": [], "next": None}

      client.fetch_indicator_data(1000000, 2000000)

      # Should start from page 5
      mock_page.assert_called_with(1000000, 2000000, 5)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.clear_checkpoint_if_exists"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyware_client.utils.cloud_logging")
  def test_invalid_page_number_defaults_to_1(
      self, mock_log, mock_get, mock_set, mock_clear
  ):
    """Test invalid page number defaults to 1."""
    client = cyware_client.CTIXClient(
        base_url="https://example.com",
        access_id="id",
        secret_key="key",
        tenant_name="tenant",
        bucket_name="bucket",
    )

    mock_get.return_value = "invalid"

    with patch.object(client, "get_saved_result_set_page") as mock_page:
      mock_page.return_value = {"results": [], "next": None}

      client.fetch_indicator_data(1000000, 2000000)

      # Should start from page 1
      mock_page.assert_called_with(1000000, 2000000, 1)


if __name__ == "__main__":
  unittest.main()
