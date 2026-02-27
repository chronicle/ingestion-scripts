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
# pylint: disable=redefined-outer-name
# pylint: disable=g-docstring-first-line-too-long
# pylint: disable=g-generic-assert

"""Unit tests for main module."""

import unittest
from unittest import mock
from datetime import timedelta
import sys

# Create proper mock structure for google modules before importing main
mock_google = mock.MagicMock()
mock_cloud = mock.MagicMock()
mock_storage = mock.MagicMock()
mock_resourcemanager = mock.MagicMock()
mock_exceptions = mock.MagicMock()
mock_auth = mock.MagicMock()
mock_auth_transport = mock.MagicMock()

mock_google.cloud = mock_cloud
mock_google.auth = mock_auth
mock_auth.transport = mock_auth_transport
mock_auth_transport.requests = mock.MagicMock()
mock_cloud.storage = mock_storage
mock_cloud.resourcemanager_v3 = mock_resourcemanager
mock_cloud.exceptions = mock_exceptions
mock_storage.Client = mock.MagicMock()

sys.modules["google"] = mock_google
sys.modules["google.cloud"] = mock_cloud
sys.modules["google.cloud.storage"] = mock_storage
sys.modules["google.cloud.resourcemanager_v3"] = mock_resourcemanager
sys.modules["google.cloud.exceptions"] = mock_exceptions
sys.modules["google.auth"] = mock_auth
sys.modules["google.auth.transport"] = mock_auth_transport
sys.modules["google.auth.transport.requests"] = mock_auth_transport.requests

# Set up google.oauth2 mock
mock_oauth2 = mock.MagicMock()
mock_google.oauth2 = mock_oauth2
sys.modules["google.oauth2"] = mock_oauth2
sys.modules["google.oauth2.service_account"] = mock.MagicMock()

# Mock greynoise SDK
mock_greynoise = mock.MagicMock()
mock_greynoise_api = mock.MagicMock()
mock_greynoise.api = mock_greynoise_api
sys.modules["greynoise"] = mock_greynoise
sys.modules["greynoise.api"] = mock_greynoise_api

# Mock other dependencies
sys.modules["secops"] = mock.MagicMock()
sys.modules["flask"] = mock.MagicMock()


# Mock common module to avoid environment variable checks during import
mock_common = mock.MagicMock()
mock_ingest_v1 = mock.MagicMock()
mock_utils = mock.MagicMock()
mock_env_constants = mock.MagicMock()

mock_common.ingest_v1 = mock_ingest_v1
mock_common.utils = mock_utils
mock_common.env_constants = mock_env_constants

INGESTION_SCRIPTS_PATH = ""
sys.modules["common"] = mock_common
sys.modules["common.ingest_v1"] = mock_ingest_v1
sys.modules["common.utils"] = mock_utils
sys.modules["common.env_constants"] = mock_env_constants

from datetime import datetime, timezone

from common import ingest_v1
from common import utils

import main
import constant
import utility
import greynoise_client
from exception_handler import LiveInvestigationError
from exception_handler import GCPPermissionDeniedError


class TestAddSevenDays(unittest.TestCase):
  """Test cases for add_seven_days function."""

  def test_date_only_format(self):
    """Test YYYY-MM-DD format (primary format per GreyNoise docs)."""
    result = main.add_seven_days("2025-11-19")
    self.assertEqual(result, "2025-11-26T00:00:00Z")

  def test_iso_format_with_z(self):
    """Test YYYY-MM-DDTHH:MM:SSZ format."""
    result = main.add_seven_days("2025-12-03T02:19:00Z")
    self.assertEqual(result, "2025-12-10T02:19:00Z")

  def test_iso_format_with_microseconds(self):
    """Test YYYY-MM-DDTHH:MM:SS.ffffffZ format."""
    result = main.add_seven_days("2025-11-19T13:00:27.123456Z")
    self.assertEqual(result, "2025-11-26T13:00:27Z")

  def test_datetime_with_space(self):
    """Test YYYY-MM-DD HH:MM:SS format."""
    result = main.add_seven_days("2025-11-19 13:00:27")
    self.assertEqual(result, "2025-11-26T13:00:27Z")

  def test_datetime_with_space_and_microseconds(self):
    """Test YYYY-MM-DD HH:MM:SS.ffffff format."""
    result = main.add_seven_days("2025-12-09 16:10:22.948129")
    self.assertEqual(result, "2025-12-16T16:10:22Z")

  def test_whitespace_handling(self):
    """Test that leading/trailing whitespace is stripped."""
    result = main.add_seven_days("  2025-11-19  ")
    self.assertEqual(result, "2025-11-26T00:00:00Z")

  def test_empty_string_raises_error(self):
    """Test that empty string raises ValueError."""
    with self.assertRaisesRegex(ValueError, "Empty date string"):
      main.add_seven_days("")

  def test_whitespace_only_raises_error(self):
    """Test that whitespace-only string raises ValueError."""
    with self.assertRaisesRegex(ValueError, "Empty date string"):
      main.add_seven_days("   ")

  def test_unsupported_format_raises_error(self):
    """Test that unsupported format raises ValueError."""
    with self.assertRaisesRegex(ValueError, "Unsupported date format"):
      main.add_seven_days("19-11-2025")

  def test_invalid_date_raises_error(self):
    """Test that invalid date string raises ValueError."""
    with self.assertRaisesRegex(ValueError, "Unsupported date format"):
      main.add_seven_days("not-a-date")

  def test_month_boundary_crossing(self):
    """Test date addition across month boundary."""
    result = main.add_seven_days("2025-11-28")
    self.assertEqual(result, "2025-12-05T00:00:00Z")

  def test_year_boundary_crossing(self):
    """Test date addition across year boundary."""
    result = main.add_seven_days("2025-12-28")
    self.assertEqual(result, "2026-01-04T00:00:00Z")


class TestCreateEndTime(unittest.TestCase):
  """Test cases for create_end_time function."""

  def test_uses_last_seen_timestamp_first(self):
    """Test that last_seen_timestamp is used when available."""
    item = {
        "internet_scanner_intelligence": {
            "last_seen": "2025-11-19",
            "last_seen_timestamp": "2025-11-19T13:00:27Z",
        }
    }
    main.create_end_time(item)
    self.assertEqual(
        item[constant.END_TIME_FIELD_NAME], "2025-11-26T13:00:27Z"
    )

  def test_falls_back_to_last_seen(self):
    """Test fallback to last_seen when last_seen_timestamp is missing."""
    item = {"internet_scanner_intelligence": {"last_seen": "2025-11-19"}}
    main.create_end_time(item)
    self.assertEqual(
        item[constant.END_TIME_FIELD_NAME], "2025-11-26T00:00:00Z"
    )

  def test_falls_back_to_last_seen_on_invalid_timestamp(self):
    """Test fallback to last_seen when last_seen_timestamp is invalid."""
    item = {
        "internet_scanner_intelligence": {
            "last_seen": "2025-11-19",
            "last_seen_timestamp": "invalid-timestamp",
        }
    }
    main.create_end_time(item)
    self.assertEqual(
        item[constant.END_TIME_FIELD_NAME], "2025-11-26T00:00:00Z"
    )

  def test_falls_back_to_current_time_no_internet_data(self):
    """Test fallback to current time when no internet data."""
    item = {"business_service_intelligence": {"found": True}}
    main.create_end_time(item)
    self.assertIn(constant.END_TIME_FIELD_NAME, item)
    # Verify it's a valid ISO format
    self.assertRegex(
        item[constant.END_TIME_FIELD_NAME],
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
    )

  def test_falls_back_to_current_time_empty_internet_data(self):
    """Test fallback to current time when internet data is empty."""
    item = {"internet_scanner_intelligence": {}}
    main.create_end_time(item)
    self.assertIn(constant.END_TIME_FIELD_NAME, item)
    self.assertRegex(
        item[constant.END_TIME_FIELD_NAME],
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
    )

  def test_falls_back_to_current_time_all_invalid(self):
    """Test fallback to current time when both timestamps are invalid."""
    item = {
        "internet_scanner_intelligence": {
            "last_seen": "invalid-date",
            "last_seen_timestamp": "also-invalid",
        }
    }
    main.create_end_time(item)
    self.assertIn(constant.END_TIME_FIELD_NAME, item)
    self.assertRegex(
        item[constant.END_TIME_FIELD_NAME],
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
    )

  def test_modifies_item_in_place(self):
    """Test that the function modifies the item dict in place."""
    item = {
        "ip": "1.2.3.4",
        "internet_scanner_intelligence": {
            "last_seen_timestamp": "2025-11-19T13:00:27Z"
        },
    }
    result = main.create_end_time(item)
    # Function returns None
    self.assertIsNone(result)
    # But item is modified
    self.assertIn(constant.END_TIME_FIELD_NAME, item)
    self.assertEqual(item["ip"], "1.2.3.4")  # Original data preserved

  def test_empty_item(self):
    """Test with empty item dict."""
    item = {}
    main.create_end_time(item)
    self.assertIn(constant.END_TIME_FIELD_NAME, item)
    self.assertRegex(
        item[constant.END_TIME_FIELD_NAME],
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
    )


class TestParseLastSeenWindow(unittest.TestCase):
  """Test cases for _parse_last_seen_window function."""

  def test_parse_days(self):
    """Test parsing days from query."""
    query = "classification:malicious last_seen:7d"
    base, days = main._parse_last_seen_window(query)
    self.assertEqual(base, "classification:malicious")
    self.assertEqual(days, 7)

  def test_parse_weeks(self):
    """Test parsing weeks from query."""
    query = "last_seen:2w"
    base, days = main._parse_last_seen_window(query)
    self.assertEqual(base, "")
    self.assertEqual(days, 14)

  def test_parse_months(self):
    """Test parsing months from query."""
    query = "last_seen:3m tags:scanner"
    base, days = main._parse_last_seen_window(query)
    self.assertEqual(base, "tags:scanner")
    self.assertEqual(days, 90)

  def test_parse_years(self):
    """Test parsing years from query."""
    query = "last_seen:1y"
    base, days = main._parse_last_seen_window(query)
    self.assertEqual(base, "")
    self.assertEqual(days, 365)

  def test_no_time_window(self):
    """Test query without time window."""
    query = "classification:malicious"
    base, days = main._parse_last_seen_window(query)
    self.assertEqual(base, query)
    self.assertIsNone(days)


class TestBuildLastSeenClause(unittest.TestCase):
  """Test cases for _build_last_seen_clause function."""

  def test_build_clause(self):
    """Test building last seen clause."""
    self.assertEqual(main._build_last_seen_clause(0), "last_seen:1d")
    self.assertEqual(main._build_last_seen_clause(1), "last_seen:1d")
    self.assertEqual(main._build_last_seen_clause(7), "last_seen:7d")


class TestComputeDynamicWindowDays(unittest.TestCase):
  """Test cases for _compute_dynamic_window_days function."""

  def test_compute_window_no_configured_days(self):
    """Case 1: No configured days should return None."""
    self.assertIsNone(main._compute_dynamic_window_days(None))

  @mock.patch.object(utility, "load_state_from_gcs")
  def test_compute_window_no_state(self, mock_load):
    """Case 2: Missing state should return the configured fallback."""
    mock_load.return_value = None
    self.assertEqual(main._compute_dynamic_window_days(30), 30)

  @mock.patch.object(utility, "load_state_from_gcs")
  def test_compute_window_with_valid_state(self, mock_load):
    """Case 3: Valid state yields a reduced window based on last_seen_time."""
    past_time = datetime.now(timezone.utc) - timedelta(days=5)
    mock_load.return_value = {"last_seen_time": past_time.isoformat()}
    result = main._compute_dynamic_window_days(30)
    self.assertTrue(
        5 <= result <= 6
    )  # Allow for slight time diff  # pylint: disable=g-generic-assert

  @mock.patch.object(utility, "load_state_from_gcs")
  def test_compute_window_error_loading_state(self, mock_load):
    """Case 4: Errors while loading state should fall back to configured days."""
    mock_load.side_effect = Exception("Error")
    self.assertEqual(main._compute_dynamic_window_days(30), 30)

  @mock.patch.object(utility, "load_state_from_gcs")
  def test_no_last_seen_in_state(self, mock_load):
    """Test when state exists but no last_seen_time (line 297)."""
    mock_load.return_value = {"other_key": "value"}
    result = main._compute_dynamic_window_days(30)
    self.assertEqual(result, 30)

  @mock.patch.object(utility, "load_state_from_gcs")
  def test_naive_datetime_handling(self, mock_load):
    """Test naive datetime is assumed UTC (lines 302-303)."""
    # Naive datetime without timezone
    mock_load.return_value = {"last_seen_time": "2024-01-01T00:00:00"}
    result = main._compute_dynamic_window_days(365)
    self.assertIsNotNone(result)

  @mock.patch.object(utility, "load_state_from_gcs")
  def test_invalid_timestamp_format(self, mock_load):
    """Test invalid timestamp format (lines 303-309)."""
    mock_load.return_value = {"last_seen_time": "invalid-timestamp"}
    result = main._compute_dynamic_window_days(30)
    self.assertEqual(result, 30)

  @mock.patch.object(utility, "load_state_from_gcs")
  def test_future_timestamp_returns_one(self, mock_load):
    """Test future timestamp returns 1 day (line 313)."""
    future_time = datetime.now(timezone.utc) + timedelta(days=400)
    mock_load.return_value = {"last_seen_time": future_time.isoformat()}
    result = main._compute_dynamic_window_days(30)
    self.assertEqual(result, 1)


class TestGenerateGNQLQuery(unittest.TestCase):
  """Test cases for generate_gnql_query function."""

  def test_generate_query(self):
    """Test generating GNQL query."""
    # Empty query
    q, custom = main.generate_gnql_query("")
    self.assertEqual(q, constant.DEFAULT_TIME_QUERY)
    self.assertFalse(custom)

    # Query with time filter
    q, custom = main.generate_gnql_query("last_seen:1d")
    self.assertEqual(q, "last_seen:1d")
    self.assertTrue(custom)

    # Query without time filter
    q, custom = main.generate_gnql_query("classification:malicious")
    self.assertIn(constant.DEFAULT_TIME_QUERY, q)
    self.assertTrue(custom)


class TestValidateLiveInvestigationInputs(unittest.TestCase):
  """Test cases for validate_live_investigation_inputs function."""

  def test_valid_inputs(self):
    """Test valid inputs."""
    args = {"query": "test", "datatable_name": "table"}
    q, t = main.validate_live_investigation_inputs(args)
    self.assertIn("test", q)
    self.assertEqual(t, "table")

  def test_invalid_inputs(self):
    """Test invalid inputs."""
    # None input
    with self.assertRaises(LiveInvestigationError):
      main.validate_live_investigation_inputs(None)

    # Missing both fields
    with self.assertRaises(LiveInvestigationError):
      main.validate_live_investigation_inputs({})


class TestValidateIpList(unittest.TestCase):
  """Test cases for validate_ip_list function."""

  def test_validate_ips(self):
    """Test IP validation."""
    # Valid list
    ips = ["1.2.3.4", "invalid", "5.6.7.8"]
    valid = main.validate_ip_list(ips)
    self.assertEqual(len(valid), 2)
    self.assertIn("1.2.3.4", valid)
    self.assertIn("5.6.7.8", valid)

    # Invalid input
    with self.assertRaises(ValueError):
      main.validate_ip_list(None)
    with self.assertRaises(ValueError):
      main.validate_ip_list("not-a-list")


class TestGetRunGnqlQuery(unittest.TestCase):
  """Test cases for get_run_gnql_query function."""

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  @mock.patch.object(utility, "save_state_to_gcs")
  def test_successful_query(self, mock_save, mock_load, mock_ingest):
    """Test successful query execution."""
    mock_load.return_value = None
    mock_client = mock.Mock()
    mock_client.gnql_query.side_effect = [
        {
            "data": [
                {
                    "ip": "1.2.3.4",
                    "internet_scanner_intelligence": {
                        "found": True,
                        "last_seen_timestamp": "2024-01-02T00:00:00Z",
                    },
                }
            ],
            "request_metadata": {"complete": True},
        }
    ]

    main.get_run_gnql_query("query", mock_client)

    mock_ingest.assert_called_once()
    mock_save.assert_called_once()

  @mock.patch.object(ingest_v1, "ingest")
  def test_empty_response(self, mock_ingest):
    """Test empty response - ingest is called with empty list."""
    mock_client = mock.Mock()
    mock_client.gnql_query.return_value = {
        "request_metadata": {"message": "no results"}
    }

    main.get_run_gnql_query("query", mock_client, default_ingestion=False)
    # Ingest is called with empty list when no results
    mock_ingest.assert_called_once_with([], "GREYNOISE")

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  def test_checkpoint_load_error_raises(self, mock_load, mock_ingest):
    """Test that checkpoint load error is raised (lines 55-64)."""
    mock_load.side_effect = Exception("GCS error")
    mock_client = mock.Mock()

    with self.assertRaises(Exception) as ctx:
      main.get_run_gnql_query(
          "query", mock_client, default_ingestion=True
      )
    self.assertIn("GCS error", str(ctx.exception))

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  @mock.patch.object(utility, "save_state_to_gcs")
  def test_skip_already_processed_items(
      self, mock_save, mock_load, mock_ingest
  ):
    """Test skipping items already processed (lines 102-109)."""
    mock_load.return_value = {"last_seen_time": "2024-01-15T00:00:00Z"}
    mock_client = mock.Mock()
    mock_client.gnql_query.return_value = {
        "data": [
            {
                "ip": "1.2.3.4",
                "internet_scanner_intelligence": {
                    "found": True,
                    "last_seen_timestamp": "2024-01-10T00:00:00Z",
                },
            },
            {
                "ip": "5.6.7.8",
                "internet_scanner_intelligence": {
                    "found": True,
                    "last_seen_timestamp": "2024-01-20T00:00:00Z",
                },
            },
        ],
        "request_metadata": {"complete": True},
    }

    main.get_run_gnql_query("query", mock_client, default_ingestion=True)

    # Only the newer item should be ingested
    call_args = mock_ingest.call_args[0][0]
    self.assertEqual(len(call_args), 1)
    self.assertEqual(call_args[0]["ip"], "5.6.7.8")

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  @mock.patch.object(utility, "save_state_to_gcs")
  def test_raw_data_removal(self, mock_save, mock_load, mock_ingest):
    """Test raw_data is removed from internet_scanner (line 125)."""
    mock_load.return_value = None
    mock_client = mock.Mock()
    mock_client.gnql_query.return_value = {
        "data": [
            {
                "ip": "1.2.3.4",
                "internet_scanner_intelligence": {
                    "found": True,
                    "last_seen_timestamp": "2024-01-02T00:00:00Z",
                    "raw_data": {"should": "be removed"},
                },
            }
        ],
        "request_metadata": {"complete": True},
    }

    main.get_run_gnql_query("query", mock_client)

    call_args = mock_ingest.call_args[0][0]
    self.assertNotIn(
        "raw_data", call_args[0]["internet_scanner_intelligence"]
    )

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  def test_no_request_metadata_breaks_loop(self, mock_load, mock_ingest):
    """Test response without request_metadata breaks loop."""
    mock_load.return_value = None
    mock_client = mock.Mock()
    # Response with request_metadata but no data triggers else branch
    mock_client.gnql_query.return_value = {
        "request_metadata": {"message": "no results", "adjusted_query": "q"}
    }

    main.get_run_gnql_query("query", mock_client, default_ingestion=False)
    # The else branch breaks without calling ingest for that iteration
    # but ingest is called with empty filtered_data
    mock_ingest.assert_called()

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  @mock.patch.object(utility, "save_state_to_gcs")
  def test_checkpoint_save_error(self, mock_save, mock_load, mock_ingest):
    """Test checkpoint save error is logged (lines 172-173)."""
    mock_load.return_value = None
    mock_save.side_effect = Exception("Save failed")
    mock_client = mock.Mock()
    mock_client.gnql_query.return_value = {
        "data": [
            {
                "ip": "1.2.3.4",
                "internet_scanner_intelligence": {
                    "found": True,
                    "last_seen_timestamp": "2024-01-02T00:00:00Z",
                },
            }
        ],
        "request_metadata": {"complete": True},
    }

    # Should not raise, just log the error
    main.get_run_gnql_query("query", mock_client)
    mock_save.assert_called_once()

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  @mock.patch.object(utility, "save_state_to_gcs")
  def test_skipped_indicators_logging(
      self, mock_save, mock_load, mock_ingest
  ):
    """Test skipped indicators are logged (lines 185-186)."""
    mock_load.return_value = {"last_seen_time": "2024-01-15T00:00:00Z"}
    mock_client = mock.Mock()
    mock_client.gnql_query.return_value = {
        "data": [
            {
                "ip": "1.2.3.4",
                "internet_scanner_intelligence": {
                    "found": True,
                    "last_seen_timestamp": "2024-01-10T00:00:00Z",
                },
            }
        ],
        "request_metadata": {"complete": True},
    }

    # All items skipped
    main.get_run_gnql_query("query", mock_client, default_ingestion=True)
    # Verify ingest was called with empty list
    call_args = mock_ingest.call_args[0][0]
    self.assertEqual(len(call_args), 0)

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  @mock.patch.object(utility, "save_state_to_gcs")
  def test_checkpoint_not_updated_when_no_new_data(
      self, mock_save, mock_load, mock_ingest
  ):
    """Test checkpoint not updated when max_last_seen <= cutoff."""
    mock_load.return_value = {"last_seen_time": "2024-01-20T00:00:00Z"}
    mock_client = mock.Mock()
    mock_client.gnql_query.return_value = {
        "data": [
            {
                "ip": "1.2.3.4",
                "internet_scanner_intelligence": {
                    "found": True,
                    "last_seen_timestamp": "2024-01-10T00:00:00Z",
                },
            }
        ],
        "request_metadata": {"complete": True},
    }

    main.get_run_gnql_query("query", mock_client, default_ingestion=True)
    # Checkpoint should not be saved since all items were skipped
    mock_save.assert_not_called()

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  def test_response_no_data_key(self, mock_load, mock_ingest):
    """Test response with request_metadata but no data."""
    mock_load.return_value = None
    mock_client = mock.Mock()
    # Response has request_metadata but no 'data' key
    mock_client.gnql_query.return_value = {
        "request_metadata": {
            "message": "Query returned no results",
            "adjusted_query": "test query",
        }
    }

    main.get_run_gnql_query("query", mock_client, default_ingestion=False)
    # Should process empty data list and call ingest
    mock_ingest.assert_called()

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  def test_response_no_request_metadata(self, mock_load, mock_ingest):
    """Test response without request_metadata key (lines 135-146)."""
    mock_load.return_value = None
    mock_client = mock.Mock()
    # Response has NO request_metadata key - triggers else branch
    mock_client.gnql_query.return_value = {
        "error": "some error",
        "other_field": "value",
    }

    main.get_run_gnql_query("query", mock_client, default_ingestion=False)
    # Should break out of loop without calling ingest
    mock_ingest.assert_not_called()

  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  def test_processing_failure_warning(self, mock_load, mock_ingest):
    """Test processing failure warning (line 177)."""
    mock_load.return_value = None
    mock_client = mock.Mock()
    # Simulate an exception during processing
    mock_client.gnql_query.side_effect = Exception("Processing error")

    with self.assertRaises(Exception):
      main.get_run_gnql_query(
          "query", mock_client, default_ingestion=True
      )

  @mock.patch.object(ingest_v1, "ingest")
  def test_live_investigation_field_added(self, mock_ingest):
    """Test is_live_investigation field is added when flag is True."""
    mock_client = mock.Mock()
    mock_client.gnql_query.return_value = {
        "data": [
            {
                "ip": "1.2.3.4",
                "internet_scanner_intelligence": {
                    "found": True,
                    "last_seen_timestamp": "2024-01-02T00:00:00Z",
                },
            }
        ],
        "request_metadata": {"complete": True},
    }

    main.get_run_gnql_query(
        "query",
        mock_client,
        default_ingestion=False,
        is_live_investigation=True,
    )

    call_args = mock_ingest.call_args[0][0]
    self.assertTrue(
        call_args[0].get(constant.LIVE_INVESTIGATION_FIELD_NAME)
    )

  @mock.patch.object(ingest_v1, "ingest")
  def test_live_investigation_field_not_added_when_false(self, mock_ingest):
    """Test is_live_investigation field is NOT added when flag is False."""
    mock_client = mock.Mock()
    mock_client.gnql_query.return_value = {
        "data": [
            {
                "ip": "1.2.3.4",
                "internet_scanner_intelligence": {
                    "found": True,
                    "last_seen_timestamp": "2024-01-02T00:00:00Z",
                },
            }
        ],
        "request_metadata": {"complete": True},
    }

    main.get_run_gnql_query(
        "query",
        mock_client,
        default_ingestion=False,
        is_live_investigation=False,
    )

    call_args = mock_ingest.call_args[0][0]
    self.assertNotIn(constant.LIVE_INVESTIGATION_FIELD_NAME, call_args[0])

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(ingest_v1, "ingest")
  @mock.patch.object(utility, "load_state_from_gcs")
  @mock.patch.object(utility, "save_state_to_gcs")
  def test_query_exception_does_not_save_checkpoint(
      self, mock_save, mock_load, mock_ingest, mock_cloud_logging
  ):
    """Test that checkpoint is not saved if gnql_query raises exception."""
    mock_load.return_value = None
    mock_client = mock.Mock()
    mock_client.gnql_query.side_effect = Exception("API error")

    with self.assertRaises(Exception) as ctx:
      main.get_run_gnql_query(
          "query", mock_client, default_ingestion=True
      )

    self.assertIn("API error", str(ctx.exception))
    mock_ingest.assert_not_called()
    mock_save.assert_not_called()
    mock_cloud_logging.assert_any_call(
        "Processing failed - checkpoint NOT updated to prevent data loss",
        severity="WARNING",
    )


class TestLookupIpsAndIngest(unittest.TestCase):
  """Test cases for lookup_ips_and_ingest function."""

  @mock.patch.object(ingest_v1, "ingest")
  def test_lookup_and_ingest(self, mock_ingest):
    """Test lookup and ingest."""
    mock_client = mock.Mock()
    mock_client.lookup_ips.return_value = [
        {"ip": "1.2.3.4", "internet_scanner_intelligence": {"found": True}},
        {
            "ip": "5.6.7.8",
            "internet_scanner_intelligence": {"found": False},
            "business_service_intelligence": {"found": False},
        },
    ]

    main.lookup_ips_and_ingest(["1.2.3.4", "5.6.7.8"], mock_client)

    # Should only ingest the found IP
    mock_ingest.assert_called_once()
    call_args = mock_ingest.call_args
    ingested_data = call_args[0][0]
    self.assertEqual(len(ingested_data), 1)
    self.assertEqual(ingested_data[0]["ip"], "1.2.3.4")

  @mock.patch.object(ingest_v1, "ingest")
  def test_lookup_raw_data_removal(self, mock_ingest):
    """Test raw_data is removed in lookup (line 215)."""
    mock_client = mock.Mock()
    mock_client.lookup_ips.return_value = [
        {
            "ip": "1.2.3.4",
            "internet_scanner_intelligence": {
                "found": True,
                "raw_data": {"should": "be removed"},
            },
        }
    ]

    main.lookup_ips_and_ingest(["1.2.3.4"], mock_client)

    call_args = mock_ingest.call_args[0][0]
    scanner = call_args[0]["internet_scanner_intelligence"]
    self.assertNotIn("raw_data", scanner)

  @mock.patch.object(ingest_v1, "ingest")
  def test_live_investigation_field_added_in_lookup(self, mock_ingest):
    """Test is_live_investigation is added in lookup_ips_and_ingest."""
    mock_client = mock.Mock()
    mock_client.lookup_ips.return_value = [
        {"ip": "1.2.3.4", "internet_scanner_intelligence": {"found": True}}
    ]

    main.lookup_ips_and_ingest(["1.2.3.4"], mock_client)

    call_args = mock_ingest.call_args[0][0]
    self.assertTrue(
        call_args[0].get(constant.LIVE_INVESTIGATION_FIELD_NAME)
    )


class TestLiveInvestigation(unittest.TestCase):
  """Test cases for live_investigation function."""

  @mock.patch.object(main, "get_run_gnql_query")
  @mock.patch.object(main, "lookup_ips_and_ingest")
  @mock.patch.object(main, "get_ip_list_from_datatable")
  @mock.patch.object(main, "validate_ip_list")
  def test_investigation_flows(
      self, mock_validate, mock_get_ips, mock_lookup, mock_query
  ):
    """Test different investigation flows."""
    mock_client = mock.Mock()
    mock_validate.return_value = ["1.2.3.4"]

    # 1. Query only
    main.live_investigation("query", None, mock_client)
    mock_query.assert_called()

    # 2. Datatable only
    main.live_investigation(None, "table", mock_client)
    mock_lookup.assert_called()

    # 3. Both
    main.live_investigation("query", "table", mock_client)
    # Should query for each IP
    self.assertEqual(
        mock_query.call_count, 2
    )  # 1 from first call + 1 from this

  @mock.patch.object(main, "get_run_gnql_query")
  def test_live_investigation_passes_flag(self, mock_query):
    """Test live_investigation passes is_live_investigation=True."""
    mock_client = mock.Mock()

    # Query only path
    main.live_investigation("query", None, mock_client)
    mock_query.assert_called_with(
        "query",
        mock_client,
        default_ingestion=False,
        is_live_investigation=True,
    )

  @mock.patch.object(main, "get_run_gnql_query")
  @mock.patch.object(main, "get_ip_list_from_datatable")
  @mock.patch.object(main, "validate_ip_list")
  def test_live_investigation_with_datatable_passes_flag(
      self, mock_validate, mock_get_ips, mock_query
  ):
    """Test live_investigation with datatable passes is_live_investigation."""
    mock_client = mock.Mock()
    mock_validate.return_value = ["1.2.3.4"]

    main.live_investigation("query", "table", mock_client)
    mock_query.assert_called_with(
        "query ip:1.2.3.4",
        mock_client,
        default_ingestion=False,
        is_live_investigation=True,
    )


class TestGetIpListFromDatatable(unittest.TestCase):
  """Test cases for get_ip_list_from_datatable function."""

  @mock.patch("secops.SecOpsClient")
  @mock.patch.object(ingest_v1, "CUSTOMER_ID", "test_customer")
  @mock.patch.object(ingest_v1, "PROJECT_ID", "test_project")
  @mock.patch.object(ingest_v1, "REGION", "test_region")
  def test_get_ip_list(self, mock_secops_cls):
    """Test getting IP list from datatable (lines 415-429)."""
    mock_client = mock.Mock()
    mock_secops_cls.return_value = mock_client
    mock_chronicle = mock.Mock()
    mock_client.chronicle.return_value = mock_chronicle
    mock_chronicle.list_data_table_rows.return_value = [
        {"values": ["1.2.3.4", "5.6.7.8"]},
        {"values": ["9.10.11.12"]},
    ]

    result = main.get_ip_list_from_datatable("test_table")

    self.assertEqual(len(result), 3)
    self.assertIn("1.2.3.4", result)
    self.assertIn("5.6.7.8", result)
    self.assertIn("9.10.11.12", result)
    mock_chronicle.list_data_table_rows.assert_called_with("test_table")


class TestMain(unittest.TestCase):
  """Test cases for main function."""

  @mock.patch.object(
      utility, "check_sufficient_permissions_on_service_account"
  )
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(main, "get_run_gnql_query")
  @mock.patch.object(greynoise_client, "GreyNoiseUtility")
  def test_scheduler_execution(
      self, mock_cls, mock_query, mock_env, mock_perms
  ):
    """Test execution via scheduler."""
    mock_request = mock.Mock()
    mock_request.headers = {constant.SCHEDULER_HEADER_KEY: "true"}
    mock_env.return_value = "test_key"

    msg, code = main.main(mock_request)

    self.assertEqual(code, 200)
    mock_query.assert_called()

  @mock.patch.object(
      utility, "check_sufficient_permissions_on_service_account"
  )
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(main, "live_investigation")
  @mock.patch.object(greynoise_client, "GreyNoiseUtility")
  def test_live_investigation_execution(
      self, mock_cls, mock_live, mock_env, mock_perms
  ):
    """Test execution via live investigation."""
    mock_request = mock.Mock()
    mock_request.headers = {}
    mock_request.get_json.return_value = {"query": "test"}
    mock_env.return_value = "test_key"

    msg, code = main.main(mock_request)

    self.assertEqual(code, 200)
    mock_live.assert_called()

  @mock.patch.object(
      utility, "check_sufficient_permissions_on_service_account"
  )
  def test_permission_error(self, mock_perms):
    """Test permission denied error."""
    mock_perms.side_effect = GCPPermissionDeniedError("Denied")
    msg, code = main.main(mock.Mock())
    self.assertEqual(code, 403)

  @mock.patch.object(
      utility, "check_sufficient_permissions_on_service_account"
  )
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(main, "validate_live_investigation_inputs")
  @mock.patch.object(greynoise_client, "GreyNoiseUtility")
  def test_live_investigation_error(
      self, mock_cls, mock_validate, mock_env, mock_perms
  ):
    """Test LiveInvestigationError handling (lines 541-558)."""
    mock_request = mock.Mock()
    mock_request.headers = {}
    mock_env.return_value = "test_key"
    mock_validate.side_effect = LiveInvestigationError("Invalid input")

    msg, code = main.main(mock_request)

    self.assertEqual(code, 400)
    self.assertIn("Invalid inputs", msg)

  @mock.patch.object(
      utility, "check_sufficient_permissions_on_service_account"
  )
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(main, "get_run_gnql_query")
  @mock.patch.object(greynoise_client, "GreyNoiseUtility")
  def test_scheduler_generic_exception(
      self, mock_cls, mock_query, mock_env, mock_perms
  ):
    """Test generic exception in scheduler path (lines 552-558)."""
    mock_request = mock.Mock()
    mock_request.headers = {constant.SCHEDULER_HEADER_KEY: "true"}
    mock_env.return_value = "test_key"
    mock_query.side_effect = Exception("Query failed")

    msg, code = main.main(mock_request)

    self.assertEqual(code, 500)
    self.assertIn("Error executing", msg)

  @mock.patch.object(
      utility, "check_sufficient_permissions_on_service_account"
  )
  @mock.patch.object(utility, "get_environment_variable")
  def test_init_generic_exception(self, mock_env, mock_perms):
    """Test generic exception during init (lines 571-577)."""
    mock_env.side_effect = Exception("Env error")

    msg, code = main.main(mock.Mock())

    self.assertEqual(code, 500)
    self.assertIn("Error initializing", msg)

  @mock.patch.object(
      utility, "check_sufficient_permissions_on_service_account"
  )
  @mock.patch.object(utility, "get_environment_variable")
  @mock.patch.object(main, "_compute_dynamic_window_days")
  @mock.patch.object(main, "get_run_gnql_query")
  @mock.patch.object(greynoise_client, "GreyNoiseUtility")
  def test_scheduler_with_dynamic_days_no_base(
      self, mock_cls, mock_query, mock_compute, mock_env, mock_perms
  ):
    """Test scheduler with dynamic days but no base query (line 523)."""
    mock_request = mock.Mock()
    mock_request.headers = {constant.SCHEDULER_HEADER_KEY: "true"}
    mock_env.return_value = "last_seen:7d"
    mock_compute.return_value = 3

    msg, code = main.main(mock_request)

    self.assertEqual(code, 200)


if __name__ == "__main__":
  unittest.main()
