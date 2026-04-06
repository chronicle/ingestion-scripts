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

"""Comprehensive unit tests for cyjax_client module - 100% coverage."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import json

# Mock common modules before importing cyjax_client
mock_common = MagicMock()
mock_utils = MagicMock()
mock_ingest_v1 = MagicMock()
mock_common.utils = mock_utils
mock_common.ingest_v1 = mock_ingest_v1
INGESTION_SCRIPTS_PATH = ""
sys.modules["common"] = mock_common
sys.modules["common.utils"] = mock_utils
sys.modules["common.ingest_v1"] = mock_ingest_v1


import constant
import cyjax_client
from exception_handler import (
    ApiKeyNotFoundException,
    CyjaxException,
    RunTimeExceeded,
    ResponseErrorException,
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    ValidationException,
    TooManyRequestsException,
)


class TestCyjaxClientInit(unittest.TestCase):
  """Test CyjaxClient initialization."""

  def test_init_all_params(self):
    """Test initialization with all parameters."""
    client = cyjax_client.CyjaxClient(
        api_token="test_token",
        bucket_name="test-bucket",
        historical_ioc_duration=30,
        enable_enrichment=True,
        query="test_query",
        indicator_type="test_type",
    )
    self.assertEqual(client._CyjaxClient__api_key, "test_token")
    self.assertEqual(client.bucket_name, "test-bucket")
    self.assertEqual(client.historical_ioc_duration, 30)
    self.assertEqual(client.enable_enrichment, True)
    self.assertEqual(client.query, "test_query")
    self.assertEqual(client.indicator_type, "test_type")

  def test_init_minimal_params(self):
    """Test initialization with minimal parameters."""
    client = cyjax_client.CyjaxClient(
        api_token="test_token",
        bucket_name="test-bucket",
        historical_ioc_duration=1,
    )
    self.assertEqual(client._CyjaxClient__api_key, "test_token")
    self.assertEqual(client.bucket_name, "test-bucket")
    self.assertEqual(client.historical_ioc_duration, 1)
    self.assertEqual(client.enable_enrichment, False)
    self.assertIsNone(client.query)
    self.assertIsNone(client.indicator_type)


class TestCyjaxClientMethods(unittest.TestCase):
  """Test CyjaxClient methods."""

  def setUp(self):
    """Set up test fixtures."""
    super().setUp()
    self.client = cyjax_client.CyjaxClient(
        api_token="test_token",
        bucket_name="test-bucket",
        historical_ioc_duration=30,
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.Response")
  def test_get_response_message_json(self, mock_response):
    """Test _get_response_message with JSON response."""
    mock_response.json.return_value = {"message": "Test message"}
    result = self.client._get_response_message(mock_response)
    self.assertEqual(result, "Test message")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.Response")
  def test_get_response_message_dict_without_message(self, mock_response):
    """Test _get_response_message with dict without message."""
    mock_response.json.return_value = {"error": "Test error"}
    mock_response.text = "Raw text"
    result = self.client._get_response_message(mock_response)
    self.assertEqual(result, "Raw text")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.Response")
  def test_get_response_message_json_decode_error(self, mock_response):
    """Test _get_response_message with JSON decode error."""
    mock_response.json.side_effect = ValueError()
    mock_response.text = "Raw response"
    result = self.client._get_response_message(mock_response)
    self.assertEqual(result, "Raw response")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  def test_request_cyjax_success(self, mock_request):
    """Test _request_cyjax successful request."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_request.return_value = mock_response

    result = self.client._request_cyjax("GET", "test_endpoint")

    self.assertEqual(result, mock_response)
    mock_request.assert_called_once_with(
        method="GET",
        url=constant.BASE_URI + "/" + "test_endpoint",
        params={},
        data={},
        headers={
            constant.HEADER_AUTHORIZATION: "Bearer test_token",
            constant.HEADER_USER_AGENT: constant.USER_AGENT,
        },
        timeout=constant.TIMEOUT,
        verify=True,
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  def test_request_cyjax_created_response(self, mock_request):
    """Test _request_cyjax handles 201 Created as success."""
    mock_response = Mock()
    mock_response.status_code = 201
    mock_request.return_value = mock_response

    result = self.client._request_cyjax("POST", "test_endpoint")

    self.assertEqual(result, mock_response)
    mock_request.assert_called()

  def test_request_cyjax_no_api_key(self):
    """Test _request_cyjax without API key."""
    self.client._CyjaxClient__api_key = None
    with self.assertRaises(ApiKeyNotFoundException):
      self.client._request_cyjax("GET", "test_endpoint")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_request_cyjax_400_error(self, mock_log, mock_request):
    """Test _request_cyjax with 400 error."""
    mock_response = Mock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"message": "Bad request"}
    mock_request.return_value = mock_response

    with self.assertRaises(ResponseErrorException) as cm:
      self.client._request_cyjax("GET", "test_endpoint")

    self.assertEqual(cm.exception.status_code, 400)
    self.assertIn("Bad Request", str(cm.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_request_cyjax_401_error(self, mock_log, mock_request):
    """Test _request_cyjax with 401 error."""
    mock_response = Mock()
    mock_response.status_code = 401
    mock_request.return_value = mock_response

    with self.assertRaises(UnauthorizedException):
      self.client._request_cyjax("GET", "test_endpoint")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_request_cyjax_403_error(self, mock_log, mock_request):
    """Test _request_cyjax with 403 error."""
    mock_response = Mock()
    mock_response.status_code = 403
    mock_request.return_value = mock_response

    with self.assertRaises(ForbiddenException):
      self.client._request_cyjax("GET", "test_endpoint")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_request_cyjax_404_error(self, mock_log, mock_request):
    """Test _request_cyjax with 404 error."""
    mock_response = Mock()
    mock_response.status_code = 404
    mock_request.return_value = mock_response

    with self.assertRaises(NotFoundException):
      self.client._request_cyjax("GET", "test_endpoint")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_request_cyjax_422_error(self, mock_log, mock_request):
    """Test _request_cyjax with 422 error."""
    mock_response = Mock()
    mock_response.status_code = 422
    mock_response.json.return_value = {"detail": "Validation error"}
    mock_request.return_value = mock_response

    with self.assertRaises(ValidationException):
      self.client._request_cyjax("GET", "test_endpoint")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  @patch("time.sleep")
  def test_request_cyjax_429_retry(self, mock_sleep, mock_log, mock_request):
    """Test _request_cyjax with 429 error and retry."""
    mock_response = Mock()
    mock_response.status_code = 429
    mock_request.side_effect = [mock_response] * constant.RETRY_COUNT

    with self.assertRaises(TooManyRequestsException):
      self.client._request_cyjax("GET", "test_endpoint")

    self.assertEqual(mock_request.call_count, constant.RETRY_COUNT)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  @patch("time.sleep")
  def test_request_cyjax_500_retry(self, mock_sleep, mock_log, mock_request):
    """Test _request_cyjax with 500 error and retry."""
    mock_response = Mock()
    mock_response.status_code = 500
    mock_request.side_effect = [mock_response] * constant.RETRY_COUNT

    with self.assertRaises(ResponseErrorException):
      self.client._request_cyjax("GET", "test_endpoint")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_request_cyjax_generic_error_with_json_message(
      self, mock_log, mock_request
  ):
    """Test _request_cyjax raises message from generic JSON response."""
    mock_response = Mock()
    mock_response.status_code = 418
    mock_response.json.return_value = {"message": "Generic failure"}
    mock_request.return_value = mock_response

    with self.assertRaises(ResponseErrorException) as exc:
      self.client._request_cyjax("GET", "test_endpoint")

    self.assertEqual(exc.exception.status_code, 418)
    self.assertEqual(str(exc.exception), "Generic failure")

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_request_cyjax_generic_error_json_decode_failure(
      self, mock_log, mock_request
  ):
    """Test _request_cyjax falls back to JSON decode failure."""
    mock_response = Mock()
    mock_response.status_code = 418
    mock_response.text = "raw text"
    mock_response.json.side_effect = json.JSONDecodeError("err", "", 0)
    mock_request.return_value = mock_response

    with self.assertRaises(ResponseErrorException) as exc:
      self.client._request_cyjax("GET", "test_endpoint")

    self.assertEqual(exc.exception.status_code, 418)
    self.assertIn("raw text", str(exc.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_request_cyjax_unknown_error(self, mock_log, mock_request):
    """Test _request_cyjax with unknown error code."""
    mock_response = Mock()
    mock_response.status_code = 418
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
    mock_response.text = "I'm a teapot"
    with patch(
        f"{INGESTION_SCRIPTS_PATH}cyjax_client.requests.api.request",
        return_value=mock_response,
    ):
      with self.assertRaises(ResponseErrorException) as cm:
        self.client._request_cyjax("GET", "test_endpoint")
      self.assertEqual(cm.exception.status_code, 418)
    self.assertIn("I'm a teapot", str(cm.exception))

  @patch.object(cyjax_client.CyjaxClient, "_request_cyjax")
  def test_get_indicators_of_compromise(self, mock_request):
    """Test _get_indicators_of_compromise."""
    mock_response = Mock()
    mock_request.return_value = mock_response

    result = self.client._get_indicators_of_compromise(
        page=1, per_page=50, since="2023-01-01T00:00:00Z", query="test"
    )

    self.assertEqual(result, mock_response)
    mock_request.assert_called_once_with(
        "GET",
        constant.ENDPOINT_INDICATOR_OF_COMPROMISE,
        params={
            "page": 1,
            "per-page": 50,
            "since": "2023-01-01T00:00:00Z",
            "query": "test",
        },
    )

  @patch.object(cyjax_client.CyjaxClient, "_request_cyjax")
  def test_get_indicators_of_compromise_with_until_and_type(self, mock_request):
    """Test _get_indicators_of_compromise includes until and type params."""
    mock_response = Mock()
    mock_request.return_value = mock_response

    result = self.client._get_indicators_of_compromise(
        page=None,
        per_page=None,
        since=None,
        until="2023-01-02T00:00:00Z",
        query=None,
        ioc_type="domain",
    )

    self.assertEqual(result, mock_response)
    mock_request.assert_called_once_with(
        "GET",
        constant.ENDPOINT_INDICATOR_OF_COMPROMISE,
        params={"until": "2023-01-02T00:00:00Z", "type": "domain"},
    )

  @patch.object(cyjax_client.CyjaxClient, "_request_cyjax")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_get_indicator_enrichment_success(self, mock_log, mock_request):
    """Test _get_indicator_enrichment successful."""
    mock_response = Mock()
    mock_response.json.return_value = {"enrichment": "data"}
    mock_request.return_value = mock_response

    result = self.client._get_indicator_enrichment("test_value")

    self.assertEqual(result, {"enrichment": "data"})

  @patch.object(cyjax_client.CyjaxClient, "_request_cyjax")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_get_indicator_enrichment_failure(self, mock_log, mock_request):
    """Test _get_indicator_enrichment failure."""
    mock_request.side_effect = Exception("Network error")

    result = self.client._get_indicator_enrichment("test_value")

    self.assertEqual(result, {})

  def test_create_end_time(self):
    """Test _create_end_time."""
    indicator = {"value": "test"}
    self.client._create_end_time(indicator)

    self.assertIn(constant.END_TIME_FIELD_NAME, indicator)
    # Verify it's a future time

  @patch.object(cyjax_client.CyjaxClient, "_get_indicators_of_compromise")
  @patch("urllib.parse.urlparse")
  @patch("urllib.parse.parse_qs")
  def test_get_indicators_page_success(
      self, mock_parse_qs, mock_urlparse, mock_request
  ):
    """Test _get_indicators_page successful."""
    mock_response = Mock()
    mock_response.json.return_value = [{"value": "indicator1"}]
    mock_response.links = {"next": {"url": "http://example.com?page=2"}}
    mock_request.return_value = mock_response
    mock_parsed = Mock()
    mock_urlparse.return_value = mock_parsed
    mock_parse_qs.return_value = {"page": ["2"]}

    indicators, has_next, next_page = self.client._get_indicators_page(
        "2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z", 1, {"query": "test"}
    )

    self.assertEqual(indicators, [{"value": "indicator1"}])
    self.assertTrue(has_next)
    self.assertEqual(next_page, 2)

  @patch.object(cyjax_client.CyjaxClient, "_get_indicators_of_compromise")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_get_indicators_page_exception(self, mock_log, mock_request):
    """Test _get_indicators_page with exception."""
    mock_request.side_effect = Exception("API error")

    with self.assertRaises(CyjaxException):
      self.client._get_indicators_page(
          "2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z", 1, {}
      )

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_last_checkpoint")
  @patch("time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_ingest_indicators_success(
      self, mock_log, mock_ingest, mock_time, mock_get_checkpoint
  ):
    """Test _ingest_indicators successful."""
    mock_get_checkpoint.return_value = None
    mock_time.return_value = 1000000

    result = self.client._ingest_indicators([{"value": "test"}])

    self.assertEqual(result, 1)
    mock_ingest.assert_called_once_with(
        [{"value": "test"}], constant.GOOGLE_SECOPS_DATA_TYPE
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_last_checkpoint")
  @patch("time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_ingest_indicators_runtime_exceeded(
      self, mock_log, mock_time, mock_get_checkpoint
  ):
    """Test _ingest_indicators runtime exceeded."""
    current_time = 1000000
    past_time = current_time - 60 * 60  # 1 hour ago
    mock_get_checkpoint.return_value = str(past_time)
    mock_time.return_value = current_time

    with self.assertRaises(RunTimeExceeded):
      self.client._ingest_indicators([{"value": "test"}])

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_last_checkpoint")
  @patch("time.time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_ingest_indicators_invalid_last_run_time(
      self, mock_log, mock_ingest, mock_time, mock_get_checkpoint
  ):
    """Test _ingest_indicators logs warning on invalid checkpoint timestamp."""
    mock_get_checkpoint.return_value = "invalid"
    mock_time.return_value = 1000000
    mock_ingest.return_value = None

    result = self.client._ingest_indicators([{"value": "test"}])

    self.assertEqual(result, 1)
    mock_ingest.assert_called_once()
    mock_log.assert_any_call(
        'Error checking execution time: ValueError("could not convert string'
        " to float: 'invalid'\"). Continuing with ingestion.",
        severity="WARNING",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_ingest_indicators_empty_list(self, mock_log, mock_get_checkpoint):
    """Test _ingest_indicators with empty list."""
    mock_get_checkpoint.return_value = None

    result = self.client._ingest_indicators([])

    self.assertEqual(result, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_ingest_indicators_ingest_failure(
      self, mock_log, mock_get_checkpoint
  ):
    """Test _ingest_indicators ingest failure."""
    mock_get_checkpoint.return_value = None

    with patch(
        f"{INGESTION_SCRIPTS_PATH}cyjax_client.ingest_v1.ingest",
        side_effect=Exception("Ingest error"),
    ):
      with self.assertRaisesRegex(Exception, "Ingest error"):
        self.client._ingest_indicators([{"value": "test"}])

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_checkpoints_and_config"
  )
  @patch.object(cyjax_client.CyjaxClient, "_get_indicators_page")
  @patch.object(cyjax_client.CyjaxClient, "_ingest_indicators")
  @patch.object(cyjax_client.CyjaxClient, "_get_indicator_enrichment")
  @patch.object(cyjax_client.CyjaxClient, "_create_end_time")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_fetch_and_ingest_indicators_full_flow(
      self,
      mock_log,
      mock_set_checkpoint,
      mock_create_end_time,
      mock_enrichment,
      mock_ingest,
      mock_get_page,
      mock_get_config,
  ):
    """Test fetch_and_ingest_indicators full flow."""
    mock_get_config.return_value = (
        "2023-01-01T00:00:00Z",
        "2023-01-02T00:00:00Z",
        1,
        {"query": "test"},
    )
    mock_get_page.return_value = ([{"value": "indicator1"}], False, None)
    mock_enrichment.return_value = {"enriched": True}
    mock_ingest.return_value = 1
    self.client.enable_enrichment = True

    self.client.fetch_and_ingest_indicators()

    mock_get_page.assert_called_once_with(
        "2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z", 1, {"query": "test"}
    )
    mock_enrichment.assert_called_once_with("indicator1")
    mock_create_end_time.assert_called_once()
    mock_ingest.assert_called_once()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_checkpoints_and_config"
  )
  @patch.object(cyjax_client.CyjaxClient, "_get_indicators_page")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_fetch_and_ingest_indicators_no_indicators(
      self,
      mock_log,
      mock_set_checkpoint,
      mock_get_page,
      mock_get_config,
  ):
    """Test fetch_and_ingest_indicators with no indicators."""
    mock_get_config.return_value = (
        "2023-01-01T00:00:00Z",
        "2023-01-02T00:00:00Z",
        1,
        {},
    )
    mock_get_page.return_value = ([], False, None)

    self.client.fetch_and_ingest_indicators()

    mock_set_checkpoint.assert_called_with(
        self.client.bucket_name, constant.CHECKPOINT_KEY_PAGE_NUMBER, 0
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_checkpoints_and_config"
  )
  @patch.object(cyjax_client.CyjaxClient, "_get_indicators_page")
  @patch.object(cyjax_client.CyjaxClient, "_ingest_indicators")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_fetch_and_ingest_indicators_missing_value(
      self,
      mock_log,
      mock_set_checkpoint,
      mock_ingest,
      mock_get_page,
      mock_get_config,
  ):
    """Test fetch_and_ingest_indicators with indicator missing value."""
    mock_get_config.return_value = (
        "2023-01-01T00:00:00Z",
        "2023-01-02T00:00:00Z",
        1,
        {},
    )
    mock_get_page.return_value = ([{"type": "ip"}], False, None)

    self.client.fetch_and_ingest_indicators()

    mock_ingest.assert_not_called()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_checkpoints_and_config"
  )
  @patch.object(cyjax_client.CyjaxClient, "_get_indicators_page")
  @patch.object(cyjax_client.CyjaxClient, "_ingest_indicators")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_fetch_and_ingest_indicators_no_enrichment(
      self,
      mock_log,
      mock_set_checkpoint,
      mock_ingest,
      mock_get_page,
      mock_get_config,
  ):
    """Test fetch_and_ingest_indicators without enrichment."""
    mock_get_config.return_value = (
        "2023-01-01T00:00:00Z",
        "2023-01-02T00:00:00Z",
        1,
        {},
    )
    mock_get_page.return_value = ([{"value": "indicator1"}], False, None)
    mock_ingest.return_value = 1
    self.client.enable_enrichment = False

    self.client.fetch_and_ingest_indicators()

    mock_ingest.assert_called_once()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.get_checkpoints_and_config"
  )
  @patch.object(cyjax_client.CyjaxClient, "_get_indicators_page")
  @patch.object(cyjax_client.CyjaxClient, "_ingest_indicators")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utility.set_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}cyjax_client.utils.cloud_logging")
  def test_fetch_and_ingest_indicators_auto_increment_page(
      self,
      mock_log,
      mock_set_checkpoint,
      mock_ingest,
      mock_get_page,
      mock_get_config,
  ):
    """Test fetch_and_ingest increments page when next page number missing."""
    mock_get_config.return_value = (
        "2023-01-01T00:00:00Z",
        "2023-01-02T00:00:00Z",
        1,
        {},
    )
    mock_get_page.side_effect = [
        ([{"value": "indicator1"}], True, None),
        ([], False, None),
    ]
    mock_ingest.return_value = 1

    self.client.fetch_and_ingest_indicators()

    self.assertEqual(mock_get_page.call_count, 2)
    mock_set_checkpoint.assert_any_call(
        self.client.bucket_name, constant.CHECKPOINT_KEY_PAGE_NUMBER, 2
    )
    mock_set_checkpoint.assert_any_call(
        self.client.bucket_name, constant.CHECKPOINT_KEY_PAGE_NUMBER, 0
    )


if __name__ == "__main__":
  unittest.main()
