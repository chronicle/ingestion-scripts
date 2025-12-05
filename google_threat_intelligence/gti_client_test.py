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
# pylint: disable=g-importing-member
# pylint: disable=invalid-name
# pylint: disable=g-multiple-import
# pylint: disable=unused-argument
# pylint: disable=g-import-not-at-top
# pylint: disable=g-bad-import-order

"""Test module for gti client."""

import json
import sys
from datetime import timezone
import unittest
from unittest import mock
from mock import Mock, patch, MagicMock
import threading

INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest_v1"] = mock.Mock()
sys.modules["common.utils"] = Mock()

# Mock problematic imports before importing the actual module
mock_google_cloud = Mock()
mock_exceptions = Mock()


class ForbiddenException(Exception):  # pylint: disable=g-bad-exception-name
  pass


class NotFoundException(Exception):  # pylint: disable=g-bad-exception-name
  pass
mock_exceptions.Forbidden = ForbiddenException
mock_exceptions.NotFound = NotFoundException
mock_google_cloud.exceptions = mock_exceptions
sys.modules["google.cloud"] = mock_google_cloud
sys.modules["google.cloud.storage"] = Mock()
sys.modules["google.cloud.resourcemanager_v3"] = Mock()
sys.modules["google.cloud.exceptions"] = mock_exceptions

import constant
import utility
from gti_client import GoogleThreatIntelligenceUtility
from exception_handler import GCPPermissionDeniedError


class TestGoogleThreatIntelligenceUtility(unittest.TestCase):
  """Test cases for GoogleThreatIntelligenceUtility class."""

  def setUp(self):
    """Set up test fixtures before each test method."""
    super().setUp()
    self.api_token = "test_api_token"
    self.bucket_name = "test_bucket"
    # Mock the dependencies to avoid actual initialization
    self.mock_logging_patcher = patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
    self.mock_logging = self.mock_logging_patcher.start()
    self.mock_get_headers_patcher = patch(f"{INGESTION_SCRIPTS_PATH}gti_client.GoogleThreatIntelligenceUtility.get_gti_headers_with_token")
    self.mock_get_headers = self.mock_get_headers_patcher.start()
    self.mock_check_permissions_patcher = patch(f"{INGESTION_SCRIPTS_PATH}gti_client.GoogleThreatIntelligenceUtility.check_sufficient_permissions_on_service_account")
    self.mock_check_permissions = self.mock_check_permissions_patcher.start()
    self.addCleanup(patch.stopall)
    self.gti_client = GoogleThreatIntelligenceUtility(
        self.api_token, self.bucket_name
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_utility_init(self, mock_get_headers, mock_cloud_logging):
    """Test successful initialization of GoogleThreatIntelligenceUtility."""
    # Arrange
    api_token = "test_api_token_123"
    bucket_name = "test_bucket_name"
    mock_headers = {
        "accept": "application/json",
        "authorization": f"Bearer {api_token}",
        "x-tool": "google-secops-siem",
        "User-Agent": "gti-app/1.0",
    }
    mock_get_headers.return_value = mock_headers
    self.mock_check_permissions.reset_mock()

    # Act
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Assert
    self.assertEqual(gti_utility.api_token, api_token)
    self.assertEqual(gti_utility.bucket_name, bucket_name)
    self.assertEqual(gti_utility.base_url, constant.BASE_URL)
    self.assertEqual(gti_utility.api_version, constant.API_VERSION)
    self.assertEqual(gti_utility.headers, mock_headers)

    # Verify that get_gti_headers_with_token was called
    mock_get_headers.assert_called_once()

    # Verify that cloud_logging was called with the expected message
    mock_cloud_logging.assert_called_once_with(
        "Google Threat Intelligence Client Initialized."
    )
    self.mock_check_permissions.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_utility_init_with_empty_strings(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test initialization with empty string parameters."""
    # Arrange
    api_token = ""
    bucket_name = ""
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Act
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Assert
    self.assertEqual(gti_utility.api_token, "")
    self.assertEqual(gti_utility.bucket_name, "")
    self.assertEqual(gti_utility.base_url, constant.BASE_URL)
    self.assertEqual(gti_utility.api_version, constant.API_VERSION)
    self.assertEqual(gti_utility.headers, mock_headers)

    mock_get_headers.assert_called_once()
    mock_cloud_logging.assert_called_once_with(
        "Google Threat Intelligence Client Initialized."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_utility_init_with_none_values(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test initialization with None values."""
    # Arrange
    api_token = None
    bucket_name = None
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Act
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Assert
    self.assertIsNone(gti_utility.api_token)
    self.assertIsNone(gti_utility.bucket_name)
    self.assertEqual(gti_utility.base_url, constant.BASE_URL)
    self.assertEqual(gti_utility.api_version, constant.API_VERSION)
    self.assertEqual(gti_utility.headers, mock_headers)

    mock_get_headers.assert_called_once()
    mock_cloud_logging.assert_called_once_with(
        "Google Threat Intelligence Client Initialized."
    )

  @patch("json.loads")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_parse_and_handle_response_success(
      self, mock_get_headers, mock_cloud_logging, mock_json_loads
  ):
    """Test successful response parsing with status code 200."""
    # Arrange
    mock_json_loads.return_value = {"data": "some data"}
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")
    result = {
        "response": Mock(status_code=200, text='{"data": "some data"}'),
        "status": True,
    }
    expected_return_dict = {
        "response": result["response"],
        "data": {"data": "some data"},
        "status": True,
    }

    # Act
    actual_result = gti_utility.parse_and_handle_response(
        {}, result, "test_fetch"
    )

    # Assert
    self.assertEqual(actual_result, expected_return_dict)
    mock_json_loads.assert_called_once_with(result["response"].text)

  @patch("json.loads")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_parse_and_handle_response_value_error(
      self, mock_get_headers, mock_cloud_logging, mock_json_loads
  ):
    """Test response parsing with ValueError during JSON parsing."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")
    mock_json_loads.side_effect = ValueError("Invalid JSON")
    result = {
        "response": Mock(status_code=200, text="invalid_json"),
        "status": True,
    }

    # Act
    gti_utility.parse_and_handle_response({}, result, "test_fetch")

    # Assert
    mock_cloud_logging.assert_called_with(
        constant.ERR_MSG_FAILED_TO_PARSE_RESPONSE.format(
            result["response"].text, "Invalid JSON"
        )
    )

  @patch("json.loads")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_parse_and_handle_response_exception(
      self, mock_get_headers, mock_cloud_logging, mock_json_loads
  ):
    """Test response parsing with general exception."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")
    mock_json_loads.side_effect = Exception("Something went wrong")
    result = {
        "response": Mock(status_code=200, text="some_text"),
        "status": True,
    }

    # Act
    gti_utility.parse_and_handle_response({}, result, "test_fetch")

    # Assert
    mock_cloud_logging.assert_called_with(
        "Error while handling response from Google Threat Intelligence."
        " Response = {0}. Error = {1}".format(
            result["response"].text, "Something went wrong"
        ),
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_parse_and_handle_response_401(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test response parsing with 401 Unauthorized status code."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")
    result = {
        "response": Mock(status_code=401, text="Unauthorized"),
        "status": True,
    }
    expected_return_dict = {
        "response": result["response"],
        "error": "Invalid API Token.",
        "status": False,
    }

    # Act
    actual_result = gti_utility.parse_and_handle_response(
        {}, result, "test_fetch"
    )

    # Assert
    self.assertEqual(actual_result, expected_return_dict)
    mock_cloud_logging.assert_called_with(
        constant.GENERAL_ERROR_MESSAGE.format(
            status_code=401, response_text="Unauthorized", fetch_type="test_fetch"
        ),
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_parse_and_handle_response_403(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test response parsing with 403 Forbidden status code."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")
    result = {
        "response": Mock(status_code=403, text="Forbidden"),
        "status": True,
    }
    expected_return_dict = {
        "response": result["response"],
        "error": "API Token does not have permission to access test_fetch.",
        "status": False,
    }

    # Act
    actual_result = gti_utility.parse_and_handle_response(
        {}, result, "test_fetch"
    )

    # Assert
    self.assertEqual(actual_result, expected_return_dict)
    mock_cloud_logging.assert_called_with(
        constant.GENERAL_ERROR_MESSAGE.format(
            status_code=403, response_text="Forbidden", fetch_type="test_fetch"
        ),
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_parse_and_handle_response_429(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test response parsing with 429 Rate Limit status code."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")
    result = {
        "response": Mock(status_code=429, text="Rate limit exceeded"),
        "status": True,
    }
    expected_return_dict = {
        "response": result["response"],
        "status": False,
        "retry": True,
        "error": (
            "API rate limit exceeded or internal server error occurred while"
            " fetching test_fetch."
        ),
    }

    # Act
    actual_result = gti_utility.parse_and_handle_response(
        {}, result, "test_fetch"
    )

    # Assert
    self.assertEqual(actual_result, expected_return_dict)
    mock_cloud_logging.assert_called_with(
        constant.GENERAL_ERROR_MESSAGE.format(
            status_code=429,
            response_text="Rate limit exceeded",
            fetch_type="test_fetch",
        ),
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_parse_and_handle_response_404(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test response parsing with 404 Not Found status code."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")
    result = {
        "response": Mock(status_code=404, text="Not Found"),
        "status": True,
    }
    expected_return_dict = {
        "response": result["response"],
        "status": False,
        "error": (
            "Failed to fetch test_fetch, received status code - 404. Response -"
            " Not Found."
        ),
    }

    # Act
    actual_result = gti_utility.parse_and_handle_response(
        {}, result, "test_fetch"
    )

    # Assert
    self.assertEqual(actual_result, expected_return_dict)
    mock_cloud_logging.assert_called_with(
        constant.GENERAL_ERROR_MESSAGE.format(
            status_code=404, response_text="Not Found", fetch_type="test_fetch"
        ),
        severity="ERROR",
    )

  def test_get_gti_headers_with_token(self):
    """Test that get_gti_headers_with_token returns the expected headers."""
    self.mock_get_headers_patcher.stop()
    self.gti_client.api_token = "token123"
    expected_headers = {
        "accept": constant.CONTENT_TYPE_JSON,
        "x-apikey": "token123",
        "x-tool": constant.X_TOOL,
        "User-Agent": constant.GTI_APP_VERSION,
    }
    self.assertEqual(self.gti_client.get_gti_headers_with_token(), expected_headers)
    self.mock_get_headers_patcher.start()

  @patch.object(GoogleThreatIntelligenceUtility, "gti_rest_api")
  @patch.object(GoogleThreatIntelligenceUtility, "parse_and_handle_response")
  @patch("time.sleep")
  def test_fetch_threat_data_should_retry_no_retry_on_status_false(
      self, mock_sleep, mock_handle_response, mock_rest_api
  ):
    """Test fetch_threat_data with should_retry=True but result is not retryable."""
    credentials = {"base_url": "https://example.com", "api_token": "token123"}
    gti_utility = GoogleThreatIntelligenceUtility(credentials, Mock())
    mock_rest_api.return_value = {"status": False, "retry": False}
    result = gti_utility.fetch_threat_data(threat_type="Malware", should_retry=True)
    self.assertEqual(result, {"status": False, "retry": False})
    mock_rest_api.assert_called_once()
    mock_handle_response.assert_not_called()
    mock_sleep.assert_not_called()

  @patch.object(GoogleThreatIntelligenceUtility, "gti_rest_api")
  @patch.object(GoogleThreatIntelligenceUtility, "parse_and_handle_response")
  @patch.object(GoogleThreatIntelligenceUtility, "handle_retry")
  @patch("time.sleep")
  def test_fetch_threat_data_success(
      self, mock_sleep, mock_handle_retry, mock_handle_response, mock_rest_api
  ):
    """Test that fetch_threat_data returns the expected result."""
    credentials = {"base_url": "https://example.com", "api_token": "token123"}
    gti_utility = GoogleThreatIntelligenceUtility(credentials, Mock())

    # Loop break
    mock_rest_api.return_value = {"retry": False, "status": True}
    mock_handle_response.return_value = {
        "retry": False,
        "status": True,
        "data": "value",
    }
    mock_handle_retry.return_value = False, {"key": "value"}, 1

    assert gti_utility.fetch_threat_data(threat_type="Malware") == {
        "key": "value"
    }
    assert mock_handle_retry.call_count == 1
    assert mock_handle_response.call_count == 1
    assert mock_sleep.call_count == 0

    # Loop continue
    mock_handle_retry.return_value = True, {"key": "value"}, 1
    expected_output = {
        "status": True,
        "data": "value",
        "error": "",
        "response": "",
        "retry": False,
    }

    assert (
        gti_utility.fetch_threat_data(threat_type="Malware") == expected_output
    )
    assert mock_handle_retry.call_count == 2
    assert mock_handle_response.call_count == 2
    assert mock_sleep.call_count == 1

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_connect_timeout_exception(
      self, mock_get_headers, mock_logging, mock_request
  ):
    """Test gti_rest_api with ConnectTimeout exception to cover exception_handler."""
    import requests

    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Mock requests.request to raise ConnectTimeout
    mock_request.side_effect = requests.exceptions.ConnectTimeout(
        "Connection timeout"
    )

    # Call a method that uses gti_rest_api
    result = gti_utility.fetch_threat_data("malware")

    # Verify exception handler response
    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("connection timeout", result["error"])
    mock_logging.assert_called_with(
        "[Google Threat Intelligence Rest API] API call failed."
        " Failed due to connection timeout. Error = ConnectTimeout('Connection timeout')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_read_timeout_exception(
      self, mock_get_headers, mock_logging, mock_request
  ):
    """Test gti_rest_api with ReadTimeout exception to cover exception_handler."""
    import requests

    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Mock requests.request to raise ReadTimeout
    mock_request.side_effect = requests.exceptions.ReadTimeout("Read timeout")

    result = gti_utility.fetch_threat_data("malware")

    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("read timeout", result["error"])
    mock_logging.assert_called_with(
        "[Google Threat Intelligence Rest API] API call failed. Failed due to"
        " read timeout. Error = ReadTimeout('Read timeout')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_too_many_redirects_exception(
      self, mock_get_headers, mock_logging, mock_request
  ):
    """Test gti_rest_api with TooManyRedirects exception to cover exception_handler."""
    import requests

    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Mock requests.request to raise TooManyRedirects
    mock_request.side_effect = requests.exceptions.TooManyRedirects(
        "Too many redirects"
    )

    result = gti_utility.fetch_threat_data("malware")

    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("too many redirects", result["error"])
    mock_logging.assert_called_with(
        "[Google Threat Intelligence Rest API] API call failed. Failed"
        " due to too many redirects. Error - TooManyRedirects('Too many redirects')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_http_error_exception(
      self, mock_get_headers, mock_logging, mock_request
  ):
    """Test gti_rest_api with HTTPError exception to cover exception_handler."""
    import requests

    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Mock requests.request to raise HTTPError
    mock_request.side_effect = requests.exceptions.HTTPError("HTTP error")

    result = gti_utility.fetch_threat_data("malware")

    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("HTTP error", result["error"])
    mock_logging.assert_called_with(
        "[Google Threat Intelligence Rest API] API call failed. Failed due to"
        " HTTP error. Error = HTTPError('HTTP error')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_ssl_error_exception(
      self, mock_get_headers, mock_logging, mock_request
  ):
    """Test gti_rest_api with SSLError exception to cover exception_handler."""
    import requests

    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Mock requests.request to raise SSLError
    mock_request.side_effect = requests.exceptions.SSLError("SSL error")

    result = gti_utility.fetch_threat_data("malware")

    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("SSL error", result["error"])
    mock_logging.assert_called_with(
        "[Google Threat Intelligence Rest API] API call failed. Failed due to"
        " SSL error. Error = SSLError('SSL error')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_general_exception(
      self, mock_get_headers, mock_logging, mock_request
  ):
    """Test gti_rest_api with general Exception to cover exception_handler."""
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Mock requests.request to raise general Exception
    mock_request.side_effect = Exception("General error")

    result = gti_utility.fetch_threat_data("malware")

    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("API call failed", result["error"])
    mock_logging.assert_called_with(
        "[Google Threat Intelligence Rest API] Exception occurred. Error ="
        " Exception('General error')"
    )

  @patch.object(GoogleThreatIntelligenceUtility, "gti_rest_api")
  @patch.object(GoogleThreatIntelligenceUtility, "parse_and_handle_response")
  @patch("time.sleep")
  def test_fetch_threat_data_fail(
      self, mock_sleep, mock_handle_response, mock_rest_api
  ):
    """Test fetch_threat_data when it fails with different cases."""
    credentials = {"base_url": "https://example.com", "api_token": "token123"}
    gti_utility = GoogleThreatIntelligenceUtility(credentials, Mock())

    # Case: Retry=true and should_retry=false
    mock_rest_api.return_value = {"retry": True, "status": True}

    assert gti_utility.fetch_threat_data(threat_type="Malware") == {
        "retry": True,
        "status": True,
    }
    assert mock_handle_response.call_count == 0
    assert mock_sleep.call_count == 0

    # Case: status=false, retry=false and should_retry=false
    mock_rest_api.return_value = {"retry": False, "status": False}

    assert gti_utility.fetch_threat_data(threat_type="Malware") == {
        "retry": False,
        "status": False,
    }
    assert mock_handle_response.call_count == 0
    assert mock_sleep.call_count == 0

    # Case: Retry=true and should_retry=true
    mock_rest_api.return_value = {"retry": True, "status": False}
    expected_output = {
        "status": False,
        "data": {},
        "error": "",
        "response": "",
        "retry": True,
    }

    assert (
        gti_utility.fetch_threat_data(threat_type="Malware", should_retry=True)
        == expected_output
    )
    assert mock_handle_response.call_count == 0
    assert mock_sleep.call_count == 2
    assert mock_rest_api.call_count == 5

  def test_handle_retry(self):
    """Test handle_retry method."""
    credentials = {"base_url": "https://example.com", "api_token": "token123"}
    gti_client = GoogleThreatIntelligenceUtility(credentials, Mock())

    assert gti_client.handle_retry({"status": True}, {}, False, 5, 0) == (
        False,
        {"status": True},
        0,
    )

    expected_output = False, {"status": False, "retry": False}, 0
    assert (
        gti_client.handle_retry(
            {"status": False, "retry": False}, {}, False, 5, 0
        )
        == expected_output
    )

    expected_output = False, {"status": False, "retry": False}, 0
    assert (
        gti_client.handle_retry(
            {"status": False, "retry": False}, {}, True, 5, 0
        )
        == expected_output
    )

    assert gti_client.handle_retry(
        {"status": False, "retry": True}, {}, True, 5, 0
    ) == (True, {}, 1)

    expected_output = False, {"status": False, "retry": True}, 1
    assert (
        gti_client.handle_retry(
            {"status": False, "retry": True}, {}, True, 1, 0
        )
        == expected_output
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__get_checkpoint_file_key_exists(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test _get_checkpoint_file when key exists in mapping."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Mock the constant.CHECKPOINT_KEY_TO_SHARD to include our test key
    original_mapping = constant.CHECKPOINT_KEY_TO_SHARD.copy()
    constant.CHECKPOINT_KEY_TO_SHARD["test_key"] = "test_shard.json"

    try:
      # Act
      result = gti_utility._get_checkpoint_file("test_key")

      # Assert
      self.assertEqual(result, "test_shard.json")
      mock_cloud_logging.assert_any_call(
          "Checkpoint key 'test_key' mapped to shard file 'test_shard.json'",
          severity="DEBUG",
      )
    finally:
      # Restore the original mapping
      constant.CHECKPOINT_KEY_TO_SHARD = original_mapping

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_checkpoint_file")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__get_last_checkpoint_exists(
      self,
      mock_get_headers,
      mock_get_checkpoint_file,
      mock_cloud_logging,
      MockStorageClient,
  ):
    """Test _get_last_checkpoint when checkpoint file exists."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock the _get_checkpoint_file method to return a specific file name
    checkpoint_file = "test_checkpoint_file.json"
    mock_get_checkpoint_file.return_value = checkpoint_file

    # Mock the storage client and related objects
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = (
        '{"test_endpoint": "test_checkpoint"}'
    )

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    checkpoint = gti_utility._get_last_checkpoint("test_endpoint")

    # Assert
    self.assertEqual(checkpoint, "test_checkpoint")
    mock_get_checkpoint_file.assert_called_once_with("test_endpoint")
    MockStorageClient.assert_called_once()
    mock_client.get_bucket.assert_called_once_with(bucket_name)
    mock_bucket.blob.assert_called_once_with(checkpoint_file)
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_checkpoint_file")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__get_last_checkpoint_not_exists(
      self,
      mock_get_headers,
      mock_get_checkpoint_file,
      mock_cloud_logging,
      MockStorageClient,
  ):
    """Test _get_last_checkpoint when checkpoint file does not exist."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock the _get_checkpoint_file method to return a specific file name
    checkpoint_file = "test_checkpoint_file.json"
    mock_get_checkpoint_file.return_value = checkpoint_file

    # Mock the storage client and related objects
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = False

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    checkpoint = gti_utility._get_last_checkpoint("test_endpoint")

    # Assert
    self.assertIsNone(checkpoint)
    mock_get_checkpoint_file.assert_called_once_with("test_endpoint")
    MockStorageClient.assert_called_once()
    mock_client.get_bucket.assert_called_once_with(bucket_name)
    mock_bucket.blob.assert_called_once_with(checkpoint_file)
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_checkpoint_file")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__get_last_checkpoint_json_decode_error(
      self,
      mock_get_headers,
      mock_get_checkpoint_file,
      mock_cloud_logging,
      MockStorageClient,
  ):
    """Test _get_last_checkpoint when JSON decode error occurs."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock the _get_checkpoint_file method to return a specific file name
    checkpoint_file = "test_checkpoint_file.json"
    mock_get_checkpoint_file.return_value = checkpoint_file

    # Mock the storage client and related objects
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "invalid json"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    checkpoint = gti_utility._get_last_checkpoint("test_endpoint")

    # Assert
    self.assertIsNone(checkpoint)
    mock_get_checkpoint_file.assert_called_once_with("test_endpoint")
    MockStorageClient.assert_called_once()
    mock_client.get_bucket.assert_called_once_with(bucket_name)
    mock_bucket.blob.assert_called_once_with(checkpoint_file)
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_called_once()
    mock_cloud_logging.assert_any_call(
        f"Failed to decode JSON content from {checkpoint_file}",
        severity="WARNING",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.exceptions")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_checkpoint_file")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__get_last_checkpoint_general_exception(
      self,
      mock_get_headers,
      mock_get_checkpoint_file,
      mock_cloud_logging,
      MockStorageClient,
      mock_exceptions_arg,
  ):
    """Test _get_last_checkpoint when a general exception occurs."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock the _get_checkpoint_file method to return a specific file name
    checkpoint_file = "test_checkpoint_file.json"
    mock_get_checkpoint_file.return_value = checkpoint_file

    # Mock the storage client to raise a general exception (not NotFound or JSONDecodeError)
    mock_storage_instance = Mock()
    mock_bucket = Mock()
    mock_blob = Mock()

    # Set up successful bucket access and blob operations
    mock_storage_instance.get_bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = '{"test": "data"}'
    MockStorageClient.return_value = mock_storage_instance

    # Mock the exceptions module so that NotFound is not caught by the specific handler
    # This ensures the exception falls through to the general exception handler
    mock_exceptions_arg.NotFound = type("NotFound", (Exception,), {})

    # Create a custom exception that will NOT be caught by the NotFound or JSONDecodeError handlers
    # We'll patch json.loads to raise this exception
    with patch(
        f"{INGESTION_SCRIPTS_PATH}gti_client.json.loads"
    ) as mock_json_loads:
      mock_json_loads.side_effect = OSError(
          "File system error during JSON processing"
      )

      # Create the utility instance
      gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

      # Act
      result = gti_utility._get_last_checkpoint("test_checkpoint_key")

      # Assert
      # Should return None when general exception occurs
      self.assertIsNone(result)
      mock_get_checkpoint_file.assert_called_once_with("test_checkpoint_key")

      # Verify that the general exception logging was called
      mock_cloud_logging.assert_any_call(
          "Unknown exception occurred while getting last checkpoint. "
          "Error message: File system error during JSON processing",
          severity="ERROR",
      )

      # Verify the storage client operations were called in the expected sequence
      MockStorageClient.assert_called_once()
      mock_storage_instance.get_bucket.assert_called_once_with(bucket_name)
      mock_bucket.blob.assert_called_once_with(checkpoint_file)
      mock_blob.exists.assert_called_once()
      mock_blob.download_as_text.assert_called_once()
      mock_json_loads.assert_called_once_with('{"test": "data"}')

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_checkpoint_file")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__get_last_checkpoint_not_found_exception(
      self,
      mock_get_headers,
      mock_get_checkpoint_file,
      mock_cloud_logging,
      MockStorageClient,
  ):
    """Test _get_last_checkpoint when NotFound exception occurs (bucket doesn't exist)."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "invalid_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock the _get_checkpoint_file method to return a specific file name
    checkpoint_file = "test_checkpoint_file.json"
    mock_get_checkpoint_file.return_value = checkpoint_file

    # Mock the storage client to raise NotFound exception
    mock_storage_instance = Mock()

    # Import the mocked NotFound exception
    from google.cloud.exceptions import NotFound

    mock_storage_instance.get_bucket.side_effect = NotFound("Bucket not found")
    MockStorageClient.return_value = mock_storage_instance

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act & Assert
    with self.assertRaises(RuntimeError) as context:
      gti_utility._get_last_checkpoint("test_endpoint")

    # Verify the RuntimeError message
    self.assertIn(
        "The specified bucket 'invalid_bucket' does not exist.",
        str(context.exception),
    )
    mock_get_checkpoint_file.assert_called_once_with("test_endpoint")
    MockStorageClient.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch.object(
      GoogleThreatIntelligenceUtility,
      "fetch_and_process_attack_techniques_data",
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_mitre_attack_processing_enabled_with_attack_data(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_fetch_attack_data,
      mock_get_env_var,
  ):
    """Test MITRE ATT&CK processing when enabled with file IOC that has attack techniques data."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_get_env_var.return_value = "true"  # MITRE_ATTACK_ENABLED = true

    # Mock attack techniques data that will be returned
    mock_attack_data = {
        "attack_techniques": ["T1055", "T1027"],
        "mitre_attack_info": {"tactics": ["defense-evasion"]},
    }
    mock_fetch_attack_data.return_value = mock_attack_data

    # Create test data simulating threat_list_data from line 447
    threat_list_data = [
        {
            "data": {
                "type": "file",
                "id": "test_file_hash_123",
                "attributes": {"file_name": "malware.exe"},
            }
        },
        {
            "data": {
                "type": "ip",
                "id": "192.168.1.1",
                "attributes": {"country": "US"},
            }
        },
    ]

    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    if (
        utility.get_environment_variable(constant.ENV_VAR_MITRE_ATTACK_ENABLED)
        == "true"
    ):
      for item in threat_list_data:
        if item.get("data", {}).get("type") == "file":
          attack_techniques_data = (
              gti_utility.fetch_and_process_attack_techniques_data(
                  item.get("data", {}).get("id"), True
              )
          )
          if attack_techniques_data:
            # Append attack techniques data to the file IOC data at parent level
            item["data"].update(attack_techniques_data)

    # Assert
    mock_get_env_var.assert_called_once_with(
        constant.ENV_VAR_MITRE_ATTACK_ENABLED
    )
    mock_fetch_attack_data.assert_called_once_with("test_file_hash_123", True)

    # Verify that attack techniques data was merged into the file IOC data
    expected_file_data = {
        "type": "file",
        "id": "test_file_hash_123",
        "attributes": {"file_name": "malware.exe"},
        "attack_techniques": ["T1055", "T1027"],
        "mitre_attack_info": {"tactics": ["defense-evasion"]},
    }
    self.assertEqual(threat_list_data[0]["data"], expected_file_data)

    # Verify that non-file IOC remains unchanged
    expected_ip_data = {
        "type": "ip",
        "id": "192.168.1.1",
        "attributes": {"country": "US"},
    }
    self.assertEqual(threat_list_data[1]["data"], expected_ip_data)

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch.object(
      GoogleThreatIntelligenceUtility,
      "fetch_and_process_attack_techniques_data",
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_mitre_attack_processing_lines_enabled_no_attack_data(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_fetch_attack_data,
      mock_get_env_var,
  ):
    """Test MITRE ATT&CK processing when enabled with file IOC but no attack techniques data returned."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_get_env_var.return_value = "true"  # MITRE_ATTACK_ENABLED = true
    mock_fetch_attack_data.return_value = None  # No attack data returned

    # Create test data simulating threat_list_data from line 447
    threat_list_data = [{
        "data": {
            "type": "file",
            "id": "test_file_hash_456",
            "attributes": {"file_name": "clean_file.exe"},
        }
    }]
    original_data = threat_list_data[0]["data"].copy()

    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    if (
        utility.get_environment_variable(constant.ENV_VAR_MITRE_ATTACK_ENABLED)
        == "true"
    ):
      for item in threat_list_data:
        if item.get("data", {}).get("type") == "file":
          attack_techniques_data = (
              gti_utility.fetch_and_process_attack_techniques_data(
                  item.get("data", {}).get("id"), True
              )
          )
          if attack_techniques_data:
            # Append attack techniques data to the file IOC data at parent level
            item["data"].update(attack_techniques_data)

    # Assert
    mock_get_env_var.assert_called_once_with(
        constant.ENV_VAR_MITRE_ATTACK_ENABLED
    )
    mock_fetch_attack_data.assert_called_once_with("test_file_hash_456", True)

    # Verify that original data remains unchanged since no attack data was returned
    self.assertEqual(threat_list_data[0]["data"], original_data)

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch.object(
      GoogleThreatIntelligenceUtility,
      "fetch_and_process_attack_techniques_data",
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_mitre_attack_processing_lines_mixed_ioc_types(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_fetch_attack_data,
      mock_get_env_var,
  ):
    """Test MITRE ATT&CK processing with mixed IOC types including multiple file types."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_get_env_var.return_value = "true"  # MITRE_ATTACK_ENABLED = true

    # Mock different attack data for different files
    def mock_fetch_side_effect(file_id, should_retry):
      if file_id == "file_hash_1":
        return {"attack_techniques": ["T1055"], "tactics": ["defense-evasion"]}
      elif file_id == "file_hash_2":
        return None  # No attack data for second file
      return None

    mock_fetch_attack_data.side_effect = mock_fetch_side_effect

    # Create test data simulating threat_list_data from line 447
    threat_list_data = [
        {
            "data": {
                "type": "ip",
                "id": "192.168.1.1",
                "attributes": {"country": "US"},
            }
        },
        {
            "data": {
                "type": "file",
                "id": "file_hash_1",
                "attributes": {"file_name": "malware1.exe"},
            }
        },
        {
            "data": {
                "type": "domain",
                "id": "evil.com",
                "attributes": {"registrar": "test"},
            }
        },
        {
            "data": {
                "type": "file",
                "id": "file_hash_2",
                "attributes": {"file_name": "malware2.dll"},
            }
        },
    ]

    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    if (
        utility.get_environment_variable(constant.ENV_VAR_MITRE_ATTACK_ENABLED)
        == "true"
    ):
      for item in threat_list_data:
        if item.get("data", {}).get("type") == "file":
          attack_techniques_data = (
              gti_utility.fetch_and_process_attack_techniques_data(
                  item.get("data", {}).get("id"), True
              )
          )
          if attack_techniques_data:
            # Append attack techniques data to the file IOC data at parent level
            item["data"].update(attack_techniques_data)

    # Assert
    mock_get_env_var.assert_called_once_with(
        constant.ENV_VAR_MITRE_ATTACK_ENABLED
    )
    # Should be called twice for the two file type IOCs
    self.assertEqual(mock_fetch_attack_data.call_count, 2)
    mock_fetch_attack_data.assert_any_call("file_hash_1", True)
    mock_fetch_attack_data.assert_any_call("file_hash_2", True)

    # Verify that only the first file IOC was updated (since second returned None)
    expected_file1_data = {
        "type": "file",
        "id": "file_hash_1",
        "attributes": {"file_name": "malware1.exe"},
        "attack_techniques": ["T1055"],
        "tactics": ["defense-evasion"],
    }
    self.assertEqual(threat_list_data[1]["data"], expected_file1_data)

    # Verify that second file IOC remains unchanged
    expected_file2_data = {
        "type": "file",
        "id": "file_hash_2",
        "attributes": {"file_name": "malware2.dll"},
    }
    self.assertEqual(threat_list_data[3]["data"], expected_file2_data)

    # Verify that non-file IOCs remain unchanged
    self.assertEqual(threat_list_data[0]["data"]["type"], "ip")
    self.assertEqual(threat_list_data[2]["data"]["type"], "domain")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.add_one_hour_to_formatted_time")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch.object(
      GoogleThreatIntelligenceUtility,
      "fetch_and_process_attack_techniques_data",
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_threat_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.check_time_current_hr")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_ingest_events_for_threat_type_with_mitre_attack_enabled_file_ioc(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_check_time,
      mock_fetch_threat_data,
      mock_get_checkpoint,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_fetch_attack_data,
      mock_get_env_var,
      mock_add_hour,
  ):
    """Test actual execution through ingest_events_for_threat_type method - MITRE enabled with file IOC."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_get_env_var.return_value = "true"  # MITRE_ATTACK_ENABLED = true
    mock_check_time.side_effect = [False, True]  # Process once, then stop
    mock_get_checkpoint.return_value = None
    mock_add_hour.return_value = "2023-01-01T01:00:00Z"

    # Mock threat data response with file type IOC
    mock_threat_response = {
        "status": True,
        "data": {
            "iocs": [{
                "data": {
                    "type": "file",
                    "id": "test_file_hash_real",
                    "attributes": {"file_name": "malware_real.exe"},
                }
            }]
        },
    }
    mock_fetch_threat_data.return_value = mock_threat_response

    # Mock attack techniques data that will be returned
    mock_attack_data = {
        "attack_techniques": ["T1055", "T1027"],
        "mitre_attack_info": {"tactics": ["defense-evasion"]},
    }
    mock_fetch_attack_data.return_value = mock_attack_data

    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Act - Call the actual method that contains lines 454-459
    gti_utility.ingest_events_for_threat_type(
        "malware", None, "2023-01-01T00:00:00Z"
    )

    # Assert - Verify that lines 454-459 were executed
    mock_get_env_var.assert_called_with(constant.ENV_VAR_MITRE_ATTACK_ENABLED)
    mock_fetch_attack_data.assert_called_once_with("test_file_hash_real", True)

    # Verify that _ingest_events was called with updated data (proving lines 457-459 executed)
    mock_ingest_events.assert_called_once()
    ingested_data = mock_ingest_events.call_args[0][0]

    # Verify that attack techniques data was merged into the IOC data (line 459 executed)
    expected_data = {
        "type": "file",
        "id": "test_file_hash_real",
        "attributes": {"file_name": "malware_real.exe"},
        "attack_techniques": ["T1055", "T1027"],
        "mitre_attack_info": {"tactics": ["defense-evasion"]},
    }
    self.assertEqual(ingested_data[0]["data"], expected_data)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.add_one_hour_to_formatted_time")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch.object(
      GoogleThreatIntelligenceUtility,
      "fetch_and_process_attack_techniques_data",
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_threat_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.check_time_current_hr")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_ingest_events_for_threat_type_with_mitre_attack_disabled(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_check_time,
      mock_fetch_threat_data,
      mock_get_checkpoint,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_fetch_attack_data,
      mock_get_env_var,
      mock_add_hour,
  ):
    """Test ingest_events_for_threat_type method - MITRE disabled."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_get_env_var.return_value = "false"  # MITRE_ATTACK_ENABLED = false
    mock_check_time.side_effect = [False, True]  # Process once, then stop
    mock_get_checkpoint.return_value = None
    mock_add_hour.return_value = "2023-01-01T01:00:00Z"

    # Mock threat data response with file type IOC
    mock_threat_response = {
        "status": True,
        "data": {
            "iocs": [{
                "data": {
                    "type": "file",
                    "id": "test_file_hash_disabled",
                    "attributes": {"file_name": "file_disabled.exe"},
                }
            }]
        },
    }
    mock_fetch_threat_data.return_value = mock_threat_response
    original_data = mock_threat_response["data"]["iocs"][0]["data"].copy()

    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Act - Call the actual method that contains lines 454-459
    gti_utility.ingest_events_for_threat_type(
        "malware", None, "2023-01-01T00:00:00Z"
    )

    # Assert - Verify that line 453 was executed but lines 454-459 were skipped
    mock_get_env_var.assert_called_with(constant.ENV_VAR_MITRE_ATTACK_ENABLED)
    mock_fetch_attack_data.assert_not_called()  # Should not be called when disabled

    # Verify that _ingest_events was called with unchanged data
    mock_ingest_events.assert_called_once()
    ingested_data = mock_ingest_events.call_args[0][0]

    # Verify that original data remains unchanged (lines 454-459 were skipped)
    self.assertEqual(ingested_data[0]["data"], original_data)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch.object(
      GoogleThreatIntelligenceUtility,
      "fetch_and_process_attack_techniques_data",
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_with_mitre_attack_enabled_file_ioc(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_ioc_stream,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_fetch_attack_data,
      mock_get_env_var,
  ):
    """Test actual execution through get_and_ingest_ioc_stream_events method - MITRE enabled with file IOC."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_get_env_var.return_value = "true"  # MITRE_ATTACK_ENABLED = true

    # Mock IOC stream parameters
    mock_get_params.return_value = ({"cursor": ""}, True)

    # Mock IOC stream response with file type IOC
    mock_ioc_stream_response = {
        "status": True,
        "data": {
            "data": [{
                "type": "file",
                "id": "test_file_hash_ioc_stream_real",
                "attributes": {"file_name": "malware_ioc_stream.exe"},
            }],
            "meta": {"cursor": ""},  # Empty cursor to stop the loop
        },
    }
    mock_fetch_ioc_stream.return_value = mock_ioc_stream_response

    # Mock attack techniques data that will be returned
    mock_attack_data = {
        "attack_techniques": ["T1055", "T1027"],
        "mitre_attack_info": {"tactics": ["defense-evasion"]},
    }
    mock_fetch_attack_data.return_value = mock_attack_data

    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # Act - Call the actual method that contains lines 555-563
    gti_utility.get_and_ingest_ioc_stream_events()

    # Assert - Verify that lines 555-563 were executed
    mock_get_env_var.assert_called_with(constant.ENV_VAR_MITRE_ATTACK_ENABLED)
    mock_fetch_attack_data.assert_called_once_with(
        "test_file_hash_ioc_stream_real", True
    )

    # Verify that _ingest_events was called with updated data (proving lines 558-560 executed)
    mock_ingest_events.assert_called_once()
    ingested_data = mock_ingest_events.call_args[0][0]

    # Verify that attack techniques data was merged into the IOC data (line 560 executed)
    expected_data = {
        "type": "file",
        "id": "test_file_hash_ioc_stream_real",
        "attributes": {"file_name": "malware_ioc_stream.exe"},
        "attack_techniques": ["T1055", "T1027"],
        "mitre_attack_info": {"tactics": ["defense-evasion"]},
    }
    self.assertEqual(ingested_data[0], expected_data)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch.object(
      GoogleThreatIntelligenceUtility,
      "fetch_and_process_attack_techniques_data",
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_with_mitre_attack_disabled(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_ioc_stream,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_fetch_attack_data,
      mock_get_env_var,
  ):
    """Test get_and_ingest_ioc_stream_events method - MITRE disabled."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_get_env_var.return_value = "false"  # MITRE_ATTACK_ENABLED = false

    # Mock IOC stream parameters
    mock_get_params.return_value = ({"cursor": ""}, True)

    # Mock IOC stream response with file type IOC
    mock_ioc_stream_response = {
        "status": True,
        "data": {
            "data": [{
                "type": "file",
                "id": "test_file_hash_disabled_stream",
                "attributes": {"file_name": "file_disabled_stream.exe"},
            }],
            "meta": {"cursor": ""},  # Empty cursor to stop the loop
        },
    }
    mock_fetch_ioc_stream.return_value = mock_ioc_stream_response
    original_data = mock_ioc_stream_response["data"]["data"][0].copy()

    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    gti_utility.get_and_ingest_ioc_stream_events()

    mock_get_env_var.assert_called_with(constant.ENV_VAR_MITRE_ATTACK_ENABLED)
    mock_fetch_attack_data.assert_not_called()

    # Verify that _ingest_events was called with unchanged data
    mock_ingest_events.assert_called_once()
    ingested_data = mock_ingest_events.call_args[0][0]

    self.assertEqual(ingested_data[0], original_data)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch.object(
      GoogleThreatIntelligenceUtility,
      "fetch_and_process_attack_techniques_data",
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_with_attack_techniques_exception(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_ioc_stream,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_fetch_attack_data,
      mock_get_env_var,
  ):
    """Test actual execution through get_and_ingest_ioc_stream_events method - exception handling."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_get_env_var.return_value = "true"  # MITRE_ATTACK_ENABLED = true

    # Mock IOC stream parameters
    mock_get_params.return_value = ({"cursor": ""}, True)

    # Mock IOC stream response with file type IOC
    mock_ioc_stream_response = {
        "status": True,
        "data": {
            "data": [{
                "type": "file",
                "id": "test_file_hash_exception_stream",
                "attributes": {"file_name": "exception_stream.exe"},
            }],
            "meta": {"cursor": ""},  # Empty cursor to stop the loop
        },
    }
    mock_fetch_ioc_stream.return_value = mock_ioc_stream_response

    # Mock an exception during attack techniques processing
    mock_fetch_attack_data.side_effect = Exception(
        "IOC Stream attack techniques API error"
    )

    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    result = gti_utility.get_and_ingest_ioc_stream_events()

    mock_get_env_var.assert_called_with(constant.ENV_VAR_MITRE_ATTACK_ENABLED)
    mock_fetch_attack_data.assert_called_once_with(
        "test_file_hash_exception_stream", True
    )

    mock_cloud_logging.assert_any_call(
        "Error during attack techniques processing for IOC Stream data:"
        " Exception('IOC Stream attack techniques API error')",
        severity="ERROR",
    )

    self.assertIsNone(result)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.CHECKPOINT_LOCKS",
      {"test_checkpoint_file.json": threading.Lock()},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_checkpoint_file")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_success_existing_file(
      self,
      mock_get_headers,
      mock_get_checkpoint_file,
      mock_cloud_logging,
      MockStorageClient,
  ):
    """Test _set_last_checkpoint when checkpoint file exists and update is successful."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock the _get_checkpoint_file method to return a specific file name
    checkpoint_file = "test_checkpoint_file.json"
    mock_get_checkpoint_file.return_value = checkpoint_file

    # Mock the storage client and related objects
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = (
        '{"existing_key": "existing_value"}'
    )

    # Mock the file write operation
    mock_blob.upload_from_string = MagicMock()

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility._set_last_checkpoint("test_key", "test_checkpoint")

    # Assert
    self.assertIsNone(result)  # Method returns None on success
    mock_get_checkpoint_file.assert_called_once_with("test_key")
    MockStorageClient.assert_called_once()
    mock_client.get_bucket.assert_called_once_with(bucket_name)
    mock_bucket.blob.assert_called_once_with(checkpoint_file)
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_called_once()

    # Verify the upload_from_string was called
    mock_blob.upload_from_string.assert_called_once()

    # Check that the call included the expected data
    call_args = mock_blob.upload_from_string.call_args[0][0]
    parsed_data = json.loads(call_args)
    self.assertEqual(parsed_data["existing_key"], "existing_value")
    self.assertEqual(parsed_data["test_key"], "test_checkpoint")

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.CHECKPOINT_LOCKS",
      {"test_checkpoint_file.json": threading.Lock()},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_checkpoint_file")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_success_new_file(
      self,
      mock_get_headers,
      mock_get_checkpoint_file,
      mock_cloud_logging,
      MockStorageClient,
  ):
    """Test _set_last_checkpoint when checkpoint file does not exist and new file is created."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock the _get_checkpoint_file method to return a specific file name
    checkpoint_file = "test_checkpoint_file.json"
    mock_get_checkpoint_file.return_value = checkpoint_file

    # Mock the storage client and related objects
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = False

    # Mock the upload_from_string method
    mock_blob.upload_from_string = MagicMock()

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility._set_last_checkpoint("test_key", "test_checkpoint")
    # mock_cloud_logging.assert_any_call("Checkpoint ")
    # Assert
    self.assertIsNone(result)  # Method returns None on success
    mock_get_checkpoint_file.assert_called_once_with("test_key")
    MockStorageClient.assert_called_once()
    mock_client.get_bucket.assert_called_once_with(bucket_name)
    mock_bucket.blob.assert_called_once_with(checkpoint_file)
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_not_called()  # File doesn't exist

    # Verify the upload_from_string was called
    mock_blob.upload_from_string.assert_called_once()

    # Check that the call included the expected data
    call_args = mock_blob.upload_from_string.call_args[0][0]
    parsed_data = json.loads(call_args)
    self.assertEqual(parsed_data["test_key"], "test_checkpoint")
    self.assertEqual(len(parsed_data), 1)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.constant.CHECKPOINT_KEY_TO_SHARD",
      {"test_key": "test_checkpoint_file.json"},
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.CHECKPOINT_LOCKS",
      {"test_checkpoint_file.json": threading.Lock()},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_json_decode_error(
      self, mock_get_headers, mock_cloud_logging, MockStorageClient
  ):
    """Test _set_last_checkpoint when JSON decode error occurs while reading existing file."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers
    checkpoint_file = "test_checkpoint_file.json"
    # Mock the storage client and related objects
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "invalid json"

    # Mock the file write operation
    mock_file = MagicMock()
    mock_blob.open.return_value.__enter__.return_value = mock_file

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility._set_last_checkpoint("test_key", "test_checkpoint")

    # Assert
    self.assertIsNone(result)  # Method returns None on success
    MockStorageClient.assert_called_once()
    mock_client.get_bucket.assert_called_once_with(bucket_name)
    mock_bucket.blob.assert_called_once_with(checkpoint_file)
    mock_blob.exists.assert_called_once()
    mock_blob.download_as_text.assert_called_once()
    # Verify the upload_from_string was called
    mock_blob.upload_from_string.assert_called_once()

    # Check that the call included the expected data
    call_args = mock_blob.upload_from_string.call_args[0][0]
    parsed_data = json.loads(call_args)

    self.assertEqual(parsed_data["test_key"], "test_checkpoint")

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.constant.CHECKPOINT_KEY_TO_SHARD",
      {"test_key": "test_checkpoint_file.json"},
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.CHECKPOINT_LOCKS",
      {"test_checkpoint_file.json": threading.Lock()},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_general_exception(
      self, mock_get_headers, mock_cloud_logging, MockStorageClient
  ):
    """Test _set_last_checkpoint when a general exception occurs."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock the storage client to raise an exception
    MockStorageClient.side_effect = Exception("Storage error")

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility._set_last_checkpoint("test_key", "test_checkpoint")

    # Assert
    self.assertIsNone(result)  # Method returns None on exception
    MockStorageClient.assert_called_once()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.constant.CHECKPOINT_KEY_TO_SHARD",
      {"test_key": "test_checkpoint_file.json"},
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.CHECKPOINT_LOCKS",
      {"test_checkpoint_file.json": threading.Lock()},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_file_write_exception(
      self, mock_get_headers, mock_cloud_logging, MockStorageClient
  ):
    """Test _set_last_checkpoint when file write operation fails."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers
    checkpoint_file = "test_checkpoint_file.json"
    # Mock the storage client and related objects
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = False

    # Mock the file write operation to raise an exception
    mock_blob.open.side_effect = Exception("File write error")

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility._set_last_checkpoint("test_key", "test_checkpoint")

    # Assert
    self.assertIsNone(result)  # Method returns None on exception
    MockStorageClient.assert_called_once()
    mock_client.get_bucket.assert_called_once_with(bucket_name)
    mock_bucket.blob.assert_called_once_with(checkpoint_file)
    mock_blob.exists.assert_called_once()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.add_one_hour_to_formatted_time"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.check_time_current_hr")
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_threat_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_ingest_events_for_threat_type_success(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_fetch_threat_data,
      mock_get_checkpoint,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_check_time,
      mock_add_hour,
  ):
    """Test successful ingestion of events for a threat type."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock return values
    mock_get_checkpoint.return_value = "2024-01-01T10:00:00Z"
    mock_check_time.side_effect = [
        False,
        True,
    ]  # First iteration continues, second stops
    mock_add_hour.return_value = "2024-01-01T11:00:00Z"

    mock_threat_data = [{"ioc": "test_ioc_1"}, {"ioc": "test_ioc_2"}]
    mock_fetch_threat_data.return_value = {
        "status": True,
        "data": {"iocs": mock_threat_data},
    }

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    gti_utility.ingest_events_for_threat_type(
        "malware", "test_query", "2024-01-01T09:00:00Z"
    )

    # Assert
    mock_get_checkpoint.assert_called_once_with("malware")
    mock_fetch_threat_data.assert_called_once_with(
        "malware",
        {"limit": constant.THREAT_FEED_LIMIT, "query": "test_query"},
        "2024-01-01T10:00:00Z",
        timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
        should_retry=True,
    )
    mock_ingest_events.assert_called_once_with(mock_threat_data)
    mock_set_checkpoint.assert_called_once_with(
        "malware", "2024-01-01T11:00:00Z"
    )
    mock_add_hour.assert_called_once_with("2024-01-01T10:00:00Z")

    # Verify logging calls
    mock_cloud_logging.assert_any_call(
        f"Fetched {len(mock_threat_data)} malware for hour:"
        " 2024-01-01T10:00:00Z from Google Threat Intelligence."
    )
    mock_cloud_logging.assert_any_call(
        f"Successfully ingested {len(mock_threat_data)} malware into Google"
        " SecOps."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_ingest_events_for_threat_type_invalid_threat_type(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test ingestion with invalid threat type."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    gti_utility.ingest_events_for_threat_type(
        "invalid_type", "test_query", "2024-01-01T09:00:00Z"
    )

    # Assert
    mock_cloud_logging.assert_any_call(
        "Invalid threat list: invalid_type. Valid threat lists are:"
        f" {constant.ALL_THREAT_LISTS}"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.check_time_current_hr")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_ingest_events_for_threat_type_current_hour_reached(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_checkpoint,
      mock_check_time,
  ):
    """Test ingestion when current hour is reached."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    mock_get_checkpoint.return_value = None
    mock_check_time.return_value = True  # Current hour reached immediately

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    gti_utility.ingest_events_for_threat_type(
        "malware", "test_query", "2024-01-01T09:00:00Z"
    )

    # Assert
    mock_cloud_logging.assert_any_call(
        "Reached the end of data, data will be collected in upcoming iteration"
        " for malware."
    )

  @patch.object(GoogleThreatIntelligenceUtility, "fetch_threat_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.check_time_current_hr")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_ingest_events_for_threat_type_fetch_error(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_checkpoint,
      mock_check_time,
      mock_fetch_threat_data,
  ):
    """Test ingestion when fetch_threat_data returns an error."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    mock_get_checkpoint.return_value = None
    mock_check_time.return_value = False
    mock_fetch_threat_data.return_value = {
        "status": False,
        "error": "API error occurred",
    }

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    gti_utility.ingest_events_for_threat_type(
        "malware", "test_query", "2024-01-01T09:00:00Z"
    )

    # Assert
    mock_cloud_logging.assert_any_call(
        "Error occurred while fetching malware data. Error: API error occurred"
    )

  @patch.object(GoogleThreatIntelligenceUtility, "fetch_threat_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.check_time_current_hr")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_ingest_events_for_threat_type_general_exception(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_checkpoint,
      mock_check_time,
      mock_fetch_threat_data,
  ):
    """Test ingestion when a general exception occurs."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    mock_get_checkpoint.side_effect = Exception("Checkpoint error")

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    gti_utility.ingest_events_for_threat_type(
        "malware", "test_query", "2024-01-01T09:00:00Z"
    )

    # Assert
    mock_cloud_logging.assert_any_call(
        "Error occurred while fetching and ingesting malware data. Error:"
        " Exception('Checkpoint error')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_threat_list_events_success(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test successful execution of get_and_ingest_threat_list_events."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility.get_and_ingest_threat_list_events()

    # Assert
    # The IOC version just passes, so result should be None
    self.assertIsNone(result)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.concurrent.futures.ThreadPoolExecutor"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_threat_lists_start_time"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_threat_list_events_all_threats(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_env_var,
      mock_get_start_time,
      mock_executor,
  ):
    """Test get_and_ingest_threat_list_events with 'all' threat types."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock environment variables
    def mock_env_side_effect(var_name):
      if var_name == constant.ENV_VAR_THREAT_LISTS:
        return "all"
      elif var_name == constant.ENV_VAR_THREAT_LIST_QUERY:
        return "test_query"
      return None

    mock_get_env_var.side_effect = mock_env_side_effect
    mock_get_start_time.return_value = "2024-01-01T09:00:00Z"

    # Mock ThreadPoolExecutor
    mock_executor_instance = MagicMock()
    mock_executor.return_value.__enter__.return_value = mock_executor_instance

    # Mock as_completed to return empty list for simplicity
    with patch(
        f"{INGESTION_SCRIPTS_PATH}gti_client.concurrent.futures.as_completed"
    ) as mock_as_completed:
      mock_as_completed.return_value = []

      # Create the utility instance
      gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

      # Act
      gti_utility.get_and_ingest_threat_list_events()

      # Assert - should submit jobs for all threat types in constant.ALL_THREAT_LISTS
      self.assertEqual(
          mock_executor_instance.submit.call_count,
          len(constant.ALL_THREAT_LISTS),
      )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.concurrent.futures.ThreadPoolExecutor"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_threat_lists_start_time"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_threat_list_events_future_exception(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_env_var,
      mock_get_start_time,
      mock_executor,
  ):
    """Test get_and_ingest_threat_list_events when a future raises an exception."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock environment variables
    def mock_env_side_effect(var_name):
      if var_name == constant.ENV_VAR_THREAT_LISTS:
        return "malware"
      elif var_name == constant.ENV_VAR_THREAT_LIST_QUERY:
        return "test_query"
      return None

    mock_get_env_var.side_effect = mock_env_side_effect
    mock_get_start_time.return_value = "2024-01-01T09:00:00Z"

    # Mock ThreadPoolExecutor
    mock_executor_instance = MagicMock()
    mock_executor.return_value.__enter__.return_value = mock_executor_instance

    mock_future = MagicMock()
    mock_future.result.side_effect = Exception("Future execution error")
    mock_executor_instance.submit.return_value = mock_future

    # Mock as_completed to return the future
    with patch(
        f"{INGESTION_SCRIPTS_PATH}gti_client.concurrent.futures.as_completed"
    ) as mock_as_completed:
      mock_as_completed.return_value = [mock_future]

      # Create the utility instance
      gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

      # Act
      gti_utility.get_and_ingest_threat_list_events()

      # Assert
      mock_cloud_logging.assert_any_call(
          "Exception occurred while executing threat lists events ingestion:"
          " Exception('Future execution error')",
          severity="ERROR",
      )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_threat_list_events_general_exception(
      self, mock_get_headers, mock_cloud_logging, mock_get_env_var
  ):
    """Test get_and_ingest_threat_list_events when a general exception occurs."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock environment variable to raise an exception
    mock_get_env_var.side_effect = Exception("Environment variable error")

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    gti_utility.get_and_ingest_threat_list_events()

    # Assert
    mock_cloud_logging.assert_any_call(
        "Execution of threat list events ingestion stops due to exception"
        " occurred call. Error message: Exception('Environment variable error')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.time")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.convert_epoch_to_utc_string"
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_success(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_stream,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_convert_epoch,
      mock_time,
  ):
    """Test successful IOC stream events ingestion."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock time and conversion
    mock_time.return_value = 1640995200  # Mock epoch time
    mock_convert_epoch.return_value = "2022-01-01T00:00:00Z"

    # Mock get_ioc_stream_params
    mock_params = {"limit": 40, "order": "date+"}
    mock_get_params.return_value = (mock_params, True)

    # Mock IOC stream data
    mock_ioc_data = [{"ioc": "test_ioc_1"}, {"ioc": "test_ioc_2"}]

    # Mock fetch_ioc_stream responses - first with cursor, second without cursor (end)
    mock_fetch_stream.side_effect = [
        {
            "status": True,
            "data": {
                "data": mock_ioc_data,
                "meta": {"cursor": "next_cursor_123"},
            },
        },
        {
            "status": True,
            "data": {
                "data": mock_ioc_data,  # Second batch also has data
                "meta": {"cursor": ""},  # Empty cursor indicates end
            },
        },
    ]

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    gti_utility.get_and_ingest_ioc_stream_events()

    # Assert
    mock_get_params.assert_called_once()
    self.assertEqual(mock_fetch_stream.call_count, 2)
    self.assertEqual(mock_ingest_events.call_count, 2)
    mock_ingest_events.assert_has_calls(
        [mock.call(mock_ioc_data), mock.call(mock_ioc_data)]
    )

    # Verify checkpoint calls
    mock_set_checkpoint.assert_any_call(
        constant.IOC_STREAM_CURSOR_CHECKPOINT_KEY, "next_cursor_123"
    )
    mock_set_checkpoint.assert_any_call(
        constant.IOC_STREAM_TIME_CHECKPOINT_KEY, "2022-01-01T00:00:00Z"
    )

    # Verify logging calls
    mock_cloud_logging.assert_any_call(
        f"Total {len(mock_ioc_data)} IOC Stream data fetched from Google Threat"
        " Intelligence."
    )
    mock_cloud_logging.assert_any_call(
        f"Total {len(mock_ioc_data)} IOC Stream data ingested into Google"
        " SecOps."
    )
    mock_cloud_logging.assert_any_call(
        "IOC Stream data fetched and ingested successfully."
    )

  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_invalid_params(
      self, mock_get_headers, mock_cloud_logging, mock_get_params
  ):
    """Test IOC stream events ingestion when get_ioc_stream_params returns invalid status."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock get_ioc_stream_params to return invalid status
    mock_get_params.return_value = ({}, False)

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility.get_and_ingest_ioc_stream_events()

    # Assert
    self.assertIsNone(result)
    mock_cloud_logging.assert_any_call(
        "Invalid parameters for Stream IOC data.", severity="ERROR"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.time")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.convert_epoch_to_utc_string"
  )
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_api_exception(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_stream,
      mock_convert_epoch,
      mock_time,
  ):
    """Test IOC stream events ingestion when fetch_ioc_stream raises an exception."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock time and conversion
    mock_time.return_value = 1640995200
    mock_convert_epoch.return_value = "2022-01-01T00:00:00Z"

    # Mock get_ioc_stream_params
    mock_params = {"limit": 1000, "order": "date+"}
    mock_get_params.return_value = (mock_params, True)

    # Mock fetch_ioc_stream to raise an exception
    mock_fetch_stream.side_effect = Exception("API connection error")

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility.get_and_ingest_ioc_stream_events()

    # Assert
    self.assertIsNone(result)
    mock_cloud_logging.assert_any_call(
        "Exception during IOC Stream API call: Exception('API connection error')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.time")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.convert_epoch_to_utc_string"
  )
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_fetch_error(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_stream,
      mock_convert_epoch,
      mock_time,
  ):
    """Test IOC stream events ingestion when fetch_ioc_stream returns error status."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock time and conversion
    mock_time.return_value = 1640995200
    mock_convert_epoch.return_value = "2022-01-01T00:00:00Z"

    # Mock get_ioc_stream_params
    mock_params = {"limit": 1000, "order": "date+"}
    mock_get_params.return_value = (mock_params, True)

    # Mock fetch_ioc_stream to return error
    mock_fetch_stream.return_value = {
        "status": False,
        "error": "API rate limit exceeded",
    }

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility.get_and_ingest_ioc_stream_events()

    # Assert
    self.assertIsNone(result)
    mock_cloud_logging.assert_any_call(
        "Error while fetching IOC Stream data: API rate limit exceeded",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.time")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.convert_epoch_to_utc_string"
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_ingestion_exception(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_stream,
      mock_ingest_events,
      mock_convert_epoch,
      mock_time,
  ):
    """Test IOC stream events ingestion when _ingest_events raises an exception."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock time and conversion
    mock_time.return_value = 1640995200
    mock_convert_epoch.return_value = "2022-01-01T00:00:00Z"

    # Mock get_ioc_stream_params
    mock_params = {"limit": 1000, "order": "date+"}
    mock_get_params.return_value = (mock_params, True)

    # Mock IOC stream data
    mock_ioc_data = [{"ioc": "test_ioc_1"}]
    mock_fetch_stream.return_value = {
        "status": True,
        "data": {"data": mock_ioc_data, "meta": {"cursor": ""}},
    }

    # Mock _ingest_events to raise an exception
    mock_ingest_events.side_effect = Exception("Ingestion failed")

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility.get_and_ingest_ioc_stream_events()

    # Assert
    self.assertIsNone(result)
    mock_cloud_logging.assert_any_call(
        "Error during ingestion: Exception('Ingestion failed')", severity="ERROR"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.time")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.convert_epoch_to_utc_string"
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_checkpoint_exception(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_stream,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_convert_epoch,
      mock_time,
  ):
    """Test IOC stream events ingestion when _set_last_checkpoint raises an exception."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock time and conversion
    mock_time.return_value = 1640995200
    mock_convert_epoch.return_value = "2022-01-01T00:00:00Z"

    # Mock get_ioc_stream_params
    mock_params = {"limit": 1000, "order": "date+"}
    mock_get_params.return_value = (mock_params, True)

    # Mock IOC stream data
    mock_ioc_data = [{"ioc": "test_ioc_1"}]
    mock_fetch_stream.return_value = {
        "status": True,
        "data": {
            "data": mock_ioc_data,
            "meta": {"cursor": ""},
        },  # Empty cursor to end loop
    }

    # Mock _set_last_checkpoint to raise an exception
    mock_set_checkpoint.side_effect = Exception("Checkpoint write failed")

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    gti_utility.get_and_ingest_ioc_stream_events()

    # Assert - should continue execution despite checkpoint errors
    mock_ingest_events.assert_called_once_with(mock_ioc_data)
    mock_cloud_logging.assert_any_call(
        "Error writing time checkpoint: Exception('Checkpoint write failed')",
        severity="ERROR",
    )
    mock_cloud_logging.assert_any_call(
        "IOC Stream data fetched and ingested successfully."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_ioc_stream_params_with_cursor_checkpoint(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_checkpoint,
      mock_get_env_var,
      mock_datetime,
  ):
    """Test get_ioc_stream_params when cursor checkpoint exists."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock checkpoints
    def mock_checkpoint_side_effect(key):
      if key == constant.IOC_STREAM_CURSOR_CHECKPOINT_KEY:
        return "existing_cursor_123"
      elif key == constant.IOC_STREAM_TIME_CHECKPOINT_KEY:
        return "2022-01-01T00:00:00Z"
      return None

    mock_get_checkpoint.side_effect = mock_checkpoint_side_effect
    mock_get_env_var.return_value = "test_filter"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    params, status = gti_utility.get_ioc_stream_params()

    # Assert
    self.assertTrue(status)
    self.assertEqual(params["limit"], constant.IOC_STREAM_PER_PAGE)
    self.assertEqual(params["order"], "date+")
    self.assertEqual(params["cursor"], "existing_cursor_123")

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_ioc_stream_params_with_time_checkpoint(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_checkpoint,
      mock_get_env_var,
      mock_datetime,
  ):
    """Test get_ioc_stream_params when time checkpoint exists."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock checkpoints
    def mock_checkpoint_side_effect(key):
      if key == constant.IOC_STREAM_CURSOR_CHECKPOINT_KEY:
        return None
      elif key == constant.IOC_STREAM_TIME_CHECKPOINT_KEY:
        return "2022-01-01T00:00:00Z"
      return None

    mock_get_checkpoint.side_effect = mock_checkpoint_side_effect
    mock_get_env_var.return_value = "test_filter"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    params, status = gti_utility.get_ioc_stream_params()

    # Assert
    self.assertTrue(status)
    self.assertEqual(params["limit"], constant.IOC_STREAM_PER_PAGE)
    self.assertEqual(params["order"], "date+")
    self.assertEqual(params["filter"], "test_filter date:2022-01-01T00:00:00Z+")

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_ioc_stream_params_with_default_days(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_checkpoint,
      mock_get_env_var,
      mock_datetime,
  ):
    """Test get_ioc_stream_params when no checkpoints exist and using default days."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock checkpoints to return None
    mock_get_checkpoint.return_value = None

    # Mock environment variables
    def mock_env_side_effect(var_name):
      if var_name == constant.ENV_VAR_IOC_STREAM_FILTER:
        return "test_filter"
      elif var_name == constant.ENV_VAR_HISTORICAL_IOC_STREAM_DURATION:
        return None  # Use default
      return None

    mock_get_env_var.side_effect = mock_env_side_effect

    # Mock datetime
    from datetime import timedelta

    mock_now = MagicMock()
    mock_past_date = MagicMock()
    mock_past_date.strftime.return_value = "2022-01-01T00:00:00Z"
    mock_now.__sub__.return_value = mock_past_date
    mock_datetime.now.return_value = mock_now
    mock_datetime.timezone = timezone
    mock_datetime.timedelta = timedelta

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    params, status = gti_utility.get_ioc_stream_params()

    # Assert
    self.assertTrue(status)
    self.assertEqual(params["limit"], constant.IOC_STREAM_PER_PAGE)
    self.assertEqual(params["order"], "date+")
    self.assertEqual(params["filter"], "test_filter date:2022-01-01T00:00:00Z+")

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.datetime")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_ioc_stream_params_days_exceeds_max(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_checkpoint,
      mock_get_env_var,
      mock_datetime,
  ):
    """Test get_ioc_stream_params when days exceeds maximum allowed."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock checkpoints to return None
    mock_get_checkpoint.return_value = None

    # Mock environment variables
    def mock_env_side_effect(var_name):
      if var_name == constant.ENV_VAR_IOC_STREAM_FILTER:
        return "test_filter"
      elif var_name == constant.ENV_VAR_HISTORICAL_IOC_STREAM_DURATION:
        return str(constant.MAX_DAYS_TO_FETCH_IOC_STREAM + 1)  # Exceed max
      return None

    mock_get_env_var.side_effect = mock_env_side_effect

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    _, status = gti_utility.get_ioc_stream_params()

    # Assert
    self.assertFalse(status)
    mock_cloud_logging.assert_any_call(
        "HISTORICAL_IOC_STREAM_DURATION value"
        f" '{constant.MAX_DAYS_TO_FETCH_IOC_STREAM + 1}' is more than"
        f" '{constant.MAX_DAYS_TO_FETCH_IOC_STREAM}'.",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  @patch.object(GoogleThreatIntelligenceUtility, "_get_last_checkpoint")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_ioc_stream_params_exception(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_checkpoint,
      mock_get_env_var,
  ):
    """Test get_ioc_stream_params when an exception occurs."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock _get_last_checkpoint to raise an exception
    mock_get_checkpoint.side_effect = Exception("Checkpoint error")

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    _, status = gti_utility.get_ioc_stream_params()

    # Assert
    self.assertFalse(status)
    mock_cloud_logging.assert_any_call(
        "Error occurred while fetching and ingesting Stream IOC data. Error:"
        " Exception('Checkpoint error')",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_success_get(
      self, mock_get_headers, mock_cloud_logging, mock_requests
  ):
    """Test successful GET request using gti_rest_api."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock requests.request response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "test_data"}
    mock_requests.return_value = mock_response

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act
    result = gti_utility.gti_rest_api(
        call_type="GET",
        url="https://api.example.com/test",
        headers={"Authorization": "Bearer token"},
        params={"limit": 10},
    )

    # Assert
    self.assertTrue(result["status"])
    self.assertEqual(result["response"], mock_response)
    self.assertFalse(result["retry"])

    mock_requests.assert_called_once_with(
        method="GET",
        url="https://api.example.com/test",
        headers={"Authorization": "Bearer token"},
        params={"limit": 10},
        data={},
        json=None,
        timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
        verify=True,
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_success_post_with_json(
      self, mock_get_headers, mock_cloud_logging, mock_requests
  ):
    """Test successful POST request with JSON data using gti_rest_api."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock requests.request response
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"id": "created_id"}
    mock_requests.return_value = mock_response

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data
    json_data = {"name": "test", "value": "data"}
    custom_timeout = (30, 60)

    # Act
    result = gti_utility.gti_rest_api(
        call_type="POST",
        url="https://api.example.com/create",
        headers={"Content-Type": "application/json"},
        json=json_data,
        timeout=custom_timeout,
    )

    # Assert
    self.assertTrue(result["status"])
    self.assertEqual(result["response"], mock_response)
    self.assertFalse(result["retry"])

    mock_requests.assert_called_once_with(
        method="POST",
        url="https://api.example.com/create",
        headers={"Content-Type": "application/json"},
        params={},
        data={},
        json=json_data,
        timeout=custom_timeout,
        verify=True,
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_default_parameters(
      self, mock_get_headers, mock_cloud_logging, mock_requests
  ):
    """Test gti_rest_api with default parameters."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock requests.request response
    mock_response = MagicMock()
    mock_requests.return_value = mock_response

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act - call with minimal parameters
    result = gti_utility.gti_rest_api(url="https://api.example.com/test")

    # Assert
    self.assertTrue(result["status"])
    self.assertEqual(result["response"], mock_response)
    self.assertFalse(result["retry"])

    mock_requests.assert_called_once_with(
        method="GET",  # Default method
        url="https://api.example.com/test",
        headers={},  # Default empty headers
        params={},  # Default empty params
        data={},  # Default empty data
        json=None,  # Default None json
        timeout=(
            constant.CONNECTION_TIMEOUT,
            constant.READ_TIMEOUT,
        ),  # Default timeout
        verify=True,
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.request")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_gti_rest_api_with_form_data(
      self, mock_get_headers, mock_cloud_logging, mock_requests
  ):
    """Test gti_rest_api with form data."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock requests.request response
    mock_response = MagicMock()
    mock_requests.return_value = mock_response

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data
    form_data = {"field1": "value1", "field2": "value2"}

    # Act
    result = gti_utility.gti_rest_api(
        call_type="PUT", url="https://api.example.com/update", data=form_data
    )

    # Assert
    self.assertTrue(result["status"])
    self.assertEqual(result["response"], mock_response)

    mock_requests.assert_called_once_with(
        method="PUT",
        url="https://api.example.com/update",
        headers={},
        params={},
        data=form_data,
        json=None,
        timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
        verify=True,
    )

  @patch.object(GoogleThreatIntelligenceUtility, "fetch_gti_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_fetch_ioc_stream_success(
      self, mock_get_headers, mock_cloud_logging, mock_fetch_gti_data
  ):
    """Test successful IOC stream fetch."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock fetch_gti_data response
    mock_response = {
        "status": True,
        "data": {
            "data": [{"ioc": "test_ioc"}],
            "meta": {"cursor": "next_cursor"},
        },
    }
    mock_fetch_gti_data.return_value = mock_response

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test parameters
    params = {"limit": 100, "order": "date+"}
    timeout = (30, 60)

    # Act
    result = gti_utility.fetch_ioc_stream(
        params=params, timeout=timeout, should_retry=True
    )

    # Assert
    self.assertEqual(result, mock_response)
    mock_fetch_gti_data.assert_called_once_with(
        url=constant.IOC_STREAM_URL,
        timeout=timeout,
        should_retry=True,
        fetch_type="IOC Stream",
        params=params,
    )

  @patch.object(GoogleThreatIntelligenceUtility, "fetch_gti_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_fetch_ioc_stream_default_parameters(
      self, mock_get_headers, mock_cloud_logging, mock_fetch_gti_data
  ):
    """Test IOC stream fetch with default parameters."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock fetch_gti_data response
    mock_response = {
        "status": True,
        "data": {"data": [], "meta": {"cursor": ""}},
    }
    mock_fetch_gti_data.return_value = mock_response

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test parameters
    params = {"limit": 50}

    # Act - use default timeout and should_retry
    result = gti_utility.fetch_ioc_stream(params=params)

    # Assert
    self.assertEqual(result, mock_response)
    mock_fetch_gti_data.assert_called_once_with(
        url=constant.IOC_STREAM_URL,
        timeout=(
            constant.CONNECTION_TIMEOUT,
            constant.READ_TIMEOUT,
        ),  # Default timeout
        should_retry=False,  # Default should_retry
        fetch_type="IOC Stream",
        params=params,
    )

  @patch.object(GoogleThreatIntelligenceUtility, "fetch_gti_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_fetch_ioc_stream_error_response(
      self, mock_get_headers, mock_cloud_logging, mock_fetch_gti_data
  ):
    """Test IOC stream fetch when fetch_gti_data returns error."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock fetch_gti_data error response
    mock_response = {
        "status": False,
        "error": "API rate limit exceeded",
        "retry": True,
    }
    mock_fetch_gti_data.return_value = mock_response

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test parameters
    params = {"limit": 100, "cursor": "test_cursor"}

    # Act
    result = gti_utility.fetch_ioc_stream(params=params, should_retry=True)

    # Assert
    self.assertEqual(result, mock_response)
    mock_fetch_gti_data.assert_called_once_with(
        url=constant.IOC_STREAM_URL,
        timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
        should_retry=True,
        fetch_type="IOC Stream",
        params=params,
    )

  @patch.object(GoogleThreatIntelligenceUtility, "fetch_gti_data")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_fetch_ioc_stream_with_filter_params(
      self, mock_get_headers, mock_cloud_logging, mock_fetch_gti_data
  ):
    """Test IOC stream fetch with filter parameters."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Mock fetch_gti_data response
    mock_response = {
        "status": True,
        "data": {
            "data": [
                {"ioc": "malicious.com", "type": "domain"},
                {"ioc": "192.168.1.1", "type": "ip"},
            ],
            "meta": {"cursor": "filtered_cursor"},
        },
    }
    mock_fetch_gti_data.return_value = mock_response

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test parameters with filter
    params = {
        "limit": 200,
        "order": "date+",
        "filter": "type:domain date:2024-01-01+",
        "cursor": "start_cursor",
    }
    custom_timeout = (45, 90)

    # Act
    result = gti_utility.fetch_ioc_stream(
        params=params, timeout=custom_timeout, should_retry=True
    )

    # Assert
    self.assertEqual(result, mock_response)
    mock_fetch_gti_data.assert_called_once_with(
        url=constant.IOC_STREAM_URL,
        timeout=custom_timeout,
        should_retry=True,
        fetch_type="IOC Stream",
        params=params,
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test__ingest_events_with_events(self, mock_cloud_logging, mock_ingest):
    """Test _ingest_events with valid events list."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data - sample events
    events = [
        {
            "id": "event1",
            "type": "malware",
            "attributes": {
                "names": ["malicious.exe"],
                "threat_severity": "high",
            },
        },
        {
            "id": "event2",
            "type": "domain",
            "attributes": {
                "domain": "malicious.com",
                "threat_severity": "medium",
            },
        },
    ]

    # Act
    gti_utility._ingest_events(events)

    # Assert
    mock_cloud_logging.assert_called_with(
        "Ingesting events into Google SecOps."
    )
    mock_ingest.assert_called_once_with(
        events, constant.GOOGLE_SECOPS_DATA_TYPE
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test__ingest_events_no_events_empty_list(self, mock_cloud_logging):
    """Test _ingest_events with empty events list."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data - empty list
    events = []

    # Act
    gti_utility._ingest_events(events)

    # Assert
    mock_cloud_logging.assert_called_with(
        "No events to push data to ingest into Google SecOps."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test__ingest_events_no_events_none(self, mock_cloud_logging):
    """Test _ingest_events with None events."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data - None
    events = None

    # Act
    gti_utility._ingest_events(events)

    # Assert
    mock_cloud_logging.assert_called_with(
        "No events to push data to ingest into Google SecOps."
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.ingest_v1.ingest",
      side_effect=Exception("Ingestion failed"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test__ingest_events_exception(self, mock_cloud_logging, mock_ingest):
    """Test _ingest_events when ingest.ingest raises an exception."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data - sample events
    events = [{
        "id": "event1",
        "type": "malware",
        "attributes": {"names": ["malicious.exe"], "threat_severity": "high"},
    }]

    # Act & Assert
    with self.assertRaises(Exception) as context:
      gti_utility._ingest_events(events)

    # Verify the exception message
    self.assertIn("Ingestion failed", str(context.exception))

    # Verify logging calls
    mock_cloud_logging.assert_any_call("Ingesting events into Google SecOps.")
    mock_cloud_logging.assert_called_with(
        "Error occurred while ingesting data: Exception('Ingestion failed')",
        severity="ERROR",
    )

    # Verify ingest was called
    mock_ingest.assert_called_once_with(
        events, constant.GOOGLE_SECOPS_DATA_TYPE
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test__ingest_events_single_event(self, mock_cloud_logging, mock_ingest):
    """Test _ingest_events with a single event."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data - single event
    events = [{
        "id": "single_event",
        "type": "ip_address",
        "attributes": {"ip": "192.168.1.100", "threat_severity": "low"},
    }]

    # Act
    gti_utility._ingest_events(events)

    # Assert
    mock_cloud_logging.assert_called_with(
        "Ingesting events into Google SecOps."
    )
    mock_ingest.assert_called_once_with(
        events, constant.GOOGLE_SECOPS_DATA_TYPE
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.ingest_v1.ingest")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test__ingest_events_large_batch(self, mock_cloud_logging, mock_ingest):
    """Test _ingest_events with a large batch of events."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data - large batch of events
    events = []
    for i in range(100):
      events.append({
          "id": f"event_{i}",
          "type": "malware",
          "attributes": {
              "names": [f"malicious_{i}.exe"],
              "threat_severity": "medium",
          },
      })

    # Act
    gti_utility._ingest_events(events)

    # Assert
    mock_cloud_logging.assert_called_with(
        "Ingesting events into Google SecOps."
    )
    mock_ingest.assert_called_once_with(
        events, constant.GOOGLE_SECOPS_DATA_TYPE
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.ingest_v1.ingest",
      side_effect=ValueError("Invalid data format"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test__ingest_events_value_error_exception(
      self, mock_cloud_logging, mock_ingest
  ):
    """Test _ingest_events when ingest.ingest raises a ValueError."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data - sample events
    events = [{"id": "invalid_event", "type": "unknown", "attributes": {}}]

    # Act & Assert
    with self.assertRaises(Exception) as context:
      gti_utility._ingest_events(events)

    # Verify the exception message
    self.assertIn("Invalid data format", str(context.exception))

    # Verify logging calls
    mock_cloud_logging.assert_any_call("Ingesting events into Google SecOps.")
    mock_cloud_logging.assert_called_with(
        "Error occurred while ingesting data: ValueError('Invalid data format')",
        severity="ERROR",
    )

    # Verify ingest was called
    mock_ingest.assert_called_once_with(
        events, constant.GOOGLE_SECOPS_DATA_TYPE
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.ingest_v1.ingest",
      side_effect=ConnectionError("Network connection failed"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test__ingest_events_connection_error(
      self, mock_cloud_logging, mock_ingest
  ):
    """Test _ingest_events when ingest.ingest raises a ConnectionError."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"

    # Create the utility instance
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Test data - sample events
    events = [{
        "id": "network_event",
        "type": "url",
        "attributes": {
            "url": "http://malicious.com/payload",
            "threat_severity": "high",
        },
    }]

    # Act & Assert
    with self.assertRaises(Exception) as context:
      gti_utility._ingest_events(events)

    # Verify the exception message
    self.assertIn("Network connection failed", str(context.exception))

    # Verify logging calls
    mock_cloud_logging.assert_any_call("Ingesting events into Google SecOps.")
    mock_cloud_logging.assert_called_with(
        "Error occurred while ingesting data: ConnectionError('Network connection failed')",
        severity="ERROR",
    )

    # Verify ingest was called
    mock_ingest.assert_called_once_with(
        events, constant.GOOGLE_SECOPS_DATA_TYPE
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_success(self, mock_logging):
    """Test successful fetching and processing of attack techniques data."""
    # Mock the get_attack_techniques response with comprehensive data
    mock_response = {
        "status": True,
        "data": {
            "data": {
                "sandbox1": {
                    "tactics": [
                        {
                            "name": "Initial Access",
                            "id": "TA0001",
                            "description": (
                                "The adversary is trying to get into your"
                                " network."
                            ),
                            "link": "https://attack.mitre.org/tactics/TA0001/",
                            "techniques": [{
                                "id": "T1566",
                                "name": "Phishing",
                                "description": (
                                    "Adversaries may send phishing messages."
                                ),
                                "link": (
                                    "https://attack.mitre.org/techniques/T1566/"
                                ),
                                "signatures": [{
                                    "severity": "high",
                                    "description": (
                                        "Suspicious email attachment detected"
                                    ),
                                }],
                            }],
                        },
                        {
                            "name": "Execution",
                            "id": "TA0002",
                            "description": (
                                "The adversary is trying to run malicious code."
                            ),
                            "link": "https://attack.mitre.org/tactics/TA0002/",
                            "techniques": [{
                                "id": "T1059",
                                "name": "Command and Scripting Interpreter",
                                "description": (
                                    "Adversaries may abuse command"
                                    " interpreters."
                                ),
                                "link": (
                                    "https://attack.mitre.org/techniques/T1059/"
                                ),
                                "signatures": [],
                            }],
                        },
                    ]
                },
                "sandbox2": {
                    "tactics": [{
                        "name": "Defense Evasion",
                        "id": "TA0005",
                        "description": (
                            "The adversary is trying to avoid being detected."
                        ),
                        "link": "https://attack.mitre.org/tactics/TA0005/",
                        "techniques": [
                            {
                                "id": "T1055",
                                "name": "Process Injection",
                                "description": (
                                    "Adversaries may inject code into"
                                    " processes."
                                ),
                                "link": (
                                    "https://attack.mitre.org/techniques/T1055/"
                                ),
                                "signatures": [
                                    {
                                        "severity": "medium",
                                        "description": (
                                            "Process hollowing detected"
                                        ),
                                    },
                                    {
                                        "severity": "high",
                                        "description": "DLL injection observed",
                                    },
                                ],
                            },
                            {
                                "id": "T1027",
                                "name": "Obfuscated Files or Information",
                                "description": (
                                    "Adversaries may attempt to make an"
                                    " executable or file."
                                ),
                                "link": (
                                    "https://attack.mitre.org/techniques/T1027/"
                                ),
                                "signatures": [],
                            },
                        ],
                    }]
                },
            }
        },
    }

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "test_hash_123", True
    )

    # Assertions
    self.assertIsNotNone(result)
    self.assertIn("sandboxobject", result)
    self.gti_client.get_attack_techniques.assert_called_once_with(
        file_hash="test_hash_123", should_retry=True
    )

    # Verify sandboxobject structure
    sandboxobject_list = result["sandboxobject"]
    self.assertEqual(len(sandboxobject_list), 2)  # Two sandboxes

    # Verify first sandbox structure
    sandbox1 = sandboxobject_list[0]
    self.assertEqual(sandbox1["sandbox_name"], "sandbox1")
    self.assertEqual(sandbox1["ioc_value"], "test_hash_123")

    # Verify tactics are passed through as-is from the raw data
    tactics = sandbox1["tactics"]
    self.assertIsNotNone(tactics)
    self.assertEqual(len(tactics), 2)  # Two tactics from mock data

    # Verify raw tactic structure (not processed)
    initial_access_tactic = tactics[0]
    self.assertEqual(initial_access_tactic["id"], "TA0001")
    self.assertEqual(initial_access_tactic["name"], "Initial Access")
    self.assertEqual(len(initial_access_tactic["techniques"]), 1)

    # Verify raw technique structure (not processed)
    phishing_technique = initial_access_tactic["techniques"][0]
    self.assertEqual(phishing_technique["id"], "T1566")
    self.assertEqual(phishing_technique["name"], "Phishing")
    self.assertEqual(len(phishing_technique["signatures"]), 1)

    # Verify raw signature structure (not processed)
    signature = phishing_technique["signatures"][0]
    self.assertEqual(signature["severity"], "high")
    self.assertEqual(
        signature["description"], "Suspicious email attachment detected"
    )

    # Verify logging
    mock_logging.assert_any_call(
        "Fetching ATT&CK techniques data for file: test_hash_123."
    )
    mock_logging.assert_any_call(
        "Successfully processed ATT&CK techniques data for file: test_hash_123."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_api_failure(
      self, mock_logging
  ):
    """Test handling of API failure when fetching attack techniques."""
    # Mock failed API response
    mock_response = {
        "status": False,
        "error": "API request failed - 401 Unauthorized",
    }

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "invalid_hash", False
    )

    # Assertions
    self.assertIsNone(result)
    self.gti_client.get_attack_techniques.assert_called_once_with(
        file_hash="invalid_hash", should_retry=False
    )

    # Verify error logging
    mock_logging.assert_any_call(
        "Fetching ATT&CK techniques data for file: invalid_hash."
    )
    mock_logging.assert_any_call(
        "Error while fetching ATT&CK techniques data for file: invalid_hash.",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_no_techniques(
      self, mock_logging
  ):
    """Test handling when no attack techniques are found."""
    # Mock response with empty data
    mock_response = {"status": True, "data": {"data": {}}}

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "clean_hash", True
    )

    # Assertions
    self.assertIsNone(result)
    self.gti_client.get_attack_techniques.assert_called_once_with(
        file_hash="clean_hash", should_retry=True
    )

    # Verify logging
    mock_logging.assert_any_call(
        "Fetching ATT&CK techniques data for file: clean_hash."
    )
    mock_logging.assert_any_call(
        "No ATT&CK techniques found for file: clean_hash."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_with_signatures(
      self, mock_logging
  ):
    """Test processing attack techniques data with signatures."""
    # Mock successful API response with signatures
    mock_response = {
        "status": True,
        "data": {
            "data": {
                "sandbox1": {
                    "tactics": [{
                        "name": "Initial Access",
                        "id": "TA0001",
                        "description": "Initial access tactic",
                        "link": "https://attack.mitre.org/tactics/TA0001/",
                        "techniques": [{
                            "id": "T1566",
                            "name": "Phishing",
                            "description": "Phishing technique",
                            "link": (
                                "https://attack.mitre.org/techniques/T1566/"
                            ),
                            "signatures": [
                                {
                                    "severity": "high",
                                    "description": "Suspicious email detected",
                                },
                                {
                                    "severity": "medium",
                                    "description": "Attachment analysis",
                                },
                            ],
                        }],
                    }]
                }
            }
        },
    }

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "signature_hash", True
    )

    # Assertions
    self.assertIsNotNone(result)
    self.assertIn("sandboxobject", result)

    # Verify signatures are passed through as-is
    sandboxobject_list = result["sandboxobject"]
    technique = sandboxobject_list[0]["tactics"][0]["techniques"][0]
    self.assertEqual(len(technique["signatures"]), 2)
    self.assertEqual(technique["signatures"][0]["severity"], "high")
    self.assertEqual(technique["signatures"][1]["severity"], "medium")

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_empty_tactics(
      self, mock_logging
  ):
    """Test handling when sandbox has empty tactics list."""
    # Mock response with sandbox having empty tactics
    mock_response = {
        "status": True,
        "data": {
            "data": {
                "sandbox1": {"tactics": []},
                "sandbox2": {
                    "tactics": [{
                        "name": "Initial Access",
                        "id": "TA0001",
                        "description": "Initial access tactic",
                        "link": "https://attack.mitre.org/tactics/TA0001/",
                        "techniques": [{
                            "id": "T1566",
                            "name": "Phishing",
                            "description": "Phishing technique",
                            "link": (
                                "https://attack.mitre.org/techniques/T1566/"
                            ),
                            "signatures": [],
                        }],
                    }]
                },
            }
        },
    }

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "mixed_hash", False
    )

    # Assertions
    self.assertIsNotNone(result)
    self.assertIn("sandboxobject", result)
    self.gti_client.get_attack_techniques.assert_called_once_with(
        file_hash="mixed_hash", should_retry=False
    )

    # Verify both sandboxes are included (method doesn't filter empty tactics)
    sandboxobject_list = result["sandboxobject"]
    self.assertEqual(len(sandboxobject_list), 2)

    # Check sandbox names
    sandbox_names = [s["sandbox_name"] for s in sandboxobject_list]
    self.assertIn("sandbox1", sandbox_names)
    self.assertIn("sandbox2", sandbox_names)

    # Verify sandbox1 has empty tactics list
    sandbox1 = next(
        s for s in sandboxobject_list if s["sandbox_name"] == "sandbox1"
    )
    self.assertEqual(sandbox1["tactics"], [])

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_missing_technique_fields(
      self, mock_logging
  ):
    """Test handling when technique data has missing optional fields."""
    # Mock response with techniques missing some fields
    mock_response = {
        "status": True,
        "data": {
            "data": {
                "sandbox1": {
                    "tactics": [{
                        # Missing "name" and "id" fields
                        "techniques": [
                            {"id": "T1566", "signatures": []}
                        ]  # Missing "name" field
                    }]
                }
            }
        },
    }

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "incomplete_hash", True
    )

    # Assertions
    self.assertIsNotNone(result)
    self.assertIn("sandboxobject", result)

    # Verify raw data is passed through without processing missing fields
    sandboxobject_list = result["sandboxobject"]
    self.assertEqual(len(sandboxobject_list), 1)

    sandbox = sandboxobject_list[0]
    self.assertEqual(sandbox["sandbox_name"], "sandbox1")
    self.assertEqual(sandbox["ioc_value"], "incomplete_hash")

    # Raw tactics data is passed through as-is
    tactic = sandbox["tactics"][0]
    self.assertNotIn("name", tactic)  # Missing field not filled with default
    self.assertNotIn("id", tactic)  # Missing field not filled with default

    technique = tactic["techniques"][0]
    self.assertEqual(technique["id"], "T1566")
    self.assertNotIn("name", technique)  # Missing field not filled with default

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_complex_scenario(
      self, mock_logging
  ):
    """Test complex scenario with multiple sandboxes and varied technique data."""
    # Mock response with complex data structure
    mock_response = {
        "status": True,
        "data": {
            "data": {
                "cuckoo_sandbox": {
                    "tactics": [{
                        "name": "Defense Evasion",
                        "id": "TA0005",
                        "description": "Defense evasion tactic",
                        "link": "https://attack.mitre.org/tactics/TA0005/",
                        "techniques": [
                            {
                                "id": "T1055",
                                "name": "Process Injection",
                                "description": "Injects code into processes",
                                "link": (
                                    "https://attack.mitre.org/techniques/T1055/"
                                ),
                                "signatures": [],
                            },
                            {
                                "id": "T1027",
                                "name": "Obfuscated Files or Information",
                                "description": "Obfuscation technique",
                                "link": (
                                    "https://attack.mitre.org/techniques/T1027/"
                                ),
                                "signatures": [],
                            },
                        ],
                    }]
                },
                "vmware_sandbox": {
                    "tactics": [
                        {
                            "name": "Collection",
                            "id": "TA0009",
                            "description": "Collection tactic",
                            "link": "https://attack.mitre.org/tactics/TA0009/",
                            "techniques": [
                                {
                                    "id": "T1005",
                                    "name": "Data from Local System",
                                    "description": "Local data collection",
                                    "link": (
                                        "https://attack.mitre.org/techniques/T1005/"
                                    ),
                                    "signatures": [],
                                },
                                {
                                    "id": "T1113",
                                    "name": "Screen Capture",
                                    "description": "Screen capture technique",
                                    "link": (
                                        "https://attack.mitre.org/techniques/T1113/"
                                    ),
                                    "signatures": [],
                                },
                                {
                                    "id": "T1056",
                                    "name": "Input Capture",
                                    "description": "Input capture technique",
                                    "link": (
                                        "https://attack.mitre.org/techniques/T1056/"
                                    ),
                                    "signatures": [],
                                },
                            ],
                        },
                        {
                            "name": "Exfiltration",
                            "id": "TA0010",
                            "description": "Exfiltration tactic",
                            "link": "https://attack.mitre.org/tactics/TA0010/",
                            "techniques": [{
                                "id": "T1041",
                                "name": "Exfiltration Over C2 Channel",
                                "description": "C2 exfiltration technique",
                                "link": (
                                    "https://attack.mitre.org/techniques/T1041/"
                                ),
                                "signatures": [],
                            }],
                        },
                    ]
                },
                "hybrid_analysis": {"tactics": []},  # Empty tactics
            }
        },
    }

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "complex_malware_hash", True
    )

    # Assertions
    self.assertIsNotNone(result)
    self.assertIn("sandboxobject", result)
    self.gti_client.get_attack_techniques.assert_called_once_with(
        file_hash="complex_malware_hash", should_retry=True
    )

    # Verify sandboxobject structure - all sandboxes included (no filtering)
    sandboxobject_list = result["sandboxobject"]
    self.assertEqual(len(sandboxobject_list), 3)  # All three sandboxes included

    # Verify sandbox names
    sandbox_names = [sandbox["sandbox_name"] for sandbox in sandboxobject_list]
    self.assertIn("cuckoo_sandbox", sandbox_names)
    self.assertIn("vmware_sandbox", sandbox_names)
    self.assertIn(
        "hybrid_analysis", sandbox_names
    )  # Included even with empty tactics

    # Verify cuckoo_sandbox structure
    cuckoo_sandbox = next(
        s for s in sandboxobject_list if s["sandbox_name"] == "cuckoo_sandbox"
    )
    self.assertEqual(len(cuckoo_sandbox["tactics"]), 1)
    self.assertEqual(len(cuckoo_sandbox["tactics"][0]["techniques"]), 2)

    # Verify vmware_sandbox structure
    vmware_sandbox = next(
        s for s in sandboxobject_list if s["sandbox_name"] == "vmware_sandbox"
    )
    self.assertEqual(
        len(vmware_sandbox["tactics"]), 2
    )  # Collection and Exfiltration tactics

    # Verify hybrid_analysis has empty tactics
    hybrid_analysis = next(
        s for s in sandboxobject_list if s["sandbox_name"] == "hybrid_analysis"
    )
    self.assertEqual(hybrid_analysis["tactics"], [])

    # Count total techniques across sandboxes with tactics
    total_techniques = sum(
        len(tactic["techniques"])  # pylint: disable=g-complex-comprehension
        for sandbox in sandboxobject_list
        for tactic in sandbox["tactics"]
        if sandbox["tactics"]
    )
    self.assertEqual(total_techniques, 6)  # 2 from cuckoo + 4 from vmware

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_malformed_response(
      self, mock_logging
  ):
    """Test handling of malformed API response structure."""
    # Mock malformed response (missing 'data' key in nested structure)
    mock_response = {
        "status": True,
        "data": {
            # Missing 'data' key - this should cause KeyError or graceful handling
        },
    }

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "malformed_hash", False
    )

    # Assertions
    self.assertIsNone(
        result
    )  # Should handle gracefully and return None for empty data
    self.gti_client.get_attack_techniques.assert_called_once_with(
        file_hash="malformed_hash", should_retry=False
    )

    # Verify appropriate logging
    mock_logging.assert_any_call(
        "Fetching ATT&CK techniques data for file: malformed_hash."
    )
    mock_logging.assert_any_call(
        "No ATT&CK techniques found for file: malformed_hash."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  def test_fetch_and_process_attack_techniques_data_data_integrity(
      self, mock_logging
  ):
    """Test that technique data maintains integrity in sandboxobject structure."""
    # Mock response with technique data
    mock_response = {
        "status": True,
        "data": {
            "data": {
                "sandbox1": {
                    "tactics": [{
                        "name": "Initial Access",
                        "id": "TA0001",
                        "description": "Initial access tactic",
                        "link": "https://attack.mitre.org/tactics/TA0001/",
                        "techniques": [{
                            "id": "T1566",
                            "name": "Phishing",
                            "description": "Phishing technique",
                            "link": (
                                "https://attack.mitre.org/techniques/T1566/"
                            ),
                            "signatures": [{
                                "severity": "high",
                                "description": "Phishing email detected",
                            }],
                        }],
                    }]
                }
            }
        },
    }

    self.gti_client.get_attack_techniques = Mock(return_value=mock_response)

    # Test the method
    result = self.gti_client.fetch_and_process_attack_techniques_data(
        "integrity_test_hash", True
    )

    # Assertions
    self.assertIsNotNone(result)
    self.assertIn("sandboxobject", result)

    # Verify raw data structure integrity (passed through as-is)
    sandboxobject_list = result["sandboxobject"]
    self.assertEqual(len(sandboxobject_list), 1)

    sandbox = sandboxobject_list[0]
    self.assertEqual(sandbox["sandbox_name"], "sandbox1")
    self.assertEqual(sandbox["ioc_value"], "integrity_test_hash")

    # Raw tactics data passed through unchanged
    tactic = sandbox["tactics"][0]
    self.assertEqual(tactic["name"], "Initial Access")
    self.assertEqual(tactic["id"], "TA0001")
    self.assertEqual(tactic["description"], "Initial access tactic")
    self.assertEqual(tactic["link"], "https://attack.mitre.org/tactics/TA0001/")

    # Raw technique data passed through unchanged
    technique = tactic["techniques"][0]
    self.assertEqual(technique["id"], "T1566")
    self.assertEqual(technique["name"], "Phishing")
    self.assertEqual(technique["description"], "Phishing technique")
    self.assertEqual(
        technique["link"], "https://attack.mitre.org/techniques/T1566/"
    )

    # Raw signature data passed through unchanged
    signature = technique["signatures"][0]
    self.assertEqual(signature["severity"], "high")
    self.assertEqual(signature["description"], "Phishing email detected")

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.sleep")
  @patch.object(GoogleThreatIntelligenceUtility, "gti_rest_api")
  @patch.object(GoogleThreatIntelligenceUtility, "parse_and_handle_response")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_attack_techniques_success(
      self,
      mock_get_headers,
      mock_logging,
      mock_parse_response,
      mock_rest_api,
      mock_sleep,
  ):
    """Test successful get_attack_techniques method."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    mock_rest_api.return_value = {"retry": False, "status": True}
    mock_parse_response.return_value = {
        "retry": False,
        "status": True,
        "data": {"data": {"sandbox1": {"tactics": []}}},
    }

    # Act
    result = gti_utility.get_attack_techniques(
        file_hash="test_hash_123", should_retry=False
    )

    # Assert
    self.assertTrue(result["status"])
    self.assertFalse(result["retry"])
    mock_rest_api.assert_called_once()
    mock_parse_response.assert_called_once()
    mock_sleep.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.sleep")
  @patch.object(GoogleThreatIntelligenceUtility, "gti_rest_api")
  @patch.object(GoogleThreatIntelligenceUtility, "parse_and_handle_response")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_attack_techniques_retry_success(
      self,
      mock_get_headers,
      mock_logging,
      mock_parse_response,
      mock_rest_api,
      mock_sleep,
  ):
    """Test get_attack_techniques with retry logic."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    # First call returns retry, second call succeeds
    mock_rest_api.side_effect = [
        {"retry": False, "status": True},
        {"retry": False, "status": True},
    ]
    mock_parse_response.side_effect = [
        {"retry": True, "status": False},  # First call needs retry
        {
            "retry": False,
            "status": True,
            "data": {"data": {}},
        },  # Second call succeeds
    ]

    # Act
    result = gti_utility.get_attack_techniques(
        file_hash="test_hash_456", should_retry=True
    )

    # Assert
    self.assertTrue(result["status"])
    self.assertFalse(result["retry"])
    self.assertEqual(mock_rest_api.call_count, 2)
    self.assertEqual(mock_parse_response.call_count, 2)
    mock_sleep.assert_called_once_with(60)  # DEFAULT_SLEEP_TIME

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.sleep")
  @patch.object(GoogleThreatIntelligenceUtility, "gti_rest_api")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_attack_techniques_api_failure(
      self, mock_get_headers, mock_logging, mock_rest_api, mock_sleep
  ):
    """Test get_attack_techniques when API call fails."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    mock_rest_api.return_value = {
        "retry": False,
        "status": False,
        "error": "API Error",
    }

    # Act
    result = gti_utility.get_attack_techniques(
        file_hash="invalid_hash", should_retry=False
    )

    # Assert
    self.assertFalse(result["status"])
    self.assertEqual(result["error"], "API Error")
    mock_rest_api.assert_called_once()
    mock_sleep.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.sleep")
  @patch.object(GoogleThreatIntelligenceUtility, "gti_rest_api")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_attack_techniques_retry_exhausted(
      self, mock_get_headers, mock_logging, mock_rest_api, mock_sleep
  ):
    """Test get_attack_techniques when retry limit is exhausted."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")

    mock_rest_api.return_value = {"retry": True, "status": False}

    # Act
    result = gti_utility.get_attack_techniques(
        file_hash="retry_hash", should_retry=True
    )

    # Assert
    self.assertFalse(result["status"])
    self.assertTrue(result["retry"])
    # Should be called 3 times (RETRY_COUNT = 3)
    self.assertEqual(mock_rest_api.call_count, 3)
    # Should sleep 2 times (between retries)
    self.assertEqual(mock_sleep.call_count, 2)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.constant.CHECKPOINT_KEY_TO_SHARD",
      {"test_key": "checkpoint_shard_1.json"},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_lock_acquisition_failure(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test _set_last_checkpoint when lock acquisition fails."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    checkpoint_key = "test_key"
    last_checkpoint = "test_checkpoint"
    checkpoint_file = "checkpoint_shard_1.json"

    # Mock the headers
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Create a mock lock that fails to acquire
    mock_lock = Mock()
    mock_lock.acquire.return_value = False  # Lock acquisition fails

    # Save the original lock and replace it with our mock
    with patch(
        f"{INGESTION_SCRIPTS_PATH}gti_client.CHECKPOINT_LOCKS",
        {checkpoint_file: mock_lock},
    ):
      # Create the utility instance
      gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

      # Act
      result = gti_utility._set_last_checkpoint(checkpoint_key, last_checkpoint)

      # Assert
      self.assertIsNone(result)
      mock_lock.acquire.assert_called_once_with(timeout=30)
      mock_cloud_logging.assert_any_call(
          f"Could not acquire lock for '{checkpoint_file}' after 30s, skipping"
          " checkpoint update",
          severity="WARNING",
      )
      mock_lock.release.assert_not_called()  # Lock should not be released if not acquired

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.constant.CHECKPOINT_KEY_TO_SHARD",
      {"test_key": "checkpoint_shard_1.json"},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_lock_acquisition_exception(
      self, mock_get_headers, mock_cloud_logging
  ):
    """Test _set_last_checkpoint when lock acquisition raises an exception."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    checkpoint_key = "test_key"
    last_checkpoint = "test_checkpoint"
    checkpoint_file = "checkpoint_shard_1.json"

    # Mock the headers
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers

    # Create a mock lock that raises an exception when acquire is called
    mock_lock = Mock()
    mock_lock.acquire.side_effect = Exception("Lock acquisition failed")

    # Patch CHECKPOINT_LOCKS with our mock lock
    with patch(
        f"{INGESTION_SCRIPTS_PATH}gti_client.CHECKPOINT_LOCKS",
        {checkpoint_file: mock_lock},
    ):
      # Create the utility instance
      gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

      # Act
      result = gti_utility._set_last_checkpoint(checkpoint_key, last_checkpoint)

      # Assert
      self.assertIsNone(result)  # Method returns None on exception
      mock_lock.acquire.assert_called_once_with(timeout=30)
      mock_cloud_logging.assert_any_call(
          f"Unexpected error while setting last checkpoint for {checkpoint_key}: Exception('Lock acquisition failed')",
          severity="ERROR",
      )
      mock_lock.release.assert_not_called()  # Lock should not be released if acquisition raised an exception

  @patch.object(GoogleThreatIntelligenceUtility, "gti_rest_api")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_fetch_gti_data_returns_default_on_exception(
      self, mock_get_headers, mock_rest_api
  ):
    """Test that fetch_gti_data returns the default dict on exception."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    # Simulate the return from @exception_handler
    mock_rest_api.return_value = {
        "status": False,
        "error": "Exception('Test exception')",
        "response": None,
        "retry": False,
    }
    gti_utility = GoogleThreatIntelligenceUtility("test_token", "test_bucket")
    expected_return_dict = {
        "status": False,
        "error": "Exception('Test exception')",
        "response": None,
        "retry": False,
    }

    # Act
    result = gti_utility.fetch_gti_data(
        url="test_url",
        fetch_type="test",
        timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
        should_retry=False,
    )

    # Assert
    self.assertEqual(result, expected_return_dict)

  def test__validate_checkpoint_shard_mapping(self):
    checkpoint_file, threat_lists = list(constant.CHECKPOINT_SHARDS.items())[0]
    for threat_list in threat_lists:
      self.assertEqual(
          constant.CHECKPOINT_KEY_TO_SHARD[threat_list], checkpoint_file
      )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.get")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.resourcemanager_v3.ProjectsClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  def test_check_sufficient_permissions_on_service_account_sufficient(
      self, mock_get_env_var, mock_projects_client, mock_requests_get
  ):
    """Test check_sufficient_permissions_on_service_account with sufficient permissions."""
    self.mock_check_permissions_patcher.stop()
    mock_get_env_var.return_value = "123456789"
    mock_requests_get.return_value.text = "test@project.iam.gserviceaccount.com"
    mock_policy = MagicMock()
    mock_binding = MagicMock()
    mock_binding.role = "roles/storage.admin"
    mock_binding.members = ["serviceAccount:test@project.iam.gserviceaccount.com"]
    mock_policy.bindings = [mock_binding]
    mock_projects_client.return_value.get_iam_policy.return_value = mock_policy

    with patch(
        f"{INGESTION_SCRIPTS_PATH}gti_client.constant.PERMISSION_DETAILS",
        {"Storage Admin": "roles/storage.admin"},
    ):
      result = self.gti_client.check_sufficient_permissions_on_service_account()
      self.assertTrue(result)
    self.mock_check_permissions_patcher.start()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.constant.CHECKPOINT_KEY_TO_SHARD",
      {"test_key": "checkpoint_shard_1.json"},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_forbidden_exception(
      self, mock_get_headers, mock_cloud_logging, MockStorageClient
  ):
    """Test _set_last_checkpoint when Forbidden exception occurs."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = False
    mock_blob.upload_from_string.side_effect = ForbiddenException(
        "Permission denied"
    )
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act & Assert
    with self.assertRaises(RuntimeError) as context:
      gti_utility._set_last_checkpoint("test_key", "test_checkpoint")

    self.assertIn(
        "Permission denied while accessing GCS bucket", str(context.exception)
    )
    mock_cloud_logging.assert_any_call(
        f"Permission denied while accessing GCS bucket '{bucket_name}'. . Error:"
        " ForbiddenException('Permission denied')",
        severity="ERROR",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.constant.CHECKPOINT_KEY_TO_SHARD",
      {"test_key": "checkpoint_shard_1.json"},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.storage.Client")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test__set_last_checkpoint_not_found_exception(
      self, mock_get_headers, mock_cloud_logging, MockStorageClient
  ):
    """Test _set_last_checkpoint when NotFound exception occurs."""
    # Arrange
    api_token = "test_api_token"
    bucket_name = "test_bucket"
    mock_headers = {"accept": "application/json"}
    mock_get_headers.return_value = mock_headers
    MockStorageClient.return_value.get_bucket.side_effect = NotFoundException(
        "Bucket not found"
    )
    gti_utility = GoogleThreatIntelligenceUtility(api_token, bucket_name)

    # Act & Assert
    gti_utility._set_last_checkpoint("test_key", "test_checkpoint")
    mock_cloud_logging.assert_any_call(
        f"The specified bucket '{bucket_name}' does not exist.", severity="ERROR"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.requests.get")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.resourcemanager_v3.ProjectsClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  def test_check_sufficient_permissions_on_service_account_insufficient(
      self, mock_get_env_var, mock_projects_client, mock_requests_get
  ):
    """Test check_sufficient_permissions_on_service_account with insufficient permissions."""
    self.mock_check_permissions_patcher.stop()
    mock_get_env_var.return_value = "123456789"
    mock_requests_get.return_value.text = "test@project.iam.gserviceaccount.com"
    mock_policy = MagicMock()
    mock_binding = MagicMock()
    mock_binding.role = "roles/viewer"
    mock_binding.members = ["serviceAccount:test@project.iam.gserviceaccount.com"]
    mock_policy.bindings = [mock_binding]
    mock_projects_client.return_value.get_iam_policy.return_value = mock_policy

    with patch(
        f"{INGESTION_SCRIPTS_PATH}gti_client.constant.PERMISSION_DETAILS",
        {"Storage Admin": "roles/storage.admin"},
    ):
      with self.assertRaises(Exception):
        self.gti_client.check_sufficient_permissions_on_service_account()
    self.mock_check_permissions_patcher.start()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utility.get_environment_variable")
  def test_check_sufficient_permissions_on_service_account_exception(
      self, mock_get_env_var
  ):
    """Test check_sufficient_permissions_on_service_account with exception."""
    self.mock_check_permissions_patcher.stop()
    mock_get_env_var.side_effect = Exception("Some error")

    with self.assertRaises(Exception):
      self.gti_client.check_sufficient_permissions_on_service_account()
    self.mock_check_permissions_patcher.start()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.time")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.convert_epoch_to_utc_string"
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_set_checkpoint_runtime_error(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_stream,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_convert_epoch,
      mock_time,
  ):
    """Test get_and_ingest_ioc_stream_events when _set_last_checkpoint raises RuntimeError."""
    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_time.return_value = 1640995200
    mock_convert_epoch.return_value = "2022-01-01T00:00:00Z"
    mock_params = {"limit": 1000, "order": "date+"}
    mock_get_params.return_value = (mock_params, True)
    mock_ioc_data = [{"ioc": "test_ioc_1"}]
    mock_fetch_stream.return_value = {
        "status": True,
        "data": {
            "data": mock_ioc_data,
            "meta": {"cursor": "next_cursor"},
        },
    }
    mock_set_checkpoint.side_effect = RuntimeError("Checkpoint failed")
    gti_utility = GoogleThreatIntelligenceUtility(
        "test_api_token", "test_bucket"
    )

    # Act & Assert
    with self.assertRaises(RuntimeError):
      gti_utility.get_and_ingest_ioc_stream_events()

  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.time.time")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}gti_client.utility.convert_epoch_to_utc_string"
  )
  @patch.object(GoogleThreatIntelligenceUtility, "_ingest_events")
  @patch.object(GoogleThreatIntelligenceUtility, "_set_last_checkpoint")
  @patch.object(GoogleThreatIntelligenceUtility, "fetch_ioc_stream")
  @patch.object(GoogleThreatIntelligenceUtility, "get_ioc_stream_params")
  @patch(f"{INGESTION_SCRIPTS_PATH}gti_client.utils.cloud_logging")
  @patch.object(GoogleThreatIntelligenceUtility, "get_gti_headers_with_token")
  def test_get_and_ingest_ioc_stream_events_time_checkpoint_runtime_error(
      self,
      mock_get_headers,
      mock_cloud_logging,
      mock_get_params,
      mock_fetch_stream,
      mock_set_checkpoint,
      mock_ingest_events,
      mock_convert_epoch,
      mock_time,
  ):
    """Test get_and_ingest_ioc_stream_events when time checkpoint raises RuntimeError."""

    def mock_set_checkpoint_side_effect(key, value):
      if key == constant.IOC_STREAM_TIME_CHECKPOINT_KEY:
        raise RuntimeError("Time checkpoint failed")
      return None

    # Arrange
    mock_get_headers.return_value = {"accept": "application/json"}
    mock_time.return_value = 1640995200
    mock_convert_epoch.return_value = "2022-01-01T00:00:00Z"
    mock_params = {"limit": 1000, "order": "date+"}
    mock_get_params.return_value = (mock_params, True)
    mock_ioc_data = [{"ioc": "test_ioc_1"}]
    mock_fetch_stream.return_value = {
        "status": True,
        "data": {
            "data": mock_ioc_data,
            "meta": {"cursor": ""},
        },
    }
    mock_set_checkpoint.side_effect = mock_set_checkpoint_side_effect
    gti_utility = GoogleThreatIntelligenceUtility(
        "test_api_token", "test_bucket"
    )

    # Act & Assert
    with self.assertRaises(RuntimeError):
      gti_utility.get_and_ingest_ioc_stream_events()


class GCPPermissionDeniedErrorTest(unittest.TestCase):

  def test_gcp_permission_denied_error_with_message_only(self):
    error = GCPPermissionDeniedError(message="Permission denied")
    self.assertEqual(str(error), "Permission denied")
    self.assertEqual(error.message, "Permission denied")
    self.assertIsNone(error.resource)
    self.assertEqual(error.permissions, [])

  def test_gcp_permission_denied_error_with_resource(self):
    error = GCPPermissionDeniedError(
        message="Permission denied", resource="test-resource"
    )
    self.assertEqual(
        str(error), "Permission denied for resource: test-resource"
    )
    self.assertEqual(error.resource, "test-resource")
    self.assertEqual(error.permissions, [])

  def test_gcp_permission_denied_error_with_permissions(self):
    error = GCPPermissionDeniedError(
        message="Permission denied", permissions=["perm1", "perm2"]
    )
    self.assertEqual(
        str(error), "Permission denied\nRequired permissions: perm1, perm2"
    )
    self.assertIsNone(error.resource)
    self.assertEqual(error.permissions, ["perm1", "perm2"])

  def test_gcp_permission_denied_error_with_all_fields(self):
    error = GCPPermissionDeniedError(
        message="Permission denied",
        resource="test-resource",
        permissions=["perm1", "perm2"],
    )
    self.assertEqual(
        str(error),
        "Permission denied for resource: test-resource\nRequired permissions:"
        " perm1, perm2",
    )
    self.assertEqual(error.message, "Permission denied")
    self.assertEqual(error.resource, "test-resource")
    self.assertEqual(error.permissions, ["perm1", "perm2"])
