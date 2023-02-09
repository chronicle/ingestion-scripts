# Copyright 2023 Google LLC
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
"""Unit Test case file for Trend Micro ingestion script."""
import sys

import unittest
from unittest import mock

import requests

INGESTION_SCRIPTS_PATH = ""
SCRIPT_PATH = ""

# Mock the chronicle library
sys.modules[f"{INGESTION_SCRIPTS_PATH}common.ingest"] = mock.MagicMock()

import main

INGESTION_COMPLETE = "Ingestion completed."


def get_mock_http_response(status_code: int, content=""):
  """Function that will return dummy response object based on provided status code and content."""
  response = requests.Response()
  response.status_code = status_code
  response._content = content.encode()
  return response


class TestTrendMicroIngestion(unittest.TestCase):
  """Test cases for Trend Micro ingestion script."""

  def test_validate_params_for_invalid_services(self):
    """Test case to verify that the client should raise InvalidValueError when invalid services are provided."""
    with self.assertRaises(main.InvalidValueError) as error:
      main.validate_params(["dummy_service"], ["securityrisk"])

    assert str(error.exception) == (
        "Validation error: Invalid value provided for service. Supported "
        "values are: ['exchange', 'sharepoint', 'onedrive', 'dropbox', 'box',"
        " 'googledrive', 'gmail', 'teams', 'exchangeserver', "
        "'salesforce_sandbox', 'salesforce_production', 'teams_chat']")

  def test_validate_params_for_invalid_event_types(self):
    """Test case to verify that the client should raise InvalidValueError when invalid event types are provided."""
    with self.assertRaises(main.InvalidValueError) as error:
      main.validate_params(["exchange"], ["dummy_event_type"])

    assert str(error.exception) == (
        "Validation error: Invalid value provided for event. Supported "
        "values are: ['securityrisk', 'virtualanalyzer', 'ransomware', 'dlp']")

  def test_validate_params_for_valid_services_events(self):
    """Test case to verify that client should not raise error when valid services and event types provided."""
    assert main.validate_params(["exchange"], ["securityrisk"]) is None

  @mock.patch("requests.get")
  def test_get_and_ingest_security_logs_for_error_code_from_response(
      self, mock_get):
    """Test case to verify function get_and_ingest_security_logs raise an exception with a message from the response for error codes."""
    mock_response = ('{"code": 401, "traceId": "trace1","msg": "A test string '
                     'describing the result code for 401."}')
    mock_get.return_value = get_mock_http_response(401, mock_response)

    with self.assertRaises(RuntimeError) as error:
      main.get_and_ingest_security_logs("dummy", "data_type", "service_url",
                                        ["service"], ["event_type"])

    assert str(
        error.exception
    ) == ("Failed to get security logs from Trend Micro with status code 401. "
          "Error message: A test string describing the result code for 401.")

  @mock.patch("requests.get")
  def test_get_and_ingest_security_logs_for_error_code_default_message(
      self, mock_get):
    """Test case to verify function get_and_ingest_security_logs raise an exception with default message for error codes."""
    # No "msg" key in sample response.
    mock_response = '{"code": 401, "traceId": "trace1"}'
    mock_get.return_value = get_mock_http_response(401, mock_response)

    with self.assertRaises(RuntimeError) as error:
      main.get_and_ingest_security_logs("dummy", "data_type", "service_url",
                                        ["service"], ["event_type"])

    assert str(
        error.exception
    ) == ("Failed to get security logs from Trend Micro with status code 401. "
          "Error message: {'code': 401, 'traceId': 'trace1'}")

  @mock.patch("requests.get")
  def test_get_and_ingest_security_logs_for_json_decode_error(self, mock_get):
    """Test case to verify function get_and_ingest_security_logs raise ValueError for invalid JSON response."""
    mock_response = '{key": """value"}'  # Invalid JSON response.
    mock_get.return_value = get_mock_http_response(200, mock_response)

    with self.assertRaises(ValueError) as error:
      main.get_and_ingest_security_logs("dummy", "data_type", "service_url",
                                        ["service"], ["event_type"])

    assert str(
        error.exception
    ) == ("Unexpected data format received while collecting security logs from "
          "Trend Micro.")

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  @mock.patch("requests.get")
  @mock.patch("builtins.print")
  def test_get_and_ingest_security_logs_success(self, mock_print,
                                                mock_get, mock_ingest):
    """Test case to verify function get_and_ingest_security_logs for success."""
    mock_response = '{"security_events":  []}'
    mock_get.return_value = get_mock_http_response(200, mock_response)

    assert main.get_and_ingest_security_logs("dummy", "data_type",
                                             "service_url", ["service"],
                                             ["event_type"]) is None
    assert mock_ingest.ingest.call_count == 1
    assert mock_print.call_count == 2

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  @mock.patch("requests.get")
  @mock.patch("time.sleep")
  def test_get_and_ingest_security_logs_success_with_429(self, mocked_sleep,
                                                         mock_get, mock_ingest):
    """Test case to verify function get_and_ingest_security_logs for success with 429 error code retries."""
    mock_valid_response = '{"security_events":  []}'
    mock_get.side_effect = [
        get_mock_http_response(429, "{}"),
        get_mock_http_response(429, "{}"),
        get_mock_http_response(200, mock_valid_response),
    ]

    assert (
        main.get_and_ingest_security_logs(
            "dummy", "data_type", "service_url", ["service"], ["event_type"]
        )
        is None
    )
    assert mock_ingest.ingest.call_count == 1
    assert mock_get.call_count == 3
    assert mocked_sleep.call_count == 2

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  @mock.patch("requests.get")
  @mock.patch("time.sleep")
  def test_get_and_ingest_security_logs_failure_with_429(self, mocked_sleep,
                                                         mock_get, mock_ingest):
    """Test case to verify function get_and_ingest_security_logs for failure with 429 error code with 5 retries."""
    mock_get.return_value = get_mock_http_response(429, "{}")

    with self.assertRaises(RuntimeError) as error:
      main.get_and_ingest_security_logs(
          "dummy", "data_type", "service_url", ["service"], ["event_type"]
      )

    assert mock_ingest.ingest.call_count == 0
    assert mock_get.call_count == 6
    assert mocked_sleep.call_count == 5
    assert (
        str(error.exception)
        == "Failed to get security logs from Trend Micro with status code 429."
        " Error message: {}"
    )

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  @mock.patch("requests.get")
  def test_get_and_ingest_security_logs_next_link(self, mock_get, mock_ingest):
    """Test case to verify ingestion of logs when next_link in response."""
    mock_response_page_1 = (
        '{"next_link": '
        '"https://api.test.trendmicro.com/v1/siem/security_events",'
        ' "security_events": ["dummy_data"]}')
    mock_response_page_2 = '{"security_events": ["dummy_data"]}'
    mock_get.side_effect = [
        get_mock_http_response(200, mock_response_page_1),
        get_mock_http_response(200, mock_response_page_2)
    ]

    assert main.get_and_ingest_security_logs("dummy", "data_type",
                                             "service_url", ["service"],
                                             ["event_type"]) is None
    assert mock_ingest.ingest.call_count == 2

  @mock.patch(f"{SCRIPT_PATH}main.utils.get_env_var")
  @mock.patch(f"{SCRIPT_PATH}main.validate_params")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_security_logs")
  def test_main_success(self, mock_get_and_ingest_security_logs,
                        mock_validate_params, mock_get_env_var):
    """Test case to verify ingestion is successful."""
    mock_get_env_var.side_effect = [
        "authentication_token", "service_url", "exchange", "securityrisk",
        "data_type"
    ]
    mock_request = mock.MagicMock()
    expected_get_evn_var_calls = [
        mock.call("TREND_MICRO_AUTHENTICATION_TOKEN", is_secret=True),
        mock.call("TREND_MICRO_SERVICE_URL"),
        mock.call(
            "TREND_MICRO_SERVICE",
            required=False,
            default=main.DEFAULT_TREND_MICRO_SERVICE),
        mock.call(
            "TREND_MICRO_EVENT",
            required=False,
            default=main.DEFAULT_TREND_MICRO_EVENT),
        mock.call("CHRONICLE_DATA_TYPE"),
    ]

    assert main.main(mock_request) == "Ingestion completed."
    assert mock_get_and_ingest_security_logs.call_count == 1
    assert mock_validate_params.call_count == 1
    assert mock_get_env_var.mock_calls == expected_get_evn_var_calls

  @mock.patch("requests.get")
  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  def test_ingest_failure(self, mock_ingest, mock_get):
    """Test case to verify ingestion failure."""
    mock_response = '{"security_events":  []}'
    mock_get.return_value = get_mock_http_response(200, mock_response)
    mock_ingest.ingest.side_effect = Exception("ingest error")

    with self.assertRaises(RuntimeError) as error:
      main.get_and_ingest_security_logs("dummy", "data_type", "service_url",
                                        ["service"], ["event_type"])

    assert str(
        error.exception
    ) == ("Unable to push Trend Micro security logs into Chronicle: "
                    "ingest error.")
