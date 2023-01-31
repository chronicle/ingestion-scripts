# Copyright 2022 Google LLC
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
"""Unit Test case file for Trend Micro Vision One ingestion script."""
import sys
import unittest
from unittest import mock

import requests

INGESTION_COMPLETE = "Ingestion completed."

INGESTION_SCRIPTS_PATH = ""
SCRIPT_PATH = ""

sys.modules[f"{INGESTION_SCRIPTS_PATH}common.ingest"] = mock.MagicMock()
sys.modules[f"{INGESTION_SCRIPTS_PATH}common.utils"] = mock.MagicMock()

import main


def get_mock_http_response(status_code: int, content=""):
  """Function that will return dummy response object based on provided status code and content."""
  response = requests.Response()
  response.status_code = status_code
  response._content = content.encode()
  return response


class TestTrendMicroVisionOneIngestion(unittest.TestCase):
  """Test cases for Trend Micro Vision One ingestion script."""

  @mock.patch("requests.get")
  def test_get_and_ingest_security_logs_for_error_code_default_message(
      self, mock_get):
    """Test case to verify function get_and_ingest_audit_logs raise an exception with default message for error codes."""
    mock_response = '{"code": 401}'  # No "msg" key in sample response.
    mock_get.return_value = get_mock_http_response(401, mock_response)

    with self.assertRaises(RuntimeError) as error:
      main.get_and_ingest_audit_logs("authentication_token", "domain")

    assert str(
        error.exception
    ) == ("Failed to get audit logs from Trend Micro Vision One with status "
          "code 401. Error message: {'code': 401}.")

  @mock.patch("requests.get")
  def test_get_and_ingest_audit_logs_for_json_decode_error(self, mock_get):
    """Test case to verify function get_and_ingest_audit_logs raise ValueError for invalid JSON response."""
    mock_response = '{key": """value"}'  # Invalid JSON response.
    mock_get.return_value = get_mock_http_response(200, mock_response)

    with self.assertRaises(ValueError) as error:
      main.get_and_ingest_audit_logs("authentication_token", "domain")

    assert str(
        error.exception
    ) == ("Unexpected data format received while collecting audit logs from "
          "Trend Micro Vision One.")

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  @mock.patch("requests.get")
  def test_get_and_ingest_audit_logs_success(self, mock_get, mock_ingest):
    """Test case to verify function get_and_ingest_audit_logs for success."""
    mock_response = '{"items":  ["data"]}'
    mock_get.return_value = get_mock_http_response(200, mock_response)

    assert main.get_and_ingest_audit_logs("authentication_token",
                                          "domain") is None
    assert mock_ingest.ingest.call_count == 1

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  @mock.patch("requests.get")
  def test_get_and_ingest_audit_logs_success_no_audit_logs(
      self, mock_get, mock_ingest):
    """Test case to verify function get_and_ingest_audit_logs for success when no audit logs in given time range."""
    mock_response = '{"items":  []}'
    mock_get.return_value = get_mock_http_response(200, mock_response)

    assert main.get_and_ingest_audit_logs("authentication_token",
                                          "domain") is None
    assert mock_ingest.ingest.call_count == 0

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  @mock.patch("requests.get")
  def test_get_and_ingest_audit_logs_next_link(self, mock_get, mock_ingest):
    """Test case to verify ingestion of logs when nextLink in response."""
    mock_response_page_1 = (
        '{"nextLink": '
        '"https://api.test.trendmicro.com/v1/siem/security_events", "items": '
        '["dummy_data"]}'
    )
    mock_response_page_2 = '{"items": ["dummy_data"]}'
    mock_get.side_effect = [
        get_mock_http_response(200, mock_response_page_1),
        get_mock_http_response(200, mock_response_page_2)
    ]

    assert main.get_and_ingest_audit_logs("authentication_token",
                                          "domain") is None
    assert mock_ingest.ingest.call_count == 2

  @mock.patch(f"{SCRIPT_PATH}main.utils.get_env_var")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_audit_logs")
  def test_main_success(self, unused_mock_get_and_ingest_audit_logs,
                        mock_get_env_var):
    """Test case to verify ingestion is successful."""
    mock_get_env_var.side_effect = ["authentication_token", "domain"]
    mock_request = mock.MagicMock()
    expected_get_evn_var_calls = [
        mock.call("TREND_MICRO_AUTHENTICATION_TOKEN", is_secret=True),
        mock.call("TREND_MICRO_DOMAIN")
    ]

    assert main.main(mock_request) == "Ingestion completed."
    assert main.get_and_ingest_audit_logs.call_count == 1
    assert mock_get_env_var.mock_calls == expected_get_evn_var_calls

  @mock.patch("requests.get")
  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  def test_ingest_failure(self, mock_ingest, mock_get):
    """Test case to verify ingestion failure."""
    mock_response = '{"items":  ["data"]}'
    mock_get.return_value = get_mock_http_response(200, mock_response)
    mock_ingest.ingest.side_effect = Exception("ingest error")

    with self.assertRaises(RuntimeError) as error:
      main.get_and_ingest_audit_logs("authentication_token", "domain")

    assert str(
        error.exception
    ) == ("Unable to push Trend Micro Vision One audit logs into Chronicle: "
          "ingest error.")
