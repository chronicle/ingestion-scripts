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
"""Unit test file for ingest.py file."""

import os
import sys

import unittest
from unittest import mock

# Path to common framework.
INGESTION_SCRIPTS_PATH = (
    "common"
)

sys.path.append(
    os.path.sep.join(
        [os.path.realpath(os.path.dirname(__file__)), "..", "common"]))

with mock.patch(
    f"{INGESTION_SCRIPTS_PATH}.utils.get_env_var") as mocked_get_env_var:
  mocked_get_env_var.return_value = "{}"
  # Disabling the import error because ingest.py file fetches value of some
  # environment variables at the start of the file. Hence, this file will need
  # to be imported after mocking the function `get_env_var()`
  from common import ingest  # pylint: disable=g-import-not-at-top

actual_calls = []


def calls_of_send_logs_to_chronicle(http_session, body, region):    # pylint: disable=unused-argument
  """Function which store entries of the body for all the calls to _send_logs_to_chronicle method."""
  actual_calls.append(body["entries"].copy())


class TestIngestMethod(unittest.TestCase):
  """Unit test class for ingest."""

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.json")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.initialize_http_session")
  def test_ingest(
      self,
      mocked_initialize_http_session,   # pylint: disable=unused-argument
      mocked_json,
      mocked_send_logs_to_chronicle):
    """Test case to verify the successful scenario of ingest function.

    Args:
      mocked_initialize_http_session (mock.Mock): Mocked object of
        initialize_http_session() method.
      mocked_json (mock.Mock): Mocked object of json module.
      mocked_send_logs_to_chronicle (mock.Mock): Mocked object of
        send_logs_to_chronicle() method.
    Asserts: Validates that ingest() method is called once and no error occurred
      while calling send_logs_to_chronicle() method. Validates that
      send_logs_to_chronicle() method is called once.
    """
    mocked_json.dumps.return_value = "{}"
    assert ingest.ingest(["data"], "log_type") is None
    assert mocked_send_logs_to_chronicle.call_count == 1

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.sys")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.initialize_http_session")
  def test_ingest_when_data_greater_than_1_mb(self,
                                              mocked_initialize_http_session,
                                              mocked_sys,
                                              mocked_send_logs_to_chronicle):
    """Test case to verify the execution of ingest function when the size of data is greater than 1MB.

    Args:
      mocked_initialize_http_session (mock.Mock): Mocked object of
        initialize_http_session() method.
      mocked_sys (mock.Mock): Mocked object of sys module.
      mocked_send_logs_to_chronicle (mock.Mock): Mocked object of
        send_logs_to_chronicle() method.
    Asserts: Validates that ingest() method is called once and no error occurred
      while calling send_logs_to_chronicle() method. Validates that
      send_logs_to_chronicle() method is called once.
    """
    global actual_calls
    actual_calls = []
    mocked_sys.getsizeof.side_effect = [10, 950000, 950000, 10, 10]
    mocked_send_logs_to_chronicle.side_effect = calls_of_send_logs_to_chronicle
    expected_calls = [[], [{"logText": '"data"'}]]

    assert ingest.ingest(["data"], "log_type") is None
    assert mocked_initialize_http_session.call_count == 1
    assert mocked_send_logs_to_chronicle.call_count == 2
    assert actual_calls == expected_calls

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.sys")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.initialize_http_session")
  def test__ingest_when_data_less_than_1_mb(self, mock_initialize_http_session,
                                            mock_sys,
                                            mock__send_logs_to_chronicle):
    """Test case to verify the execution of ingest function when the size of first 100 logs data is less than 1MB.

    Args:
      mock_initialize_http_session (mock.Mock): Mocked object of
        initialize_http_session() method.
      mock_sys (mock.Mock): Mocked object of sys module.
      mock__send_logs_to_chronicle (mock.Mock): Mocked object of
        send_logs_to_chronicle() method.
    Asserts: Validates that ingest() method is called once and no error occurred
      while calling send_logs_to_chronicle() method. Validates that
      send_logs_to_chronicle() method is called once. Validate body passed to
      send_logs_to_chronicle().
    """
    global actual_calls
    actual_calls = []
    mock_sys.getsizeof.side_effect = [900, 900, 10, 10]
    mock__send_logs_to_chronicle.side_effect = calls_of_send_logs_to_chronicle
    expected_calls = [[{"logText": '"data"'}] * 150]

    assert ingest.ingest(["data"] * 150, "log_type") is None
    assert mock_initialize_http_session.call_count == 1
    assert mock__send_logs_to_chronicle.call_count == 1
    assert actual_calls == expected_calls

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.sys")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.initialize_http_session")
  def test__ingest_when_data_greater_than_1_mb_in_chunk(
      self, mock_initialize_http_session, mock_sys,
      mock__send_logs_to_chronicle):
    """Test case to verify the execution of ingest function when the size of first 100 logs data is less than 1MB.

    Args:
      mock_initialize_http_session (mock.Mock): Mocked object of
        initialize_http_session() method.
      mock_sys (mock.Mock): Mocked object of sys module.
      mock__send_logs_to_chronicle (mock.Mock): Mocked object of
        send_logs_to_chronicle() method.
    Asserts: Validates that ingest() method is called once and no error occurred
      while calling send_logs_to_chronicle() method. Validates that
      send_logs_to_chronicle() method is called once. Validate body passed to
      send_logs_to_chronicle().
    """
    global actual_calls
    actual_calls = []
    mock_sys.getsizeof.side_effect = [900, 90000000, 10, 9000000, 10, 10, 10]
    mock__send_logs_to_chronicle.side_effect = calls_of_send_logs_to_chronicle
    expected_calls = [[{
        "logText": '"data1"'
    }], [{
        "logText": '"data2"'
    }, {
        "logText": '"data3"'
    }]]

    assert ingest.ingest(["data1", "data2", "data3"], "log_type") is None
    assert mock_initialize_http_session.call_count == 1
    assert mock__send_logs_to_chronicle.call_count == 2
    assert actual_calls == expected_calls

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.sys")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.initialize_http_session")
  def test_ingest_when_first_100_logs_data_greater_than_1_mb(
      self, mocked_initialize_http_session, mocked_sys,
      mocked_send_logs_to_chronicle):
    """Test case to verify the execution of ingest function when the size of first 100 logs data is greater than 1MB.

    Args:
      mocked_initialize_http_session (mock.Mock): Mocked object of
        initialize_http_session() method.
      mocked_sys (mock.Mock): Mocked object of sys module.
      mocked_send_logs_to_chronicle (mock.Mock): Mocked object of
        send_logs_to_chronicle() method.
    Asserts: Validates that ingest() method is called once and no error occurred
      while calling send_logs_to_chronicle() method. Validates that
      send_logs_to_chronicle() method is called once.
    """
    global actual_calls
    actual_calls = []
    mocked_sys.getsizeof.side_effect = [950000, 950000, 950000, 10, 10]
    mocked_send_logs_to_chronicle.side_effect = calls_of_send_logs_to_chronicle

    assert ingest.ingest([{"id": 1}] * 100, "log_type") is None
    assert mocked_initialize_http_session.call_count == 1
    assert mocked_send_logs_to_chronicle.call_count == 2
    assert len(actual_calls[1]) == ingest.LOG_BATCH_SIZE

  def test_send_logs_to_chronicle_for_success(self):
    """Test case to verify the successful ingestion of logs to the Chronicle.

    Asserts:
      Validates the execution of send_logs_to_chronicle() method.
      Validates the session sends the request to chronicle.
      Validates the json() object is fetched from the response.
      Validates the raise_for_status() object is executed for the request.
    """
    mocked_http_session = mock.MagicMock()
    mocked_response = mock.MagicMock()
    mocked_http_session.request.return_value = mocked_response
    mock_body = {"entries": [{"logText": '{"id": "test_id"}'}]}
    assert ingest._send_logs_to_chronicle(mocked_http_session, mock_body,
                                          "region") is None
    assert mocked_http_session.request.call_count == 1
    assert mocked_response.json.call_count == 1
    assert mocked_response.raise_for_status.call_count == 1

  def test_send_logs_to_chronicle_for_failure(self):
    """Test case to verify the failure of ingestion of logs to the Chronicle.

    Asserts:
      Validates the execution of send_logs_to_chronicle() method.
      Validates the session sends the request to chronicle.
      Validates the json() object is fetched from the response.
      Validates the raise_for_status() object is executed for the request.
    """
    mocked_http_session = mock.MagicMock()
    mocked_response = mock.MagicMock()
    mocked_response.raise_for_status.side_effect = Exception()
    mocked_http_session.request.return_value = mocked_response
    mock_body = {"entries": [{"logText": '{"id": "test_id"}'}]}
    with self.assertRaises(RuntimeError):
      assert ingest._send_logs_to_chronicle(mocked_http_session, mock_body,
                                            "region") is None
    assert mocked_http_session.request.call_count == 1
    assert mocked_response.json.call_count == 1
    assert mocked_response.raise_for_status.call_count == 1

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.initialize_http_session")
  def test_get_reference_list_success(self, mocked_initialize_http_session):
    mock_session = mock.MagicMock()
    mock_session.request.return_value = mock.Mock(
        status_code=200, json=lambda: {"lines": ["item1", "item2", "item3"]}
    )
    mocked_initialize_http_session.return_value = mock_session
    response = ingest.get_reference_list("test")
    assert response == ["item1", "item2", "item3"]

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.initialize_http_session")
  def test_get_reference_list_success_us_location(
      self, mocked_initialize_http_session
  ):
    original_value = ingest.REGION
    ingest.REGION = "us"
    mock_session = mock.MagicMock()
    mock_session.request.return_value = mock.Mock(
        status_code=200, json=lambda: {"lines": ["item1", "item2", "item3"]}
    )
    mocked_initialize_http_session.return_value = mock_session
    response = ingest.get_reference_list("test")
    assert (
        mock_session.request.call_args_list[0][0][1]
        == "https://backstory.googleapis.com/v2/lists/test"
    )
    assert response == ["item1", "item2", "item3"]
    ingest.REGION = original_value

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest.initialize_http_session")
  def test_get_reference_list_http_error(self, mock_initialize_http_session):
    # Mocking an HTTP error response
    mock_session = mock.MagicMock()
    mock_session.request.return_value = mock.Mock(status_code=404)
    mock_initialize_http_session.return_value = mock_session

    with self.assertRaises(Exception):
      ingest.get_reference_list("test")
