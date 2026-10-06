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
"""Unit test file for ingest.py file."""

import base64
import json
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
        [os.path.realpath(os.path.dirname(__file__)), "..", "common"]
    )
)

with mock.patch(
    f"{INGESTION_SCRIPTS_PATH}.utils.get_env_var"
) as mocked_get_env_var:
  mocked_get_env_var.return_value = "{}"
  # Disabling the import error because ingest.py file fetches value of some
  # environment variables at the start of the file. Hence, this file will need
  # to be imported after mocking the function `get_env_var()`
  from common import ingest_v1  # pylint: disable=g-import-not-at-top

actual_calls = []


def calls_of_send_logs_to_chronicle(http_session, body):  # pylint: disable=unused-argument
  """Function which store entries of the body for all the calls to _send_logs_to_chronicle method."""
  actual_calls.append(body["inlineSource"]["logs"].copy())


class TestIngestMethod(unittest.TestCase):
  """Unit test class for ingest."""

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.json")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.initialize_http_session")
  def test_ingest(
      self,
      mocked_initialize_http_session,  # pylint: disable=unused-argument
      mocked_json,
      mocked_send_logs_to_chronicle,
  ):
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
    assert ingest_v1.ingest(["data"], "log_type") is None
    assert mocked_send_logs_to_chronicle.call_count == 1

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.sys")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.initialize_http_session")
  def test_ingest_with_3_95mb_data_chunks(
      self,
      mocked_initialize_http_session,
      mocked_sys,
      mocked_send_logs_to_chronicle,
  ):
    """Test case to verify the execution of ingest function when the size of data chunks is around 3.95MB.

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
    mocked_sys.getsizeof.side_effect = [10, 3_950_000, 3_950_000, 10, 10]
    mocked_send_logs_to_chronicle.side_effect = calls_of_send_logs_to_chronicle
    expected_calls = []

    assert ingest_v1.ingest(["data"], "log_type") is None
    assert mocked_initialize_http_session.call_count == 1
    assert mocked_send_logs_to_chronicle.call_count == 0
    assert actual_calls == expected_calls

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.sys")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.initialize_http_session")
  def test__ingest_when_data_less_than_1_mb(
      self, mock_initialize_http_session, mock_sys, mock__send_logs_to_chronicle
  ):
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
    expected_calls = [
        [{
            "data": (
                base64.b64encode(json.dumps("data").encode("utf-8")).decode(
                    "utf-8"
                )
            )
        }]
        * 150
    ]

    assert ingest_v1.ingest(["data"] * 150, "log_type") is None
    assert mock_initialize_http_session.call_count == 1
    assert actual_calls == expected_calls

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.sys")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.initialize_http_session")
  def test_ingest_with_mixed_size_data_chunks(
      self, mock_initialize_http_session, mock_sys, mock__send_logs_to_chronicle
  ):
    """Test case to verify the execution of ingest function with mixed size data chunks.

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
    mock_sys.getsizeof.side_effect = [
        900,
        90_000_000,
        10,
        9_000_000,
        10,
        10,
        10,
    ]
    mock__send_logs_to_chronicle.side_effect = calls_of_send_logs_to_chronicle
    expected_calls = [
        [{
            "data": (
                base64.b64encode(json.dumps("data1").encode("utf-8")).decode(
                    "utf-8"
                )
            )
        }],
        [
            {
                "data": (
                    base64.b64encode(
                        json.dumps("data2").encode("utf-8")
                    ).decode("utf-8")
                )
            },
            {
                "data": (
                    base64.b64encode(
                        json.dumps("data3").encode("utf-8")
                    ).decode("utf-8")
                )
            },
        ],
    ]

    assert ingest_v1.ingest(["data1", "data2", "data3"], "log_type") is None
    assert mock_initialize_http_session.call_count == 1
    assert mock__send_logs_to_chronicle.call_count == 2

    assert actual_calls == expected_calls

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1._send_logs_to_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.sys")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.initialize_http_session")
  def test_ingest_when_first_100_logs_data_around_3_95mb(
      self,
      mocked_initialize_http_session,
      mocked_sys,
      mocked_send_logs_to_chronicle,
  ):
    """Test case to verify the execution of ingest function when the size of first 100 logs data is around 3.95MB.

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
    mocked_sys.getsizeof.side_effect = [3_950_000, 3_950_000, 3_950_000, 10, 10]
    mocked_send_logs_to_chronicle.side_effect = calls_of_send_logs_to_chronicle

    assert ingest_v1.ingest([{"id": 1}] * 100, "log_type") is None
    assert mocked_initialize_http_session.call_count == 1
    assert mocked_send_logs_to_chronicle.call_count == 1
    assert len(actual_calls[0]) == ingest_v1.LOG_BATCH_SIZE - 1

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
    mocked_response.json.return_value = None
    mocked_http_session.request.return_value = mocked_response
    mock_body = {
        "parent": "parent",
        "inlineSource": {"logs": [{"data": '{"id": "test_id"}'}]},
    }
    assert (
        ingest_v1._send_logs_to_chronicle(mocked_http_session, mock_body)
        is None
    )
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
    mock_body = {
        "parent": "parent",
        "inlineSource": {"logs": [{"data": '{"id": "test_id"}'}]},
    }
    with self.assertRaises(RuntimeError):
      assert (
          ingest_v1._send_logs_to_chronicle(mocked_http_session, mock_body)
          is None
      )
    assert mocked_http_session.request.call_count == 1
    assert mocked_response.json.call_count == 1
    assert mocked_response.raise_for_status.call_count == 1

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.Requests.AuthorizedSession")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}.ingest_v1.service_account.Credentials.from_service_account_info"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.utils.load_service_account")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.utils.get_env_var")
  def test_initialize_http_session_with_service_account(
      self,
      mock_get_env_var,
      mock_load_service_account,
      mock_cloud_logging,
      mock_from_service_account_info,
      mock_authorized_session,
  ):
    """Test case to verify initialize_http_session with service account.

    Args:
      mock_get_env_var (mock.Mock): Mocked object of get_env_var() method.
      mock_load_service_account (mock.Mock): Mocked object of
        load_service_account() method.
      mock_cloud_logging (mock.Mock): Mocked object of cloud_logging() method.
      mock_from_service_account_info (mock.Mock): Mocked object of
        from_service_account_info() method.
      mock_authorized_session (mock.Mock): Mocked object of AuthorizedSession
        class.

    Asserts:
      Validates that initialize_http_session() returns an AuthorizedSession.
      Validates that service account is loaded from environment variable.
      Validates that credentials are created from service account info.
    """
    mock_service_account_dict = {
        "type": "service_account",
        "project_id": "test-project",
    }
    mock_get_env_var.return_value = json.dumps(mock_service_account_dict)
    mock_load_service_account.return_value = mock_service_account_dict
    mock_credentials = mock.MagicMock()
    mock_from_service_account_info.return_value = mock_credentials
    mock_session = mock.MagicMock()
    mock_authorized_session.return_value = mock_session

    result = ingest_v1.initialize_http_session()

    assert result == mock_session
    mock_get_env_var.assert_called_once()
    mock_load_service_account.assert_called_once()
    mock_from_service_account_info.assert_called_once_with(
        mock_service_account_dict, scopes=ingest_v1.AUTHORIZATION_SCOPES
    )
    mock_authorized_session.assert_called_once_with(mock_credentials)
    # Verify logging message for service account
    assert any(
        "Service account found" in str(call)
        for call in mock_cloud_logging.call_args_list
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.Requests.AuthorizedSession")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.google.auth.default")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.utils.load_service_account")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.utils.get_env_var")
  def test_initialize_http_session_with_adc(
      self,
      mock_get_env_var,
      mock_load_service_account,
      mock_cloud_logging,
      mock_google_auth_default,
      mock_authorized_session,
  ):
    """Test case to verify initialize_http_session with ADC (Application Default Credentials).

    Args:
      mock_get_env_var (mock.Mock): Mocked object of get_env_var() method.
      mock_load_service_account (mock.Mock): Mocked object of
        load_service_account() method.
      mock_cloud_logging (mock.Mock): Mocked object of cloud_logging() method.
      mock_google_auth_default (mock.Mock): Mocked object of
        google_auth_default() method.
      mock_authorized_session (mock.Mock): Mocked object of AuthorizedSession
        class.

    Asserts:
      Validates that initialize_http_session() falls back to ADC when service
        account is not found.
      Validates that default credentials are used.
      Validates that appropriate logging message is generated.
    """
    mock_get_env_var.return_value = json.dumps({})
    mock_load_service_account.side_effect = RuntimeError(
        "Service account not found"
    )
    mock_credentials = mock.MagicMock()
    mock_project = "test-project"
    mock_google_auth_default.return_value = (mock_credentials, mock_project)
    mock_session = mock.MagicMock()
    mock_authorized_session.return_value = mock_session

    result = ingest_v1.initialize_http_session()

    assert result == mock_session
    mock_google_auth_default.assert_called_once_with(
        scopes=ingest_v1.AUTHORIZATION_SCOPES
    )
    mock_authorized_session.assert_called_once_with(mock_credentials)
    # Verify logging message for ADC
    assert any(
        "default service account" in str(call)
        for call in mock_cloud_logging.call_args_list
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.Requests.AuthorizedSession")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}.ingest_v1.service_account.Credentials.from_service_account_info"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.utils.load_service_account")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.ingest_v1.utils.get_env_var")
  def test_initialize_http_session_with_custom_scopes(
      self,
      mock_get_env_var,
      mock_load_service_account,
      mock_from_service_account_info,
      mock_authorized_session,
  ):
    """Test case to verify initialize_http_session with custom scopes.

    Args:
      mock_get_env_var (mock.Mock): Mocked object of get_env_var() method.
      mock_load_service_account (mock.Mock): Mocked object of
        load_service_account() method.
      mock_from_service_account_info (mock.Mock): Mocked object of
        from_service_account_info() method.
      mock_authorized_session (mock.Mock): Mocked object of AuthorizedSession
        class.

    Asserts:
      Validates that custom scopes are passed correctly to credentials.
    """
    custom_scopes = ["https://www.googleapis.com/auth/custom-scope"]
    mock_service_account_dict = {
        "type": "service_account",
        "project_id": "test-project",
    }
    mock_get_env_var.return_value = json.dumps(mock_service_account_dict)
    mock_load_service_account.return_value = mock_service_account_dict
    mock_credentials = mock.MagicMock()
    mock_from_service_account_info.return_value = mock_credentials
    mock_session = mock.MagicMock()
    mock_authorized_session.return_value = mock_session

    result = ingest_v1.initialize_http_session(scopes=custom_scopes)

    assert result == mock_session
    mock_from_service_account_info.assert_called_once_with(
        mock_service_account_dict, scopes=custom_scopes
    )
    mock_authorized_session.assert_called_once_with(mock_credentials)
