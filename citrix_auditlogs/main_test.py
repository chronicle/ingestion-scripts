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
"""Unit test case file for citrix audit logs."""

import datetime
import json
import sys

# copybara:insert(imports) import unittest
from unittest import mock

import requests

# copybara:strip_begin(imports)
from google3.testing.pybase import googletest
# copybara:strip_end

INGESTION_SCRIPTS_PATH = "google3.third_party.chronicle.ingestion_scripts"

sys.modules["{}.common.ingest".format(INGESTION_SCRIPTS_PATH)] = mock.Mock()

# copybara:strip_begin(imports)
from citrix_auditlogs import main  # pylint: disable=g-import-not-at-top
# copybara:strip_end


def mock_get_env_var(*args, **kwargs):  # pylint: disable=unused-argument
  """Mock and return env variable values."""
  if args[0] == "POLL_INTERVAL":
    return 10
  else:
    return "test"


def get_mock_session():
  """Return a mock OAuth object."""
  mock_session = mock.Mock()
  mock_session.headers = {"Authorization": "Bearer test_access_token"}
  return mock_session


def get_mock_creds():
  """Return a mock OAuth object."""
  mock_oauth = mock.Mock()
  mock_session = mock.Mock()
  mock_session.headers = {"Authorization": "Bearer test_access_token"}
  mock_oauth.session = mock_session
  return mock_oauth


def get_mock_response():
  """Return a mock response."""
  response = mock.Mock()
  response.raise_for_status = mock.Mock()
  response.status_code = 200
  return response


# Mock .
_test_entities = [{
    "items": [{
        "id": "1"
    }, {
        "id": "2"
    }],
    "continuationToken": "9b00a6f0f04ed44e374738d9c8de460a"
}, {
    "items": [{
        "id": "3"
    }, {
        "id": "4"
    }],
    "continuationToken": None
}]


# copybara:insert(imports) class TestAccessToken(unittest.TestCase):
class TestAccessToken(googletest.TestCase):
  """Test cases to verfy "get_access_token" functionality."""

  @mock.patch("builtins.print")
  def test_get_access_token_index_error(self, mocked_print):
    """Test case to verify we raise key error when token is not found."""
    mocked_session = mock.Mock()
    mocked_session.headers = {"Authorization": "Bearer"}

    with self.assertRaises(IndexError):
      main.get_access_token(mocked_session)

    mocked_print.assert_called_with(
        "Unable to fetch access token from the session.")

  @mock.patch("builtins.print")
  def test_get_access_token_keyerror(self, mocked_print):
    """Test case to verify we raise key error when 'Authorization' is not found.
    """
    mocked_session = mock.Mock()
    mocked_session.headers = {}

    with self.assertRaises(KeyError):
      main.get_access_token(mocked_session)

    mocked_print.assert_called_with(
        "Unable to fetch access token from the session.")

  def test_get_access_token_valid_response(self):
    """Test case to verify we get access token from the session headers."""
    actual_access_token = main.get_access_token(get_mock_session())
    expected_access_token = "test_access_token"
    self.assertEqual(actual_access_token, expected_access_token)


# copybara:insert(imports) class TestCitrixAuditLogs(unittest.TestCase):
@mock.patch(
    "{}.citrix_auditlogs.main.utils.get_env_var".format(INGESTION_SCRIPTS_PATH),
    side_effect=mock_get_env_var)
@mock.patch(
    "{}.citrix_auditlogs.main.ingest.ingest".format(INGESTION_SCRIPTS_PATH))
@mock.patch(
    "{}.citrix_auditlogs.main.create_new_session".format(INGESTION_SCRIPTS_PATH)
)
@mock.patch(
    "{}.citrix_auditlogs.main.requests.get".format(INGESTION_SCRIPTS_PATH))
class TestCitrixAuditLogs(googletest.TestCase):
  """Test cases to verify Citrix Audit Logs script."""

  @mock.patch("builtins.print")
  def test_http_error(self, mocked_print, mocked_get, mocked_create_session,
                      unused_mocked_ingest, unused_mocked_get_env_var):
    """Test case to verify we raise error when we encounter status code other than 2XX.
    """
    mocked_create_session.return_value = get_mock_session()
    mocked_response = requests.Response()
    mocked_response.status_code = 403
    mocked_response._content = json.dumps({  # pylint: disable=protected-access
        "type": "Forbidden error"
    }).encode()
    mocked_get.return_value = mocked_response

    with self.assertRaises(requests.HTTPError):
      main.main(req="")

    mocked_print.assert_called_with(
        "HTTP Error: 403, Reason: {'type': 'Forbidden error'}.")

  def test_http_401_error_reauthorize(self, mocked_get, mocked_create_session,
                                      mocked_ingest, unused_mocked_get_env_var):
    """Test case to verify that we create new session if status code is 401."""
    mocked_create_session.return_value = get_mock_session()

    response_1 = get_mock_response()
    response_1.raise_for_status.side_effect = requests.HTTPError()
    response_1.status_code = 401

    response_2 = get_mock_response()
    response_2.json.return_value = {"items": ["abc"], "continuationToken": None}
    mocked_get.side_effect = [response_1, response_2]

    main.main(req="")

    self.assertEqual(mocked_create_session.call_count, 2)
    self.assertEqual(mocked_get.call_count, 2)
    self.assertEqual(mocked_ingest.call_count, 1)
    mocked_ingest.assert_called_with(["abc"], "CITRIX_MONITOR")

  @mock.patch("builtins.print")
  def test_http_401_error_exit(self, mocked_print, mocked_get,
                               mocked_create_session, unused_mocked_ingest,
                               unused_mocked_get_env_var):
    """Test case to verify that we raise error when we get 401 error for continuous 4 API Calls.
    """
    mocked_create_session.return_value = get_mock_session()
    mocked_response = requests.Response()
    mocked_response.status_code = 401
    mocked_response._content = json.dumps({  # pylint: disable=protected-access
        "type": "Unauthorized error"
    }).encode()

    mocked_get.side_effect = [
        mocked_response, mocked_response, mocked_response, mocked_response
    ]

    with self.assertRaises(requests.HTTPError):
      main.main(req="")

    self.assertEqual(mocked_get.call_count, 4)
    mocked_print.assert_called_with(
        "Unable to fetch the access token for data collection. Exiting...")

  @mock.patch("builtins.print")
  def test_value_error(self, mocked_print, mocked_get, mocked_create_session,
                       unused_mocked_ingest, unused_mocked_get_env_var):
    """Test case to verify we raise ValueError when we get invalid JSON response.
    """
    mocked_create_session.return_value = get_mock_session()
    mocked_response = requests.Response()
    mocked_response.status_code = 200
    mocked_response.data = None

    mocked_get.return_value = mocked_response

    with self.assertRaises(ValueError):
      main.main(req="")

    mocked_print.assert_called_with(
        "ERROR: Unexpected data format received while collecting audit logs.")

  @mock.patch("builtins.print")
  def test_type_error(self, mocked_print, mocked_get, mocked_create_session,
                      unused_mocked_ingest, unused_mocked_get_env_var):
    """Test case to verify we raise TypeError when we get JSON response in unexpected format.
    """

    mocked_create_session.return_value = get_mock_session()
    mocked_response = requests.Response()
    mocked_response.status_code = 200
    mocked_response._content = 12  # pylint: disable=protected-access

    mocked_get.return_value = mocked_response

    with self.assertRaises(TypeError):
      main.main(req="")

    mocked_print.assert_called_with(
        "ERROR: Unexpected data format received while collecting audit logs.")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.citrix_auditlogs.main.utils.datetime")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.citrix_auditlogs.main.datetime")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}.citrix_auditlogs.main.get_access_token")
  def test_log_retrieve_time(self, unused_mock_token, mocked_utils_datetime,
                             mocked_script_datetime, mocked_get,
                             mocked_create_session,
                             unused_mocked_ingest, unused_mocked_get_env_var):
    """Test case to verify log retrieve time is passed as expected."""
    now_date = datetime.datetime(
        2022, 1, 1, 10, 15, 15, 234566, tzinfo=datetime.timezone.utc)
    mocked_script_datetime.datetime.now.return_value = now_date
    mocked_script_datetime.timedelta.side_effect = datetime.timedelta
    mocked_utils_datetime.datetime.now.return_value = now_date
    mocked_utils_datetime.timedelta.side_effect = datetime.timedelta

    mocked_create_session.return_value = get_mock_creds()
    response = get_mock_response()
    response.json.return_value = {"items": [], "continuationToken": None}
    mocked_get.return_value = response

    main.main(req="")

    _, kwargs = mocked_get.call_args
    expected_log_retrieve_params = {
        # (now - 10 minutes)
        "startDateTime": "2022-01-01T10:05:15.234Z",
        "endDateTime": "2022-01-01T10:15:15.234Z",
        "limit": 200,
    }
    self.assertEqual(kwargs.get("params"), expected_log_retrieve_params)

  @mock.patch(
      "{}.citrix_auditlogs.main.get_access_token".format(INGESTION_SCRIPTS_PATH)
  )
  def test_no_logs_to_ingest(self, unused_mock_token, mocked_get,
                             mocked_create_session, mocked_ingest,
                             unused_mocked_get_env_var):
    """Test case to verify we call ingest only single time when there are no logs to ingest.
    """
    mocked_create_session.return_value = get_mock_creds()
    response = get_mock_response()
    response.json.return_value = {"items": [], "continuationToken": None}
    mocked_get.return_value = response

    main.main(req="")

    self.assertEqual(mocked_ingest.call_count, 0)

  @mock.patch(
      "{}.citrix_auditlogs.main.get_access_token".format(INGESTION_SCRIPTS_PATH)
  )
  def test_pagination(self, unused_mock_token, mocked_get, mocked_creds,
                      mocked_ingest, unused_mocked_get_env_var):
    """Test case to verify we fetch next page logs when the API response contains a "continuationToken".
    """
    mocked_creds.return_value = get_mock_creds()
    response = get_mock_response()
    response.json.side_effect = _test_entities
    mocked_get.return_value = response

    main.main(req="")

    actual_calls = mocked_ingest.mock_calls
    expected_calls = [
        mock.call(
            # Call ingest with 1st page logs
            [{
                "id": "1"
            }, {
                "id": "2"
            }],
            "CITRIX_MONITOR"),
        mock.call(
            # Call ingest with 2nd page logs
            [{
                "id": "3"
            }, {
                "id": "4"
            }],
            "CITRIX_MONITOR")
    ]
    self.assertEqual(mocked_ingest.call_count, 2)
    self.assertEqual(actual_calls, expected_calls)
