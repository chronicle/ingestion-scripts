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
"""Unit test file for OneLogin user."""

import datetime
import sys


# copybara:insert(imports) import unittest
from unittest import mock

from google.auth.transport import requests
import requests as req

# copybara:strip_begin(imports)
from google3.testing.pybase import googletest
# copybara:strip_end


INGESTION_SCRIPTS_PATH = 'google3.third_party.chronicle.ingestion_scripts'

# Mock the chronicle library
sys.modules['{}.common.ingest'.format(
    INGESTION_SCRIPTS_PATH)] = mock.MagicMock()

# copybara:strip_begin(imports)
from google3.third_party.chronicle.ingestion_scripts.onelogin_user import main  # pylint: disable=g-import-not-at-top
# copybara:strip_end


def mock_get_env_var(*args, **kwargs):  # pylint: disable=unused-argument
  """Mock and return env variable values."""
  if args[0] == 'POLL_INTERVAL':
    return 10
  else:
    return 'test'


# copybara:insert(imports) class TestGetUsersFromOneLogin(unittest.TestCase):
@mock.patch(
    '{}.onelogin_user.main.utils.get_env_var'.format(
        INGESTION_SCRIPTS_PATH), side_effect=mock_get_env_var)
@mock.patch('{}.onelogin_user.main.auth.OAuthClientCredentialsAuth'.format(
    INGESTION_SCRIPTS_PATH))
@mock.patch('{}.onelogin_user.main.ingest.ingest'.format(INGESTION_SCRIPTS_PATH)
           )
class TestGetUsersFromOneLogin(googletest.TestCase):
  """Unit test case class for OneLogin User."""

  def test_empty_response(self, mock_ingest, unused_mock_oauth,
                          unused_mock_env_var):
    """Test that the `get_users` function ingest empty list without any error in case of no data from API it self.
    """
    mocked_session = mock.Mock()
    mocked_get = mock.Mock()
    mocked_get.json.return_value = {
        'data': [],
        'pagination': {
            'next_link': None
        }
    }
    mocked_session.get.return_value = mocked_get
    main.get_and_ingest_users(mocked_session)

    self.assertEqual(mock_ingest.call_count, 0)

  def test_multiple_page_response(self, mock_ingest, unused_mock_oauth,
                                  unused_mock_env_var):
    """Test that the `get_users` function ingest list of events without any error in case of multiple pages from API.
    """
    mocked_session = mock.Mock()
    mocked_get = mock.Mock()
    mocked_get.json.side_effect = [{
        'data': [{
            'id': 1
        }],
        'pagination': {
            'next_link': 'next_link_1'
        }
    }, {
        'data': [{
            'id': 2
        }],
        'pagination': {
            'next_link': None
        }
    }]

    mocked_session.get.return_value = mocked_get
    main.get_and_ingest_users(mocked_session)

    actual_calls = mock_ingest.mock_calls
    expected_calls = [
        mock.call([{
            'id': 1
        }], 'ONELOGIN_USER_CONTEXT'),
        mock.call([{
            'id': 2
        }], 'ONELOGIN_USER_CONTEXT')
    ]
    self.assertEqual(actual_calls, expected_calls)
    self.assertEqual(mock_ingest.call_count, 2)

  @mock.patch('{}.onelogin_user.main.get_and_ingest_users'.format(
      INGESTION_SCRIPTS_PATH))
  def test_http_error(self, unused_mock_ingest, unused_mock_oauth,
                      unused_mock_env_var, mock_events):
    """Test that `main` function raises exception if API returns error."""
    mock_events.side_effect = requests.requests.exceptions.HTTPError()

    with self.assertRaises(requests.requests.exceptions.HTTPError):
      main.main(request='')

  @mock.patch('builtins.print')
  def test_value_error(self, mocked_print, unused_mock_ingest,
                       unused_mock_oauth, unused_mock_env_var):
    """Test case to verify that we raise ValueError when we get invalid JSON response.
    """
    mocked_session = mock.Mock()
    mocked_response = req.Response()
    mocked_response.status_code = 200
    mocked_response.data = None

    mocked_session.get.return_value = mocked_response
    with self.assertRaises(ValueError):
      main.get_and_ingest_users(mocked_session)

    mocked_print.assert_called_with(
        'ERROR: Unexpected data format received while collecting OneLogin'
        ' users.'
    )

  @mock.patch('builtins.print')
  def test_type_error(self, mocked_print, unused_mock_ingest, unused_mock_oauth,
                      unused_mock_env_var):
    """Test case to verify that we raise TypeError when we get JSON response in unexpected format.
    """
    mocked_session = mock.Mock()
    mocked_response = req.Response()
    mocked_response.status_code = 200
    mocked_response._content = 12  # pylint: disable=protected-access
    mocked_session.get.return_value = mocked_response

    with self.assertRaises(TypeError):
      main.get_and_ingest_users(mocked_session)

    mocked_print.assert_called_with(
        'ERROR: Unexpected data format received while collecting OneLogin'
        ' users.'
    )

  @mock.patch(f'{INGESTION_SCRIPTS_PATH}.onelogin_user.main.utils.datetime')
  @mock.patch(f'{INGESTION_SCRIPTS_PATH}.onelogin_user.main.datetime')
  def test_log_retrieve_time(self, mocked_utils_datetime
                             , mocked_script_datetime, unused_mock_ingest,
                             unused_mock_oauth, unused_mock_env_var):
    """Test case to verify that log retrieve time is passed as expected."""
    now_date = datetime.datetime(
        2022, 1, 1, 10, 15, 15, 234566, tzinfo=datetime.timezone.utc)
    mocked_script_datetime.datetime.now.return_value = now_date
    mocked_script_datetime.timedelta.side_effect = datetime.timedelta
    mocked_utils_datetime.datetime.now.return_value = now_date
    mocked_utils_datetime.timedelta.side_effect = datetime.timedelta

    mocked_session = mock.Mock()
    mocked_get = mock.Mock()
    mocked_get.json.return_value = {
        'data': [],
        'pagination': {
            'next_link': None
        }
    }
    mocked_session.get.return_value = mocked_get

    main.get_and_ingest_users(mocked_session)

    args, _ = mocked_session.get.call_args
    expected_start_date = '2022-01-01T10:05:15.234Z'  # (now - 10 minutes)
    expected_end_date = '2022-01-01T10:15:15.234Z'
    expected_url = f'https://api.us.onelogin.com/api/1/users?since={expected_start_date}&until={expected_end_date}'
    self.assertEqual(args[0], expected_url)
