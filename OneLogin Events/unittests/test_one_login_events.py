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
import unittest
import requests as req
import sys
from unittest import mock
import datetime
from google.auth.transport import requests

# Mock the chronicle library
sys.modules['chronicle.ingest'] = mock.MagicMock()

from OneLogin_Events.main import get_events, main

@mock.patch("OneLogin_Events.main.get_env_var")
@mock.patch("OneLogin_Events.main.OAuthClientCredentialsAuth")
@mock.patch('OneLogin_Events.main.ingest')
class GetEventsFromOneLogin(unittest.TestCase):

    @mock.patch("builtins.print")
    def test_value_error(self, mocked_print, mock_ingest, mock_oauth, mock_env_var):
        """
        Test case to verify that we raise ValueError when we get invalid JSON response.
        """
        mocked_session = mock.Mock()
        mocked_response = req.Response()
        mocked_response.status_code = 200
        mocked_response.data = None

        mocked_session.get.return_value = mocked_response
        with self.assertRaises(ValueError):
            get_events(mocked_session)

        mocked_print.assert_called_with("ERROR: Unexpected data format received while collecting OneLogin events")

    @mock.patch("builtins.print")
    def test_type_error(self, mocked_print, mock_ingest, mock_oauth, mock_env_var):
        """Test case to verify that we raise TypeError when we get JSON response in unexpected format."""


        mocked_session = mock.Mock()
        mocked_response = req.Response()
        mocked_response.status_code = 200
        mocked_response._content = 12
        mocked_session.get.return_value = mocked_response

        with self.assertRaises(TypeError):
            get_events(mocked_session)

        mocked_print.assert_called_with("ERROR: Unexpected data format received while collecting OneLogin events")

    def test_empty_response(self, mock_ingest, mock_oauth, mock_env_var):
        """
        Test that the `get_events` function ingest empty list without any error in case of no data from API it self.
        """
        mocked_session = mock.Mock()
        mocked_get = mock.Mock()
        mocked_get.json.return_value = {'data':[], 'pagination': {'next_link': None}}
        mocked_session.get.return_value = mocked_get
        get_events(mocked_session)

        self.assertEqual(mock_ingest.call_count, 0)

    def test_multiple_page_response(self, mock_ingest, mock_oauth, mock_env_var):
        """
        Test that the `get_events` function ingest list of events without any error in case of multiple pages from API.
        """
        mocked_session = mock.Mock()
        mocked_get = mock.Mock()
        mocked_get.json.side_effect = [
            {'data':[{'id': 1}], 'pagination': {'next_link': 'next_link_1'}},
            {'data':[{'id': 2}], 'pagination': {'next_link': None}}
        ]

        mocked_session.get.return_value = mocked_get
        get_events(mocked_session)
        
        actual_calls = mock_ingest.mock_calls
        expected_calls = [
            mock.call([{'id': 1}], 'ONELOGIN_SSO'),
            mock.call([{'id': 2}], 'ONELOGIN_SSO')
        ]
        self.assertEqual(actual_calls, expected_calls)
        self.assertEqual(mock_ingest.call_count, 2)

    @mock.patch("OneLogin_Events.main.datetime")
    @mock.patch("OneLogin_Events.main.get_last_run_at", return_value="2022-01-01 10:05:15.234566")
    def test_log_retrieve_time(self, mock_last_run_at, mocked_datetime, mock_ingest, mock_oauth, mock_env_var):
        """Test case to verify that log retrieve time is passed as expected."""
        now_date = datetime.datetime(2022, 1, 1, 10, 15, 15, 234566)
        mocked_datetime.datetime.side_effect = datetime.datetime
        mocked_datetime.datetime.now.return_value = now_date
        mocked_datetime.side_effect = datetime

        mocked_session = mock.Mock()
        mocked_get = mock.Mock()
        mocked_get.json.return_value = {'data':[], 'pagination': {'next_link': None}}
        mocked_session.get.return_value = mocked_get

        get_events(mocked_session)

        args, _ = mocked_session.get.call_args
        expected_start_date = "2022-01-01T10:05:15.234Z" # (now - 10 minutes)
        expected_end_date = "2022-01-01T10:15:15.234Z"
        expected_url = f"https://api.us.onelogin.com/api/1/events?since={expected_start_date}&until={expected_end_date}"
        self.assertEqual(args[0], expected_url)

    @mock.patch('OneLogin_Events.main.get_events')
    def test_http_error(self, mock_ingest, mock_oauth, mock_env_var, mock_events):
        """
        Test that `main` function raises exception if API returns error. 
        """
        mock_events.side_effect = requests.requests.exceptions.HTTPError()

        with self.assertRaises(requests.requests.exceptions.HTTPError):
            main(request="")
