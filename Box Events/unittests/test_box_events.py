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
"""Unit tests for the 'main' module."""

import logging
import unittest
import sys
from unittest import mock
from datetime import datetime
import requests

# Mock the chronicle library
sys.modules['chronicle.ingest'] = mock.MagicMock()
from Box_Events.main import main

def get_mock_response():
    """Return a mock response."""
    response = mock.Mock()
    response.raise_for_status = mock.Mock()
    response.status_code = 200
    return response

@mock.patch("Box_Events.main.get_env_var")
@mock.patch("Box_Events.main.get_last_run_at")
@mock.patch("chronicle.auth.requests.Session.send")
@mock.patch("Box_Events.main.ingest")
class TestBox(unittest.TestCase):

    def test_no_logs_to_ingest(self, mocked_ingest, mocked_send, mocked_get_last_run_at, mocked_get_env_var):
        """Test case to verify that we do not call ingest function when there are no logs to ingest."""

        mock_response_1 = get_mock_response()
        mock_response_1.json.return_value = {"access_token": "test_access_token"}

        mock_response_2 = get_mock_response()
        mock_response_2.json.return_value = {"entries": [], "chunk_size": 0}

        mocked_send.side_effect = [mock_response_1, mock_response_2]

        main(request="")

        self.assertEqual(mocked_ingest.call_count, 0)

    @mock.patch("Box_Events.main.datetime")
    def test_pagination(self, mocked_datetime, mocked_ingest, mocked_send, mocked_get_last_run_at, mocked_get_env_var):
        """
        Test case to verify the pagination mechanism.
        """
        mocked_get_last_run_at.return_value = datetime(2021, 12, 20, 11, 34, 55)
        mocked_datetime.now.return_value = datetime(2022, 1, 1, 10, 15, 15)
        mocked_datetime.side_effect = datetime

        mock_response_1 = get_mock_response()
        mock_response_1.json.return_value = {"access_token": "test_access_token"}

        mock_response_2 = get_mock_response()
        mock_response_2.json.return_value = {"entries": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}], "chunk_size": 5, "next_stream_position": 1152922976252290800}

        mock_response_3 = get_mock_response()
        mock_response_3.json.return_value = {"entries": [{"id": 6}, {"id": 7}], "chunk_size": 2, "next_stream_position": "now"}

        mock_response_4 = get_mock_response()
        mock_response_4.json.return_value = {"entries": [], "chunk_size": 0}

        mocked_send.side_effect = [mock_response_1, mock_response_2, mock_response_3, mock_response_4]

        main(request="")

        actual_url_calls = [call.args[0].url for call in mocked_send.mock_calls[1:]]
        expected_url_calls = [
            "https://api.box.com/2.0/events?stream_type=admin_logs&limit=100&created_after=2021-12-20T11%3A34%3A55Z&created_before=2022-01-01T10%3A15%3A15Z",
            "https://api.box.com/2.0/events?stream_type=admin_logs&limit=100&created_after=2021-12-20T11%3A34%3A55Z&created_before=2022-01-01T10%3A15%3A15Z&stream_position=1152922976252290800",
            "https://api.box.com/2.0/events?stream_type=admin_logs&limit=100&created_after=2021-12-20T11%3A34%3A55Z&created_before=2022-01-01T10%3A15%3A15Z&stream_position=now"
        ]
        expected_calls_ingest = [
            mock.call([{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}], "BOX"),
            mock.call([{"id": 6}, {"id": 7}], "BOX")
        ]
        self.assertEqual(mocked_ingest.call_count, 2)
        self.assertEqual(mocked_ingest.mock_calls, expected_calls_ingest)
        self.assertEqual(actual_url_calls, expected_url_calls)

    def test_http_error(self, mocked_ingest, mocked_send, mocked_get_last_run_at, mocked_get_env_var):
        """
        Test case to verify http error
        """
        mock_response_1 = get_mock_response()
        mock_response_1.json.return_value = {"access_token": "test_access_token"}

        mock_response_2 = get_mock_response()
        mock_response_2.raise_for_status.side_effect = requests.HTTPError()
        mock_response_2.status_code = 400

        mocked_send.side_effect = [mock_response_1, mock_response_2]

        with self.assertRaises(requests.HTTPError):
            main(request="")

    @mock.patch("Box_Events.main.datetime")
    def test_log_retrieve_time(self, mocked_datetime, mocked_ingest, mocked_send, mocked_get_last_run_at, mocked_get_env_var):
        """
        Test case to verify that log retrieve time is passed as expected.
        """
        mocked_get_last_run_at.return_value = datetime(2021, 12, 20, 11, 34, 55)
        mocked_datetime.now.return_value = datetime(2022, 1, 1, 10, 15, 15)
        mocked_datetime.side_effect = datetime

        mock_response_1 = get_mock_response()
        mock_response_1.json.return_value = {"access_token": "test_access_token"}

        mock_response_2 = get_mock_response()
        mock_response_2.json.return_value = {"entries": [], "chunk_size": 0}

        mocked_send.side_effect = [mock_response_1, mock_response_2]

        main(request="")

        args, _ = mocked_send.call_args
        actual_url = args[0].url
        expected_url = "https://api.box.com/2.0/events?stream_type=admin_logs&limit=100&created_after=2021-12-20T11%3A34%3A55Z&created_before=2022-01-01T10%3A15%3A15Z"
        self.assertEqual(actual_url, expected_url)

    @mock.patch("builtins.print")
    def test_value_error(self, mocked_print, mocked_ingest, mocked_send, mocked_get_last_run_at, mocked_get_env_var):
        """Test case to verify that we raise ValueError when we get invalid JSON response."""
        mock_response_1 = get_mock_response()
        mock_response_1.json.return_value = {"access_token": "test_access_token"}

        mocked_response_2 = requests.Response()
        mocked_response_2.status_code = 200
        mocked_response_2.data = None

        mocked_send.side_effect = [mock_response_1, mocked_response_2]

        with self.assertRaises(ValueError):
            main(request="")

        mocked_print.assert_called_with("ERROR: Unexpected data format received while collecting Box events")

    @mock.patch("builtins.print")
    def test_type_error(self, mocked_print, mocked_ingest, mocked_send, mocked_get_last_run_at, mocked_get_env_var):
        """Test case to verify that we raise TypeError when we get JSON response in unexpected format."""

        mock_response_1 = get_mock_response()
        mock_response_1.json.return_value = {"access_token": "test_access_token"}

        mocked_response_2 = requests.Response()
        mocked_response_2.status_code = 200
        mocked_response_2._content = 12

        mocked_send.side_effect = [mock_response_1, mocked_response_2]

        with self.assertRaises(TypeError):
            main(request="")

        mocked_print.assert_called_with("ERROR: Unexpected data format received while collecting Box events")
