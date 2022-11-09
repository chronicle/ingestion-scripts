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
from datetime import datetime
import sys
from unittest import mock
import unittest
import requests

sys.modules["chronicle.ingest"] = mock.Mock()
from slack.main import main

def mock_get_env_var(*args, **kwargs):
    """Mock and return env variable values."""
    if args[0] == "FUNCTION_MINUTE_INTERVAL":
        return 10
    else:
        return "test"

# Mock data
_test_entities = [
    {
        "entries": [
            {"id": "0123a45b-6c7d-8900-e12f-3456789gh0i1"},
            {"id": "0123a45b-6c7d-8900-e12f-3456789gh0i2"}
        ],
        "response_metadata": {
            "next_cursor": "dXNlcjpVMEc5V0ZYTlo="
        }
    },
    {
        "entries": [
            {"id": "0123a45b-6c7d-8900-e12f-3456789gh0i3"},
            {"id": "0123a45b-6c7d-8900-e12f-3456789gh0i4"}
        ],
        "response_metadata": {
            "next_cursor": ""
        }
    }
]

def get_mock_response():
    """Return a mock response."""
    response = mock.Mock()
    response.raise_for_status = mock.Mock()
    response.status_code = 200
    return response

@mock.patch("slack.main.get_env_var", side_effect=mock_get_env_var)
@mock.patch("slack.main.ingest")
@mock.patch("requests.get")
class TestSlack(unittest.TestCase):
    """Test cases to verify Slack ingestion script"""

    @mock.patch("builtins.print")
    def test_http_error(self, mocked_print, mocked_get, mocked_ingest, mocked_get_env_var):
        """Test case to ensure that we raise errors when status code other than 2XX is encountered."""
        response = get_mock_response()
        response.raise_for_status.side_effect = requests.HTTPError()
        response.status_code = 400
        response.json.return_value = {
            "code": "access_denied",
            "description": "You do not have sufficient permissions to view this resource."
        }
        mocked_get.return_value = response

        with self.assertRaises(requests.HTTPError):
            main(req="")

        mocked_print.assert_called_with("HTTP Error: 400, Reason: {'code': 'access_denied', 'description': 'You do not have sufficient permissions to view this resource.'}")

    @mock.patch("builtins.print")
    def test_value_error(self, mocked_print, mocked_get, mocked_ingest, mocked_get_env_var):
        """Test case to ensure that we raise error when we encounter ValueError from JSON response."""
        response = get_mock_response()
        response.json.side_effect = ValueError
        mocked_get.return_value = response

        with self.assertRaises(ValueError):
            main(req="")

        mocked_print.assert_called_with(
                "ERROR: Unexpected data format received while collecting \
                 audit logs")

    def test_no_logs_to_ingest(self, mocked_get, mocked_ingest, mocked_get_env_var):
        """Test case to ensure that we break the loop when there are no logs to ingest."""
        response = get_mock_response()
        response.json.return_value = {
            "entries": []
        }
        mocked_get.return_value = response

        main(req="")

        self.assertEqual(mocked_ingest.call_count, 0)

    @mock.patch("slack.main.datetime")
    def test_log_retrieve_time(self, mocked_datetime, mocked_get, mocked_ingest, mocked_get_env_var):
        """Test case to verify the log retrieve time is as expected."""
        mocked_datetime.utcnow.return_value = datetime(2022, 1, 1, 10, 15, 15)
        mocked_datetime.side_effect = datetime

        response = get_mock_response()
        response.json.return_value = {
            "entries": []
        }
        mocked_get.return_value = response

        main(req="")

        _, kwargs = mocked_get.call_args
        expected_log_retrieve_time = 1641031515 # (2022-01-01 10:15:15) - 10 minutes = (2022-01-01 10:05:15)
        self.assertEqual(
            kwargs.get("url"),
            f"https://api.slack.com/audit/v1/logs?oldest={expected_log_retrieve_time}")

    def test_pagination(self, mocked_get, mocked_ingest, mocked_get_env_var):
        """Test case to verify we fetch next page records when the API response contains next cursor."""
        response = get_mock_response()
        response.json.side_effect = _test_entities
        mocked_get.return_value = response

        main(req="")

        actual_calls = mocked_ingest.mock_calls
        expected_calls = [
            mock.call(
                [
                    {"id": "0123a45b-6c7d-8900-e12f-3456789gh0i1"},
                    {"id": "0123a45b-6c7d-8900-e12f-3456789gh0i2"}
                ], "SLACK_AUDIT"), # Call ingest with 1st page logs
            mock.call(
                [
                    {"id": "0123a45b-6c7d-8900-e12f-3456789gh0i3"},
                    {"id": "0123a45b-6c7d-8900-e12f-3456789gh0i4"}
                ], "SLACK_AUDIT") # Call ingest with 2nd page logs
        ]
        self.assertEqual(mocked_ingest.call_count, 2)
        self.assertEqual(actual_calls, expected_calls)
