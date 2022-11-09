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
from time import time
from unittest import mock
import unittest

sys.modules["chronicle.ingest"] = mock.Mock()
from duo_admin.main import main

def mock_get_env_var(*args, **kwargs):
    """Mock and return env variable values."""
    if args[0] == "FUNCTION_MINUTE_INTERVAL":
        return 10
    elif args[0] == "DUO_API_DETAILS":
        return '{"ikey": "", "skey": "", "api_host": ""}'
    else:
        return "test"

@mock.patch("duo_admin.main.get_env_var", side_effect=mock_get_env_var)
@mock.patch("duo_admin.main.ingest")
@mock.patch("duo_admin.main.duo_client.Admin")
class TestDuoAdmin(unittest.TestCase):
    """Test cases to verify Duo Admin ingestion script"""

    def test_no_logs_to_ingest(self, mocked_duo_admin, mocked_ingest, mocked_get_env_var):
        """Test case to ensure that we break the loop when there are no logs to ingest."""
        mock_duo_client = mock.Mock()
        mock_duo_client.get_administrator_log.return_value = []
        mocked_duo_admin.return_value = mock_duo_client

        main(req="")

        self.assertEqual(mocked_ingest.call_count, 0)

    @mock.patch("duo_admin.main.datetime")
    def test_log_retrieve_time(self, mocked_datetime, mocked_duo_admin, mocked_ingest, mocked_get_env_var):
        """Test case to verify the log retrieve time is as expected."""
        mocked_datetime.utcnow.return_value = datetime(2022, 1, 1, 11, 17, 15)
        mocked_datetime.side_effect = datetime

        mock_duo_client = mock.Mock()
        mock_duo_client.get_administrator_log.return_value = []
        mocked_duo_admin.return_value = mock_duo_client

        main(req="")

        _, kwargs = mock_duo_client.get_administrator_log.call_args
        expected_log_retrieve_time = 1641035235 # (2022-01-01 11:17:15) - 10 miuntes = (2022-01-01 11:07:15)
        self.assertEqual(kwargs.get("mintime"), expected_log_retrieve_time)

    def test_pagination(self, mocked_duo_admin, mocked_ingest, mocked_get_env_var):
        """Test case to verify we fetch next page records when the log count is 1000."""
        dummy_logs = [
            [{"id": i, "timestamp": int(time() - i)} for i in range(1001, 1, -1)], # 1st page, 1000 logs
            [{"id": i, "timestamp": int(time() - i)} for i in range(1545 , 1001, -1)] # 2nd page, 544 logs
        ]
        mock_duo_client = mock.Mock()
        mock_duo_client.get_administrator_log.side_effect = dummy_logs
        mocked_duo_admin.return_value = mock_duo_client

        main(req="")

        actual_calls = mocked_ingest.mock_calls
        expected_calls = [
            mock.call(dummy_logs[0], "DUO_ADMIN"), # Call ingest with 1000 logs
            mock.call(dummy_logs[1], "DUO_ADMIN") # Call ingest with 544 logs
        ]
        self.assertEqual(mocked_ingest.call_count, 2)
        self.assertEqual(actual_calls, expected_calls)
