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
"""Unit test case file for duo client."""
import datetime
import sys
import time

import unittest
from unittest import mock

INGESTION_SCRIPTS_PATH = "google3.third_party.chronicle.ingestion_scripts"
sys.modules[f"{INGESTION_SCRIPTS_PATH}.common.ingest"] = mock.Mock()


def mock_get_env_var(*args, **unused_kwargs):
  """Mock and return env variable values.

  Args:
    *args (list[Any]): Any number of positional arguments.
    **unused_kwargs (list[Any]): Any number of keyword arguments.

  Returns:
    Value of POLL_INTERVAL environment variable as 10.
    Dummy values of DUO_API_DETAILS environment variable.
    Dummy value as "test" for any other environment variable.
  """
  if args[0] == "POLL_INTERVAL":
    return 10
  elif args[0] == "DUO_API_DETAILS":
    return '{"ikey": "", "skey": "", "api_host": ""}'
  else:
    return "test"


class TestDuoAdminIngestion(unittest.TestCase):
@mock.patch(
    f"{INGESTION_SCRIPTS_PATH}.duo_admin.main.utils.get_env_var",
    side_effect=mock_get_env_var)
@mock.patch(f"{INGESTION_SCRIPTS_PATH}.duo_admin.main.ingest.ingest")
@mock.patch(f"{INGESTION_SCRIPTS_PATH}.duo_admin.main.duo_client.Admin")
class TestDuoAdminIngestion(googletest.TestCase):
  """Test cases to verify Duo Admin ingestion script."""

  def test_no_logs_to_ingest(self, mocked_duo_admin, mocked_ingest,
                             unused_mocked_get_env_var):
    """Test case to ensure that we break the loop when there are no logs to ingest.

    Args:
      mocked_duo_admin (mock.Mock): Mocked object of duo_client.admmin module.
      mocked_ingest (mock.Mock): Mocked object of ingest method.
      unused_mocked_get_env_var (mock.Mock): Mocked object of get_env_var
        method.

    Asserts:
      Validates that ingest() method is not called if no records are returned
      from the Duo Admin API.
    """
    mock_duo_client = mock.Mock()
    mock_duo_client.get_administrator_log.return_value = []
    mocked_duo_admin.return_value = mock_duo_client

    main.main(req="")

    self.assertEqual(mocked_ingest.call_count, 0)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.duo_admin.main.utils.datetime")
  def test_log_retrieve_time(self, mocked_script_datetime, mocked_duo_admin,
                             unused_mocked_ingest, unused_mocked_get_env_var):
    """Test case to verify the log retrieve time is as expected.

    Args:
      mocked_script_datetime (mock.Mock): Mocked object of datetime module
        imported in ingestion script.
      mocked_duo_admin (mock.Mock): Mocked object of duo_client.admmin module.
      unused_mocked_ingest (mock.Mock): Mocked object of ingest method.
      unused_mocked_get_env_var (mock.Mock): Mocked object of get_env_var
        method.

    Asserts:
      Validates the start date from which data collection will start for Duo
      Admin logs. By default, the start date will be (now - 10 minutes).
    """
    now_date = datetime.datetime(
        2022, 1, 1, 10, 15, 15, 234566, tzinfo=datetime.timezone.utc)
    mocked_script_datetime.datetime.now.return_value = now_date
    mocked_script_datetime.timedelta.side_effect = datetime.timedelta

    mock_duo_client = mock.Mock()
    mock_duo_client.get_administrator_log.return_value = []
    mocked_duo_admin.return_value = mock_duo_client

    main.main(req="")

    _, kwargs = mock_duo_client.get_administrator_log.call_args
    # (2022-01-01 10:15:15) - 10 minutes = (2022-01-01 10:05:15)
    expected_log_start_time = 1641031515
    self.assertEqual(kwargs.get("mintime"), expected_log_start_time)

  def test_pagination(self, mocked_duo_admin, mocked_ingest,
                      unused_mocked_get_env_var):
    """Test case to verify we fetch next page records when the log count is 1000.

    Args:
      mocked_duo_admin (mock.Mock): Mocked object of duo_client.admmin module.
      mocked_ingest (mock.Mock): Mocked object of ingest method.
      unused_mocked_get_env_var (mock.Mock): Mocked object of get_env_var
        method.

    Asserts:
      Validates that the ingest() method is called twice if number of records
      are more than 1000.
      Validates the number of records being sent to the ingest() method during
      the execution.
    """
    dummy_logs = [
        [{
            "id": i, "timestamp": int(time.time() - i)
        } for i in range(1001, 1, -1)],  # 1st page, 1000 logs
        [{
            "id": i, "timestamp": int(time.time() - i)
        } for i in range(1545, 1001, -1)]  # 2nd page, 544 logs
    ]
    mock_duo_client = mock.Mock()
    mock_duo_client.get_administrator_log.side_effect = dummy_logs
    mocked_duo_admin.return_value = mock_duo_client

    main.main(req="")

    actual_calls = mocked_ingest.mock_calls
    expected_calls = [
        mock.call(dummy_logs[0], "DUO_ADMIN"),  # Call ingest with 1000 logs
        mock.call(dummy_logs[1], "DUO_ADMIN")  # Call ingest with 544 logs
    ]
    self.assertEqual(mocked_ingest.call_count, 2)
    self.assertEqual(actual_calls, expected_calls)

  def test_get_max_timestamp(
      self,
      mocked_duo_admin, mocked_ingest,  # pylint: disable=unused-argument
      unused_mocked_get_env_var):
    """Test case to verify if the maximum timestamp is identified from the logs.

    Args:
      mocked_duo_admin (mock.Mock): Mocked object of duo_client.admmin module.
      mocked_ingest (mock.Mock): Mocked object of ingest method.
      unused_mocked_get_env_var (mock.Mock): Mocked object of get_env_var
        method.

    Asserts:
      Record with maximum timestamp is returned by the get_max_timestamp()
      method.
    """
    dummy_logs = [{"id": dummy_val, "timestamp": dummy_val
                   } for dummy_val in range(0, 1000)]

    actual_latest_timestamp = main.get_last_timestamp(dummy_logs)
    expected_latest_timestamp = 999

    self.assertEqual(actual_latest_timestamp, expected_latest_timestamp)

if __name__ == "__main__":
  googletest.main()
