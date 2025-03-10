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
"""Unittest cases for Duo Activty ingestion script."""

import datetime
import os
import sys
import tempfile
import unittest
import unittest.mock

import requests


INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest"] = mock.Mock()

INGESTION_SCRIPTS_PATH_1 = ""

MOCK_OS_ENVIRON_TEST_2 = {
    "skey": "abc",
    "ikey": "123",
    "DUO_SECRET_KEY": "abc",
    "DUO_INTEGRATION_KEY": "123",
    "CHRONICLE_CUSTOMER_ID": "456",
    "CHECKPOINT_FILE_PATH": "checkpoint.json",
    "LOG_FETCH_DURATION": "1",
    "BACKSTORY_API_V1_URL": (
        "https://api-a0bd0de3.duosecurity.com/admin/v2/logs/activity"
    ),
    "SCOPES": "https://www.googleapis.com/auth/chronicle-backstory",
    "SERVICE_ACCOUNT_FILE": "service_account.json",
}
sys.modules["os"].environ = MOCK_OS_ENVIRON_TEST_2


import main


class TestFetchLogsAndIngest(unittest.TestCase):
  """Test cases for fetching logs and ingesting them into Chronicle."""

  @unittest.mock.patch("requests.get")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_invalid_log_duration_input(
      self, mock_get_env_var, mock_ingest, mock_get  # pylint: disable=unused-argument
  ):
    """Test that invalid log fetch duration inputs are handled gracefully."""
    mock_get_env_var.side_effect = [
        "https://api-a0bd0de3.duosecurity.com/admin/v2/logs/activity",
        "invalid",  # Invalid log_fetch_duration
        "abc",
        "123",
    ]

    with self.assertRaises(ValueError):
      main.fetch_logs_and_ingest()

  @unittest.mock.patch("requests.get")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_log_fetch_duration(self, mock_get_env_var, mock_ingest, mock_get):  # pylint: disable=unused-argument
    """Test that start and end times are calculated correctly for different log fetch durations."""
    mock_get_env_var.side_effect = [
        "https://api-a0bd0de3.duosecurity.com/admin/v2/logs/activity",
        "7",  # log_fetch_duration = 7 days
        "abc",
        "123",
    ]

    main.fetch_logs_and_ingest()

    now = datetime.datetime.now(tz=datetime.timezone.utc)

    expected_start_of_period = (now - datetime.timedelta(days=7)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    expected_end_of_period = (
        now.replace(hour=0, minute=0, second=0, microsecond=0)
        - datetime.timedelta(seconds=1)
    )

    expected_start_epoch = int(expected_start_of_period.timestamp() * 1000)
    expected_end_epoch = int(expected_end_of_period.timestamp() * 1000)

    self.assertEqual(
        mock_get.call_args[1]["params"]["mintime"], str(expected_start_epoch)
    )
    self.assertEqual(
        mock_get.call_args[1]["params"]["maxtime"], str(expected_end_epoch)
    )

  @unittest.mock.patch("requests.get")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_failed_log_ingestion_due_to_invalid_logs(
      self, mock_get_env_var, mock_ingest, mock_get  # pylint: disable=unused-argument
  ):
    """Test successful fetching and ingestion of logs."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
      file_path = temp_file.name
    # Mock API response
    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = {
        "response": {"items": [{"key": "value"}]}
    }
    mock_response.raise_for_status.side_effect = Exception("Mocked exception")
    # mock_response.raise_for_status. =
    mock_get.return_value = mock_response

    with self.assertRaises(Exception) as context:
      ingest_to_chronicle_mock = unittest.mock.MagicMock()
      with unittest.mock.patch(
          f"{INGESTION_SCRIPTS_PATH}main.ingest_to_chronicle",
          ingest_to_chronicle_mock,
      ):
        main.fetch_logs_and_ingest(file_path=file_path)
    self.assertEqual(
        str(context.exception), "Mocked exception"
    )

    # if os.path.exists(file_path):
    #   os.remove(file_path)

    # Asserts
    # mock_get.assert_called_once()
    # ingest_to_chronicle_mock.assert_called_once()

  @unittest.mock.patch("requests.get")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_successful_log_fetching_and_ingestion(
      self, mock_get_env_var, mock_ingest, mock_get  # pylint: disable=unused-argument
  ):
    """Test successful fetching and ingestion of logs."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
      file_path = temp_file.name
    # Mock API response
    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = {
        "response": {"items": [{"key": "value"}]}
    }
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response
    mock_ingest.return_value = unittest.mock.MagicMock()

    # Mock ingest_to_chronicle function.
    # ingest_to_chronicle_mock = unittest.mock.MagicMock()
    # with unittest.mock.patch(
    #     f"{INGESTION_SCRIPTS_PATH}main.ingest_to_chronicle",
    #     ingest_to_chronicle_mock,
    # ):
    main.fetch_logs_and_ingest(file_path=file_path)

    if os.path.exists(file_path):
      os.remove(file_path)

    # Asserts
    mock_get.assert_called_once()
    # ingest_to_chronicle_mock.assert_called_once()
    self.assertEqual(mock_ingest.call_count, 1)

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_default_maxtime(self, mock_get_env_var):
    """Mock the environment variable to return a controlled value."""
    today = datetime.datetime.now(tz=datetime.timezone.utc)
    mock_get_env_var.side_effect = [
        "https://api-a0bd0de3.duosecurity.com/admin/v2/logs/activity",
        1,
        "abc",
        "123",
    ]

    yesterday = today - datetime.timedelta(
        days=int(mock_get_env_var.return_value[1])
    )

    end_of_yesterday = datetime.datetime(
        yesterday.year,
        yesterday.month,
        yesterday.day,
        23,
        59,
        59,
        tzinfo=datetime.timezone.utc,
    )

    end_epoch = end_of_yesterday.timestamp()

    self.assertIsNotNone(end_epoch)

  @unittest.mock.patch("requests.get")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_failed_log_fetching_due_to_invalid_api_response(
      self, mock_get_env_var, mock_ingest, mock_get    # pylint: disable=unused-argument
  ):
    """Test log fetching failure due to invalid API response."""
    # Mock API response
    mock_response = unittest.mock.MagicMock()
    mock_response.raise_for_status.side_effect = requests.HTTPError()
    mock_get.return_value = mock_response

    # Test function
    ingest_to_chronicle_mock = unittest.mock.MagicMock()
    with unittest.mock.patch(
        f"{INGESTION_SCRIPTS_PATH}main.ingest_to_chronicle",
        ingest_to_chronicle_mock,
    ):
      main.fetch_logs_and_ingest()

    # Asserts
    mock_get.assert_called_once()
    # Check if ingest_to_chronicle was not called
    ingest_to_chronicle_mock.assert_not_called()

  @unittest.mock.patch("requests.get")
  @unittest.mock.patch("builtins.print")  # Patch the print function
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_failed_log_ingestion_due_to_non_dictionary_response(
      self,
      mock_get_env_var,  # pylint: disable=unused-argument
      mock_ingest,  # pylint: disable=unused-argument
      mock_print,
      mock_get
      ):
    """Test ingestion failure due to a non-dictionary response."""
    # Mock API response returning a non-dictionary (list) instead
    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = [
        "not",
        "a",
        "dictionary",
    ]  # Return a list instead
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    # Mock ingest_to_chronicle function
    with unittest.mock.patch(
        f"{INGESTION_SCRIPTS_PATH}main.ingest_to_chronicle"
    ) as ingest_to_chronicle_mock:
      # Call the function to handle logs
      main.fetch_logs_and_ingest()

    # Asserts
    mock_get.assert_called_once()
    ingest_to_chronicle_mock.assert_not_called()
    mock_print.assert_called_once_with("Received logs is not a dictionary.")

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_failed_http_request(
      self,
      mock_get_env_var,  # pylint: disable=unused-argument
      mock_ingest,  # pylint: disable=unused-argument
      ):
    """Test ingestion failure due to a non-dictionary response."""
    invalid_list = [1, "yes", 4]
    with self.assertRaises(TypeError) as context:
      main.ingest_to_chronicle(invalid_list)
    self.assertEqual(
        str(context.exception), "Each log must be a dictionary."
    )

  @unittest.mock.patch("requests.get")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_exception_handling_for_requests_requestexception(self, mock_get_env_var, mock_get):   # pylint: disable=unused-argument,unused-variable,disable=line-too-long
    """Test exception handling for requests.RequestException."""
    # Mock API response
    mock_response = unittest.mock.MagicMock()
    mock_response.raise_for_status.side_effect = requests.RequestException()
    mock_get.return_value = mock_response

    # Test function
    mock_get.return_value = "1"
    main.fetch_logs_and_ingest()

    # Asserts
    mock_get.assert_called_once()


class TestSignFunction(unittest.TestCase):
  """Test cases for the sign function."""

  def test_skey_none(self):
    """Test that skey becomes an empty string if None is passed."""
    result = main.sign("GET", "api.example.com", "/test", {}, "", "valid_skey")
    self.assertIsNotNone(result["Authorization"])
    self.assertNotEqual(result["Authorization"], "")

  def test_skey_valid(self):
    """Test that valid skey is converted to string."""
    result = main.sign(
        "GET", "api.example.com", "/test", {}, "valid_ikey", "123"
    )
    self.assertRegex(result["Authorization"], r"Basic .*")

  @unittest.mock.patch("requests.get")
  @unittest.mock.patch(
      f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_value_from_secret_manager"
  )
  def test_exception_handling_for_requests_requestexception(
      self, mock_get_secret_manager, mock_get
  ):  # pylint: disable=unused-argument,unused-variable,disable=line-too-long
    """Test exception handling for requests.RequestException."""
    # Mock API response
    mock_response = unittest.mock.MagicMock()
    mock_response.raise_for_status.side_effect = requests.RequestException()
    mock_get.return_value = mock_response

    # Test function
    mock_get.return_value = "1"
    mock_get_secret_manager.return_value = "valid_skey"
    main.fetch_logs_and_ingest()
    self.assertEqual(
        main.utils.get_env_var("DUO_SECRET_KEY", is_secret=True), "valid_skey"
    )
    self.assertEqual(mock_get_secret_manager.call_count, 3)

  def test_ikey_none(self):
    """Test that ikey becomes an empty string if None is passed."""
    result = main.sign("GET", "api.example.com", "/test", {}, "valid_ikey", "")
    self.assertIsNotNone(result["Authorization"])
    self.assertNotEqual(result["Authorization"], "")

  def test_ikey_valid(self):
    """Test that valid ikey is converted to string."""
    result = main.sign(
        "GET", "api.example.com", "/test", {}, "valid_ikey", "456"
    )
    self.assertRegex(result["Authorization"], r"Basic .*")

  def test_valid_input(self):
    """Test signing with valid input parameters."""
    method = "GET"
    host = "example.com"
    path = "/api/endpoint"
    params = {"key": "value"}
    skey = "secret_key"
    ikey = "integration_key"

    result = main.sign(method, host, path, params, skey, ikey)
    self.assertIsInstance(result, dict)
    self.assertIn("Date", result)
    self.assertIn("Authorization", result)

  def test_empty_query_params(self):
    """Test signing with empty query parameters."""
    method = "GET"
    host = "example.com"
    path = "/api/endpoint"
    params = {}
    skey = "secret_key"
    ikey = "integration_key"

    result = main.sign(method, host, path, params, skey, ikey)
    self.assertIsInstance(result, dict)
    self.assertIn("Date", result)
    self.assertIn("Authorization", result)

  def test_none_query_params(self):
    """Test signing with None as query parameters."""
    method = "GET"
    host = "example.com"
    path = "/api/endpoint"
    params = None
    skey = "secret_key"
    ikey = "integration_key"

    with self.assertRaises(ValueError):
      main.sign(method, host, path, params, skey, ikey)

  def test_invalid_input_types(self):
    """Test signing with invalid input types."""
    method = 123  # Invalid type for method
    host = "example.com"
    path = "/api/endpoint"
    params = {"key": "value"}
    skey = "secret_key"
    ikey = "integration_key"

    with self.assertRaises(TypeError) as context:
      main.sign(method, host, path, params, skey, ikey)
    self.assertEqual(str(context.exception), "Method must be a string.")

    method = "GET"
    host = 123  # Invalid type for host
    path = "/api/endpoint"
    params = {"key": "value"}
    skey = "secret_key"
    ikey = "integration_key"

    with self.assertRaises(TypeError) as context:
      main.sign(method, host, path, params, skey, ikey)
    self.assertEqual(str(context.exception), "Host must be a string.")

  def test_missing_required_params(self):
    """Test signing with missing required parameters."""
    method = "GET"
    host = "example.com"
    path = "/api/endpoint"
    params = {"key": "value"}
    skey = "secret_key"

    with self.assertRaises(TypeError):
      main.sign(method, host, path, params, skey)  # pylint: disable=no-value-for-parameter


class TestIngestToChronicle(unittest.TestCase):
  """Test cases for ingesting logs into Chronicle."""

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_ingest_with_empty_logs(self, mock_ingest, mock_get_env_var):
    """Test ingestion when logs are empty."""
    logs = {}
    result = main.ingest_to_chronicle(logs)
    mock_get_env_var.return_value = "checkpoint.json"
    self.assertEqual(result, "No logs to ingest.")
    mock_ingest.assert_not_called()

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  def test_ingest_with_valid_logs(self, mock_ingest):
    """Test ingestion with valid logs."""
    logs = [{"key": "value"}]
    result = main.ingest_to_chronicle(logs)
    self.assertEqual(result, "Logs successfully ingested into Chronicle.")
    mock_ingest.assert_called_once_with(logs, "DUO_ACTIVITY")

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_ingest_with_invalid_logs(
      self, mock_ingest, mock_get_env_var  # pylint: disable=unused-argument
  ):  # pylint: disable=unused-argument
    """Test ingestion with invalid log type."""
    logs = "invalid logs"
    with self.assertRaises(TypeError) as context:
      main.ingest_to_chronicle(logs)
    self.assertEqual(
        str(context.exception), "Logs must be a list of dictionaries."
    )
    mock_ingest.assert_not_called()

  @unittest.mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest",
      side_effect=Exception("Mocked exception"),
  )
  def test_ingest_with_exception(self, mock_ingest):
    """Test ingestion when an exception occurs."""
    logs = [
        {"event": "login", "user": "user1"},
        {"event": "logout", "user": "user1"},
    ]
    mock_ingest.side_effect = Exception("Mocked exception")
    result = main.ingest_to_chronicle(logs)
    self.assertEqual(
        result, "Failed to ingest logs into Chronicle. Error: Mocked exception"
    )
    mock_ingest.assert_called_once_with(logs, "DUO_ACTIVITY")


class TestWriteCheckpoint(unittest.TestCase):
  """Test cases for writing checkpoint data."""

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_checkpoint_file_created(self, mock_get_env_var):
    """Test that the checkpoint file is created."""
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    mock_get_env_var.return_value = temp_file.name
    main.write_checkpoint(1643723400)
    self.assertTrue(os.path.exists(temp_file.name))
    os.remove(temp_file.name)

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_checkpoint_file_contents(self, mock_get_env_var):
    """Test that the checkpoint file contains the correct timestamp."""
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    mock_get_env_var.return_value = temp_file.name
    timestamp = 1643723400
    main.write_checkpoint(timestamp)
    with open(temp_file.name, "r") as file:
      content = file.read()
      # You can parse content if necessary, depending on how it's written
      self.assertIn(str(timestamp), content)
    os.remove(temp_file.name)

  def test_non_integer_timestamp(self):
    """Test writing a checkpoint with a non-integer timestamp."""
    with self.assertRaises(TypeError):
      main.write_checkpoint("1643723400")

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_negative_timestamp(self, mock_get_env_var):
    """Test writing a checkpoint with a negative timestamp."""
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    mock_get_env_var.return_value = temp_file.name
    with self.assertRaises(ValueError):
      main.write_checkpoint(-1643723400)
    os.remove(temp_file.name)

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_overwrite_existing_file(self, mock_get_env_var):
    """Test overwriting the checkpoint file with a new timestamp."""
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    mock_get_env_var.return_value = temp_file.name

    with open(temp_file.name, "w") as file:
      file.write("12345")
    main.write_checkpoint(1643723400)

    with open(temp_file.name, "r") as file:
      self.assertEqual(file.read().strip(), "1643723400")

    os.remove(temp_file.name)

  def tearDown(self):
    """Remove the checkpoint file after each test."""
    if os.path.exists("checkpoint.json"):
      os.remove("checkpoint.json")
    super().tearDown()


class TestMainFunction(unittest.TestCase):
  """Test cases for the main function of the ingestion script."""

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH}main.fetch_logs_and_ingest")
  def test_successful_ingestion(self, mock_fetch_logs_and_ingest):
    """Test main function for successful log ingestion."""
    mock_fetch_logs_and_ingest.return_value = None
    request = unittest.mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertEqual(result, "Scheduled ingestion completed successfully.\n")
    mock_fetch_logs_and_ingest.assert_called_once_with("output.json")

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_ingestion_failure_due_to_exception(self, mock_fetch_logs_and_ingest):
    """Test main function for ingestion failure due to an exception."""
    mock_fetch_logs_and_ingest.side_effect = Exception("Test exception")
    request = unittest.mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertEqual(
        result, "Ingestion not completed due to unexpected error.\n"
    )

  @unittest.mock.patch(f"{INGESTION_SCRIPTS_PATH_1}main.utils.get_env_var")
  def test_ingestion_failure_due_to_unexpected_error(
      self, mock_fetch_logs_and_ingest
  ):
    """Test main function for ingestion failure due to an unexpected error."""
    mock_fetch_logs_and_ingest.side_effect = RuntimeError("Test runtime error")
    request = unittest.mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertEqual(
        result, "Ingestion not completed due to unexpected error.\n"
    )
