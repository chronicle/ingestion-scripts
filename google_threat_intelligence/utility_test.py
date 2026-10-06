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

# pylint: disable=line-too-long
# pylint: disable=g-importing-member
# pylint: disable=invalid-name
# pylint: disable=g-multiple-import
# pylint: disable=unused-argument
# pylint: disable=g-import-not-at-top
# pylint: disable=g-bad-import-order

"""Unit tests for utility functions."""

import os
import sys
import unittest
from unittest import mock
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import constant
import utility


mock_google_cloud = mock.Mock()
mock_exceptions = mock.Mock()
mock_exceptions.NotFound = (
    Exception  # Mock NotFound as a proper exception class
)
mock_google_cloud.exceptions = mock_exceptions
sys.modules["google.cloud"] = mock_google_cloud
sys.modules["google.cloud.storage"] = mock.Mock()
sys.modules["google.cloud.exceptions"] = mock_exceptions
sys.modules["google.cloud.secretmanager"] = mock.Mock()
INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest_v1"] = mock.Mock()
sys.modules["common.utils"] = mock.Mock()


class TestUtilityFunctions(unittest.TestCase):
  """Test cases for utility functions."""

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_default_behavior(self, mock_get_env_var):
    """Test get_environment_variable with default behavior (not required, not secret)."""
    # Arrange
    env_name = "TEST_VAR"
    mock_get_env_var.return_value = (  # With spaces and uppercase
        "  TEST_VALUE  "
    )

    # Act
    result = utility.get_environment_variable(env_name)

    # Assert
    self.assertEqual(result, "test_value")  # Should be lowercase and stripped
    mock_get_env_var.assert_called_once_with(
        env_name, required=False, is_secret=False, default=""
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_with_default_value(self, mock_get_env_var):
    """Test get_environment_variable with a default value from constants."""
    # Arrange
    env_name = constant.ENV_VAR_ENRICHMENT_ENABLED
    expected_default = constant.DEFAULT_VALUES[env_name]
    mock_get_env_var.return_value = "  TRUE  "

    # Act
    result = utility.get_environment_variable(env_name)

    # Assert
    self.assertEqual(result, "true")
    mock_get_env_var.assert_called_once_with(
        env_name, required=False, is_secret=False, default=expected_default
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_required_true(self, mock_get_env_var):
    """Test get_environment_variable with required=True."""
    # Arrange
    env_name = "REQUIRED_VAR"
    mock_get_env_var.return_value = "required_value"

    # Act
    result = utility.get_environment_variable(env_name, is_required=True)

    # Assert
    self.assertEqual(result, "required_value")
    mock_get_env_var.assert_called_once_with(
        env_name, required=True, is_secret=False, default=""
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_value_from_secret_manager")
  @patch.dict(os.environ, {"SECRET_VAR": "projects/test/secrets/my-secret"})
  def test_get_environment_variable_secret_with_versions(self, mock_get_secret):
    """Test get_environment_variable with is_secret=True and path already has versions."""
    # Arrange
    env_name = "SECRET_VAR"
    secret_path = "projects/test/secrets/my-secret/versions/1"
    expected_secret_value = "secret_value_123"

    with patch.dict(os.environ, {env_name: secret_path}):
      mock_get_secret.return_value = expected_secret_value

      # Act
      result = utility.get_environment_variable(env_name, is_secret=True)

      # Assert
      self.assertEqual(result, expected_secret_value)
      mock_get_secret.assert_called_once_with(secret_path)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_value_from_secret_manager")
  @patch.dict(os.environ, {"SECRET_VAR": "projects/test/secrets/my-secret"})
  def test_get_environment_variable_secret_without_versions(
      self, mock_get_secret
  ):
    """Test get_environment_variable with is_secret=True and path needs versions/latest."""
    # Arrange
    env_name = "SECRET_VAR"
    secret_path = "projects/test/secrets/my-secret"
    expected_secret_value = "secret_value_456"

    with patch.dict(os.environ, {env_name: secret_path}):
      mock_get_secret.return_value = expected_secret_value

      # Act
      result = utility.get_environment_variable(env_name, is_secret=True)

      # Assert
      self.assertEqual(result, expected_secret_value)
      mock_get_secret.assert_called_once_with(secret_path + "/versions/latest")

  def test_get_environment_variable_secret_required_missing(self):
    """Test get_environment_variable with is_secret=True, is_required=True but env var missing."""
    # Arrange
    env_name = "MISSING_SECRET_VAR"

    # Ensure the environment variable is not set
    if env_name in os.environ:
      del os.environ[env_name]

    # Act & Assert
    with self.assertRaises(RuntimeError) as context:
      utility.get_environment_variable(
          env_name, is_required=True, is_secret=True
      )

    self.assertEqual(
        str(context.exception), f"Environment variable {env_name} is required."
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_value_from_secret_manager")
  @patch.dict(os.environ, {"SECRET_VAR": "projects/test/secrets/my-secret"})
  def test_get_environment_variable_secret_not_required_exists(
      self, mock_get_secret
  ):
    """Test get_environment_variable with is_secret=True, is_required=False and env var exists."""
    # Arrange
    env_name = "SECRET_VAR"
    secret_path = "projects/test/secrets/my-secret"
    expected_secret_value = "optional_secret_value"

    with patch.dict(os.environ, {env_name: secret_path}):
      mock_get_secret.return_value = expected_secret_value

      # Act
      result = utility.get_environment_variable(
          env_name, is_required=False, is_secret=True
      )

      # Assert
      self.assertEqual(result, expected_secret_value)
      mock_get_secret.assert_called_once_with(secret_path + "/versions/latest")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_preserve_case_for_secret(
      self, mock_get_env_var
  ):
    """Test get_environment_variable preserves case when is_secret=False but value should not be lowercased."""
    # Arrange
    env_name = "CASE_SENSITIVE_VAR"
    mock_get_env_var.return_value = "  MixedCaseValue  "

    # Act
    result = utility.get_environment_variable(env_name)

    # Assert
    self.assertEqual(result, "mixedcasevalue")  # Should be lowercase
    mock_get_env_var.assert_called_once_with(
        env_name, required=False, is_secret=False, default=""
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_empty_string(self, mock_get_env_var):
    """Test get_environment_variable with empty string value."""
    # Arrange
    env_name = "EMPTY_VAR"
    mock_get_env_var.return_value = "   "  # Only spaces

    # Act
    result = utility.get_environment_variable(env_name)

    # Assert
    self.assertEqual(result, "")  # Should be empty after strip and lower
    mock_get_env_var.assert_called_once_with(
        env_name, required=False, is_secret=False, default=""
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.get_env_var")
  def test_get_environment_variable_multiple_scenarios(self, mock_get_env_var):
    """Test get_environment_variable with multiple different scenarios."""
    # Test cases with different combinations
    test_cases = [
        {
            "env_name": "TEST1",
            "is_required": False,
            "is_secret": False,
            "mock_return": "  Value1  ",
            "expected": "value1",
        },
        {
            "env_name": "TEST2",
            "is_required": True,
            "is_secret": False,
            "mock_return": "VALUE2",
            "expected": "value2",
        },
        {
            "env_name": constant.ENV_VAR_THREAT_LISTS,
            "is_required": False,
            "is_secret": False,
            "mock_return": "  ALL,MALWARE  ",
            "expected": "all,malware",
        },
    ]

    for test_case in test_cases:
      with self.subTest(env_name=test_case["env_name"]):
        # Reset mock
        mock_get_env_var.reset_mock()
        mock_get_env_var.return_value = test_case["mock_return"]

        # Act
        result = utility.get_environment_variable(
            test_case["env_name"],
            is_required=test_case["is_required"],
            is_secret=test_case["is_secret"],
        )

        # Assert
        self.assertEqual(result, test_case["expected"])

  def test_convert_epoch_to_utc_string_valid_epoch(self):
    """Test convert_epoch_to_utc_string with valid epoch timestamp."""
    # Arrange
    epoch_seconds = 1640995200  # 2022-01-01 00:00:00 UTC
    expected_result = "2022-01-01T00:00:00"

    # Act
    result = utility.convert_epoch_to_utc_string(epoch_seconds)

    # Assert
    self.assertEqual(result, expected_result)

  def test_convert_epoch_to_utc_string_different_timestamps(self):
    """Test convert_epoch_to_utc_string with different timestamp values."""
    test_cases = [
        {"epoch": 0, "expected": "1970-01-01T00:00:00"},  # Unix epoch start
        {
            "epoch": 946684800,
            "expected": "2000-01-01T00:00:00",
        },  # 2000-01-01 00:00:00 UTC
        {
            "epoch": 1577836800,
            "expected": "2020-01-01T00:00:00",
        },  # 2020-01-01 00:00:00 UTC
        {
            "epoch": 1672531200,
            "expected": "2023-01-01T00:00:00",
        },  # 2023-01-01 00:00:00 UTC
        {
            "epoch": 1640995261,
            "expected": "2022-01-01T00:01:01",
        },  # 2022-01-01 00:01:01 UTC
    ]

    for test_case in test_cases:
      with self.subTest(epoch=test_case["epoch"]):
        # Act
        result = utility.convert_epoch_to_utc_string(test_case["epoch"])

        # Assert
        self.assertEqual(result, test_case["expected"])

  def test_convert_epoch_to_utc_string_leap_year(self):
    """Test convert_epoch_to_utc_string with leap year date."""
    # Arrange - 2024-02-29 12:00:00 UTC (leap year)
    epoch_seconds = 1709208000
    expected_result = "2024-02-29T12:00:00"

    # Act
    result = utility.convert_epoch_to_utc_string(epoch_seconds)

    # Assert
    self.assertEqual(result, expected_result)

  def test_convert_epoch_to_utc_string_end_of_year(self):
    """Test convert_epoch_to_utc_string with end of year timestamp."""
    # Arrange - 2023-12-31 23:59:59 UTC
    epoch_seconds = 1704067199
    expected_result = "2023-12-31T23:59:59"

    # Act
    result = utility.convert_epoch_to_utc_string(epoch_seconds)

    # Assert
    self.assertEqual(result, expected_result)

  def test_convert_epoch_to_utc_string_float_epoch(self):
    """Test convert_epoch_to_utc_string with float epoch (should truncate)."""
    # Arrange
    epoch_seconds = 1640995200.789  # With fractional seconds
    expected_result = "2022-01-01T00:00:00"  # Should ignore fractional part

    # Act
    result = utility.convert_epoch_to_utc_string(epoch_seconds)

    # Assert
    self.assertEqual(result, expected_result)

  def test_convert_epoch_to_utc_string_negative_epoch(self):
    """Test convert_epoch_to_utc_string with negative epoch (before 1970)."""
    # Arrange - 1969-12-31 23:59:59 UTC
    epoch_seconds = -1
    expected_result = "1969-12-31T23:59:59"

    # Act
    result = utility.convert_epoch_to_utc_string(epoch_seconds)

    # Assert
    self.assertEqual(result, expected_result)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime")
  def test_convert_epoch_to_utc_string_uses_correct_pattern(
      self, mock_datetime
  ):
    """Test convert_epoch_to_utc_string uses the correct date pattern from constants."""
    # Arrange
    epoch_seconds = 1640995200
    mock_dt = MagicMock()
    mock_datetime.fromtimestamp.return_value = mock_dt
    mock_dt.strftime.return_value = "2022-01-01T00:00:00"

    # Act
    result = utility.convert_epoch_to_utc_string(epoch_seconds)

    # Assert
    mock_datetime.fromtimestamp.assert_called_once_with(
        epoch_seconds, tz=timezone.utc
    )
    mock_dt.strftime.assert_called_once_with(constant.IOC_STREAM_DATE_PATTERN)
    self.assertEqual(result, "2022-01-01T00:00:00")

  def test_convert_epoch_to_utc_string_current_time(self):
    """Test convert_epoch_to_utc_string with current time epoch."""
    # Arrange
    import time

    current_epoch = int(time.time())

    # Act
    result = utility.convert_epoch_to_utc_string(current_epoch)

    # Assert
    # Verify the result follows the expected pattern
    self.assertRegex(result, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")

    # Verify it's close to current time (within a few seconds)
    expected_dt = datetime.fromtimestamp(current_epoch, tz=timezone.utc)
    expected_str = expected_dt.strftime(constant.IOC_STREAM_DATE_PATTERN)
    self.assertEqual(result, expected_str)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.as_completed")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.ThreadPoolExecutor"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_run_methods_in_parallel_success(
      self, mock_cloud_logging, mock_executor_class, mock_as_completed
  ):
    """Test run_methods_in_parallel with successful method execution."""
    # Arrange
    mock_executor = MagicMock()
    mock_executor_class.return_value.__enter__.return_value = mock_executor

    # Create mock methods
    method1 = MagicMock()
    method2 = MagicMock()
    method3 = MagicMock()
    methods = [method1, method2, method3]

    # Mock futures
    future1 = MagicMock()
    future2 = MagicMock()
    future3 = MagicMock()
    futures = [future1, future2, future3]

    mock_executor.submit.side_effect = futures
    mock_as_completed.return_value = futures

    # Mock successful results
    future1.result.return_value = None
    future2.result.return_value = None
    future3.result.return_value = None

    # Act
    utility.run_methods_in_parallel(methods)

    # Assert
    self.assertEqual(mock_executor.submit.call_count, 3)
    mock_executor.submit.assert_any_call(method1)
    mock_executor.submit.assert_any_call(method2)
    mock_executor.submit.assert_any_call(method3)

    # Verify as_completed was called with the futures list
    mock_as_completed.assert_called_once_with(futures)

    # Verify all futures were waited for
    future1.result.assert_called_once()
    future2.result.assert_called_once()
    future3.result.assert_called_once()

    # No error logging should occur
    mock_cloud_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.as_completed")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.ThreadPoolExecutor"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_run_methods_in_parallel_with_exception(
      self, mock_cloud_logging, mock_executor_class, mock_as_completed
  ):
    """Test run_methods_in_parallel when one method raises an exception."""
    # Arrange
    mock_executor = MagicMock()
    mock_executor_class.return_value.__enter__.return_value = mock_executor

    # Create mock methods
    method1 = MagicMock()
    method2 = MagicMock()
    methods = [method1, method2]

    # Mock futures
    future1 = MagicMock()
    future2 = MagicMock()
    futures = [future1, future2]

    mock_executor.submit.side_effect = futures
    mock_as_completed.return_value = futures

    # Mock one successful result and one exception
    future1.result.return_value = None
    future2.result.side_effect = Exception("Method execution failed")

    # Act
    utility.run_methods_in_parallel(methods)

    # Assert
    self.assertEqual(mock_executor.submit.call_count, 2)
    mock_executor.submit.assert_any_call(method1)
    mock_executor.submit.assert_any_call(method2)

    # Verify as_completed was called with the futures list
    mock_as_completed.assert_called_once_with(futures)

    # Verify all futures were waited for
    future1.result.assert_called_once()
    future2.result.assert_called_once()

    # Error logging should occur for the exception
    mock_cloud_logging.assert_called_once_with(
        "Exception occurred while executing a method: Method execution failed",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.as_completed")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.ThreadPoolExecutor"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_run_methods_in_parallel_multiple_exceptions(
      self, mock_cloud_logging, mock_executor_class, mock_as_completed
  ):
    """Test run_methods_in_parallel when multiple methods raise exceptions."""
    # Arrange
    mock_executor = MagicMock()
    mock_executor_class.return_value.__enter__.return_value = mock_executor

    # Create mock methods
    method1 = MagicMock()
    method2 = MagicMock()
    method3 = MagicMock()
    methods = [method1, method2, method3]

    # Mock futures
    future1 = MagicMock()
    future2 = MagicMock()
    future3 = MagicMock()
    futures = [future1, future2, future3]

    mock_executor.submit.side_effect = futures
    mock_as_completed.return_value = futures

    # Mock multiple exceptions
    future1.result.side_effect = ValueError("Value error occurred")
    future2.result.return_value = None  # Success
    future3.result.side_effect = RuntimeError("Runtime error occurred")

    # Act
    utility.run_methods_in_parallel(methods)

    # Assert
    self.assertEqual(mock_executor.submit.call_count, 3)

    # Verify as_completed was called with the futures list
    mock_as_completed.assert_called_once_with(futures)

    # Verify all futures were waited for
    future1.result.assert_called_once()
    future2.result.assert_called_once()
    future3.result.assert_called_once()

    # Error logging should occur for both exceptions
    self.assertEqual(mock_cloud_logging.call_count, 2)
    mock_cloud_logging.assert_any_call(
        "Exception occurred while executing a method: Value error occurred",
        severity="ERROR",
    )
    mock_cloud_logging.assert_any_call(
        "Exception occurred while executing a method: Runtime error occurred",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.as_completed")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.ThreadPoolExecutor"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_run_methods_in_parallel_empty_list(
      self, mock_cloud_logging, mock_executor_class, mock_as_completed
  ):
    """Test run_methods_in_parallel with empty methods list."""
    # Arrange
    mock_executor = MagicMock()
    mock_executor_class.return_value.__enter__.return_value = mock_executor

    methods = []
    futures = []

    mock_as_completed.return_value = []

    # Act
    utility.run_methods_in_parallel(methods)

    # Assert
    mock_executor.submit.assert_not_called()
    mock_as_completed.assert_called_once_with(futures)
    mock_cloud_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.as_completed")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}utility.concurrent.futures.ThreadPoolExecutor"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_run_methods_in_parallel_single_method(
      self, mock_cloud_logging, mock_executor_class, mock_as_completed
  ):
    """Test run_methods_in_parallel with single method."""
    # Arrange
    mock_executor = MagicMock()
    mock_executor_class.return_value.__enter__.return_value = mock_executor

    method1 = MagicMock()
    methods = [method1]

    future1 = MagicMock()
    futures = [future1]
    mock_executor.submit.return_value = future1
    mock_as_completed.return_value = futures

    future1.result.return_value = "success"

    # Act
    utility.run_methods_in_parallel(methods)

    # Assert
    mock_executor.submit.assert_called_once_with(method1)
    mock_as_completed.assert_called_once_with(futures)
    future1.result.assert_called_once()
    mock_cloud_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime")
  def test_check_time_current_hr_current_hour(self, mock_datetime):
    """Test check_time_current_hr with time in current hour."""
    # Arrange
    current_time_str = "2023061514"  # 2023-06-15 14:xx:xx
    time_to_check = "2023061514"  # Same hour

    # Mock datetime.now to return a specific time
    mock_now = MagicMock()
    mock_now.strftime.return_value = current_time_str
    mock_datetime.now.return_value = mock_now

    # Mock datetime.strptime for both calls
    mock_current_dt = MagicMock()
    mock_check_dt = MagicMock()
    mock_datetime.strptime.side_effect = [mock_current_dt, mock_check_dt]

    # Mock comparison - time_to_check >= current_time
    mock_check_dt.__ge__.return_value = True

    # Act
    result = utility.check_time_current_hr(time_to_check)

    # Assert
    self.assertTrue(result)
    mock_datetime.now.assert_called_once_with(timezone.utc)
    mock_now.strftime.assert_called_once_with("%Y%m%d%H")

    # Verify strptime calls
    expected_calls = [
        mock.call(current_time_str, "%Y%m%d%H"),
        mock.call(time_to_check, "%Y%m%d%H"),
    ]
    mock_datetime.strptime.assert_has_calls(expected_calls)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime")
  def test_check_time_current_hr_past_hour(self, mock_datetime):
    """Test check_time_current_hr with time in past hour."""
    # Arrange
    current_time_str = "2023061514"  # 2023-06-15 14:xx:xx
    time_to_check = "2023061513"  # Previous hour

    # Mock datetime.now to return a specific time
    mock_now = MagicMock()
    mock_now.strftime.return_value = current_time_str
    mock_datetime.now.return_value = mock_now

    # Mock datetime.strptime for both calls
    mock_current_dt = MagicMock()
    mock_check_dt = MagicMock()
    mock_datetime.strptime.side_effect = [mock_current_dt, mock_check_dt]

    # Mock comparison - time_to_check < current_time
    mock_check_dt.__ge__.return_value = False

    # Act
    result = utility.check_time_current_hr(time_to_check)

    # Assert
    self.assertFalse(result)
    mock_datetime.now.assert_called_once_with(timezone.utc)
    mock_now.strftime.assert_called_once_with("%Y%m%d%H")

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime")
  def test_check_time_current_hr_future_hour(self, mock_datetime):
    """Test check_time_current_hr with time in future hour."""
    # Arrange
    current_time_str = "2023061514"  # 2023-06-15 14:xx:xx
    time_to_check = "2023061515"  # Next hour

    # Mock datetime.now to return a specific time
    mock_now = MagicMock()
    mock_now.strftime.return_value = current_time_str
    mock_datetime.now.return_value = mock_now

    # Mock datetime.strptime for both calls
    mock_current_dt = MagicMock()
    mock_check_dt = MagicMock()
    mock_datetime.strptime.side_effect = [mock_current_dt, mock_check_dt]

    # Mock comparison - time_to_check > current_time
    mock_check_dt.__ge__.return_value = True

    # Act
    result = utility.check_time_current_hr(time_to_check)

    # Assert
    self.assertTrue(result)

  def test_check_time_current_hr_real_time_scenarios(self):
    """Test check_time_current_hr with real datetime scenarios."""
    # Test cases with actual datetime objects (no mocking)
    test_cases = [
        {
            "description": "Same hour",
            "current_hour": "2023061514",
            "check_hour": "2023061514",
            "expected": True,
        },
        {
            "description": "Past hour",
            "current_hour": "2023061514",
            "check_hour": "2023061513",
            "expected": False,
        },
        {
            "description": "Future hour",
            "current_hour": "2023061514",
            "check_hour": "2023061515",
            "expected": True,
        },
        {
            "description": "Different day - past",
            "current_hour": "2023061514",
            "check_hour": "2023061414",
            "expected": False,
        },
        {
            "description": "Different day - future",
            "current_hour": "2023061514",
            "check_hour": "2023061614",
            "expected": True,
        },
    ]

    for test_case in test_cases:
      with self.subTest(description=test_case["description"]):
        with patch(
            f"{INGESTION_SCRIPTS_PATH}utility.datetime"
        ) as mock_datetime:
          # Mock datetime.now to return specific current time
          mock_now = MagicMock()
          mock_now.strftime.return_value = test_case["current_hour"]
          mock_datetime.now.return_value = mock_now

          # Use real datetime.strptime for accurate parsing
          mock_datetime.strptime.side_effect = datetime.strptime

          # Act
          result = utility.check_time_current_hr(test_case["check_hour"])

          # Assert
          self.assertEqual(result, test_case["expected"])

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime")
  def test_check_time_current_hr_edge_cases(self, mock_datetime):
    """Test check_time_current_hr with edge cases."""
    # Test end of day transition
    current_time_str = "2023061523"  # 2023-06-15 23:xx:xx
    time_to_check = "2023061600"  # Next day 00:xx:xx

    # Mock datetime.now to return a specific time
    mock_now = MagicMock()
    mock_now.strftime.return_value = current_time_str
    mock_datetime.now.return_value = mock_now

    # Mock datetime.strptime for both calls
    mock_current_dt = MagicMock()
    mock_check_dt = MagicMock()
    mock_datetime.strptime.side_effect = [mock_current_dt, mock_check_dt]

    # Mock comparison - next day is future
    mock_check_dt.__ge__.return_value = True

    # Act
    result = utility.check_time_current_hr(time_to_check)

    # Assert
    self.assertTrue(result)

    # Verify correct format strings used
    mock_datetime.strptime.assert_any_call(current_time_str, "%Y%m%d%H")
    mock_datetime.strptime.assert_any_call(time_to_check, "%Y%m%d%H")

  def test_add_one_hour_to_formatted_time_normal_hour(self):
    """Test add_one_hour_to_formatted_time with normal hour increment."""
    # Arrange
    input_time = "2024031514"  # March 15, 2024, 14:00
    expected_output = "2024031515"  # March 15, 2024, 15:00

    # Act
    result = utility.add_one_hour_to_formatted_time(input_time)

    # Assert
    self.assertEqual(result, expected_output)

  def test_add_one_hour_to_formatted_time_end_of_day(self):
    """Test add_one_hour_to_formatted_time when hour rolls over to next day."""
    # Arrange
    input_time = "2024031523"  # March 15, 2024, 23:00
    expected_output = "2024031600"  # March 16, 2024, 00:00

    # Act
    result = utility.add_one_hour_to_formatted_time(input_time)

    # Assert
    self.assertEqual(result, expected_output)

  def test_add_one_hour_to_formatted_time_end_of_month(self):
    """Test add_one_hour_to_formatted_time when hour rolls over to next month."""
    # Arrange
    input_time = "2024033123"  # March 31, 2024, 23:00
    expected_output = "2024040100"  # April 1, 2024, 00:00

    # Act
    result = utility.add_one_hour_to_formatted_time(input_time)

    # Assert
    self.assertEqual(result, expected_output)

  def test_add_one_hour_to_formatted_time_end_of_year(self):
    """Test add_one_hour_to_formatted_time when hour rolls over to next year."""
    # Arrange
    input_time = "2024123123"  # December 31, 2024, 23:00
    expected_output = "2025010100"  # January 1, 2025, 00:00

    # Act
    result = utility.add_one_hour_to_formatted_time(input_time)

    # Assert
    self.assertEqual(result, expected_output)

  def test_add_one_hour_to_formatted_time_leap_year(self):
    """Test add_one_hour_to_formatted_time with leap year February 29."""
    # Arrange
    input_time = "2024022923"  # February 29, 2024, 23:00 (leap year)
    expected_output = "2024030100"  # March 1, 2024, 00:00

    # Act
    result = utility.add_one_hour_to_formatted_time(input_time)

    # Assert
    self.assertEqual(result, expected_output)

  def test_add_one_hour_to_formatted_time_midnight(self):
    """Test add_one_hour_to_formatted_time starting from midnight."""
    # Arrange
    input_time = "2024031500"  # March 15, 2024, 00:00
    expected_output = "2024031501"  # March 15, 2024, 01:00

    # Act
    result = utility.add_one_hour_to_formatted_time(input_time)

    # Assert
    self.assertEqual(result, expected_output)

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_threat_lists_start_time_with_valid_env_var(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test get_threat_lists_start_time with valid environment variable."""
    # Arrange
    test_start_time = "2024031514"  # March 15, 2024, 14:00
    mock_get_env_var.return_value = test_start_time

    with patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime") as mock_datetime:
      # Mock current time to be within allowed range
      mock_now = datetime(2024, 3, 16, 10, 0, 0, tzinfo=timezone.utc)
      mock_datetime.now.return_value = mock_now
      mock_datetime.strptime = datetime.strptime

      # Act
      result = utility.get_threat_lists_start_time()

      # Assert
      self.assertEqual(result, test_start_time)
      mock_get_env_var.assert_called_once_with(
          constant.ENV_VAR_THREAT_LISTS_START_TIME
      )
      mock_cloud_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_threat_lists_start_time_with_old_env_var(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test get_threat_lists_start_time with environment variable older than max days."""
    # Arrange
    test_start_time = (  # January 15, 2024, 14:00 (more than 30 days ago)
        "2024011514"
    )
    mock_get_env_var.return_value = test_start_time

    with patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime") as mock_datetime:
      # Mock current time to be more than 30 days after start time
      mock_now = datetime(2024, 3, 16, 10, 0, 0, tzinfo=timezone.utc)
      mock_datetime.now.return_value = mock_now
      mock_datetime.strptime = datetime.strptime

      # Act & Assert
      with self.assertRaises(Exception) as context:
        utility.get_threat_lists_start_time()

      self.assertIn(
          "Threat lists start time should be less than 7 days ago",
          str(context.exception),
      )
      mock_cloud_logging.assert_called_once()
      self.assertIn(
          "Error occurred while validating threat lists start time",
          mock_cloud_logging.call_args[0][0],
      )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_threat_lists_start_time_with_invalid_format(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test get_threat_lists_start_time with invalid time format."""
    # Arrange
    test_start_time = "invalid_format"
    mock_get_env_var.return_value = test_start_time

    # Act & Assert
    with self.assertRaises(Exception):
      utility.get_threat_lists_start_time()

    mock_cloud_logging.assert_called_once()
    self.assertIn(
        "Error occurred while validating threat lists start time",
        mock_cloud_logging.call_args[0][0],
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_threat_lists_start_time_no_env_var(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test get_threat_lists_start_time when environment variable is not set."""
    # Arrange
    mock_get_env_var.return_value = None

    with patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime") as mock_datetime:
      # Mock current time
      mock_now = datetime(2024, 3, 16, 10, 0, 0, tzinfo=timezone.utc)
      mock_datetime.now.return_value = mock_now
      mock_datetime.strftime = datetime.strftime

      # Expected start time (1 day ago from current time)
      expected_start_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
      expected_result = expected_start_time.strftime("%Y%m%d%H")

      # Act
      result = utility.get_threat_lists_start_time()

      # Assert
      self.assertEqual(result, expected_result)
      mock_get_env_var.assert_called_once_with(
          constant.ENV_VAR_THREAT_LISTS_START_TIME
      )
      mock_cloud_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_threat_lists_start_time_empty_env_var(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test get_threat_lists_start_time when environment variable is empty string."""
    # Arrange
    mock_get_env_var.return_value = ""

    with patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime") as mock_datetime:
      # Mock current time
      mock_now = datetime(2024, 3, 16, 10, 0, 0, tzinfo=timezone.utc)
      mock_datetime.now.return_value = mock_now
      mock_datetime.strftime = datetime.strftime

      # Expected start time (1 day ago from current time)
      expected_start_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
      expected_result = expected_start_time.strftime("%Y%m%d%H")

      # Act
      result = utility.get_threat_lists_start_time()

      # Assert
      self.assertEqual(result, expected_result)
      mock_get_env_var.assert_called_once_with(
          constant.ENV_VAR_THREAT_LISTS_START_TIME
      )
      mock_cloud_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_threat_lists_start_time_exactly_max_days(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test get_threat_lists_start_time with start time exactly at max days limit."""
    # Arrange
    test_start_time = "2024031010"  # March 10, 2024, 10:00
    mock_get_env_var.return_value = test_start_time

    with patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime") as mock_datetime:
      # Mock current time to be exactly 7 days after start time
      mock_now = datetime(2024, 3, 17, 10, 0, 0, tzinfo=timezone.utc)
      mock_datetime.now.return_value = mock_now
      mock_datetime.strptime = datetime.strptime

      # Act
      result = utility.get_threat_lists_start_time()

      # Assert
      self.assertEqual(result, test_start_time)
      mock_get_env_var.assert_called_once_with(
          constant.ENV_VAR_THREAT_LISTS_START_TIME
      )
      mock_cloud_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}utility.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}utility.utils.cloud_logging")
  def test_get_threat_lists_start_time_one_day_over_max(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test get_threat_lists_start_time with start time one day over max days limit."""
    # Arrange
    test_start_time = "2024030910"  # March 9, 2024, 10:00
    mock_get_env_var.return_value = test_start_time

    with patch(f"{INGESTION_SCRIPTS_PATH}utility.datetime") as mock_datetime:
      # Mock current time to be 8 days after start time (1 day over limit)
      mock_now = datetime(2024, 3, 17, 10, 0, 0, tzinfo=timezone.utc)
      mock_datetime.now.return_value = mock_now
      mock_datetime.strptime = datetime.strptime

      # Act & Assert
      with self.assertRaises(Exception) as context:
        utility.get_threat_lists_start_time()

      self.assertIn(
          "Threat lists start time should be less than 7 days ago",
          str(context.exception),
      )
      mock_cloud_logging.assert_called_once()
