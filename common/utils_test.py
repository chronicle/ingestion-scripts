# Copyright 2023 Google LLC
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
"""Unit test file for utils.py file."""

import datetime
import unittest
from unittest import mock

from common import utils

# Path to common framework.
INGESTION_SCRIPTS_PATH = (
    "common"
)


class TestUtilsFromCommon(unittest.TestCase):
  """Unit test class for utils."""

  def test_get_env_var_runtime_error(self):
    """Test case to verify that the RuntimeError is raised when the name not found in the environment variable and is_required is set to True.

    Asserts:
      RuntimeError is thrown if the requirement environment variable doesn't
      exist.
    """
    self.assertRaises(RuntimeError, utils.get_env_var, "test", required=True)

  @mock.patch.dict("{}.utils.os.environ".format(INGESTION_SCRIPTS_PATH),
                   {"poll_interval": "10"})
  def test_get_env_var_success(self):
    """Test case to verify that the correct value is returned for the poll_interval if it exists in the environment variable.

    Asserts:
      get_env_var() returns the expected value of existing environment variable.
    """
    self.assertEqual(utils.get_env_var("poll_interval"), "10")

  def test_get_env_var_default_value(self):
    """Test case to verify that the defualt value is returned for the variable which does not exist in the environment variables.

    Asserts:
      get_env_var() returns the default value set for the optional environment
      variable if the variable is not found.
    """
    self.assertEqual(
        utils.get_env_var("poll_interval", required=False, default=10), 10)

  @mock.patch(
      "{}.utils.get_value_from_secret_manager".format(INGESTION_SCRIPTS_PATH))
  @mock.patch.dict("{}.utils.os.environ".format(INGESTION_SCRIPTS_PATH),
                   {"POLL_INTERVAL": "10"})
  def test_get_env_var_secret_value(self, mocked_get_value_from_secret_manager):
    """Test case to verify that the correct value is returned when is_secret is set to True.

    Args:
      mocked_get_value_from_secret_manager (mock.Mock): Mocked object of
      SecretManager() class.

    Asserts:
      get_env_var() method leverages the SecretManager() class to access the
      value of environment variable stored in the Google Secret Manager.
    """
    mocked_get_value_from_secret_manager.return_value = "10"
    self.assertEqual(
        utils.get_env_var("POLL_INTERVAL", is_secret=True), "10")

  @mock.patch.dict("{}.utils.os.environ".format(INGESTION_SCRIPTS_PATH),
                   {"POLL_INTERVAL": "-10"})
  def test_get_last_run_at_invalid(self):
    """Test case to verify that the RuntimeError is raised when the poll_interval value is zero or negative.

    Asserts:
      get_env_var() method raises RuntimeError for negative values of
      POLL_INTERVAL environment variable.
    """
    self.assertRaises(RuntimeError, utils.get_last_run_at)

  @mock.patch("{}.utils.datetime".format(INGESTION_SCRIPTS_PATH))
  @mock.patch.dict("{}.utils.os.environ".format(INGESTION_SCRIPTS_PATH),
                   {"POLL_INTERVAL": "10"})
  def test_get_last_run_at_success(self, mocked_datetime):
    """Test case to verify that the get_last_run_at returns the valid datetime object.

    Args:
      mocked_datetime (mock.Mock): Mocked object of datetime module.

    Asserts:
      get_last_run_at() method returns a datetime object based on POLL_INTERVAL
      environment variable.
    """
    mocked_datetime.datetime.now.return_value = datetime.datetime(
        2022, 1, 1, 6, 30, 00)
    mocked_datetime.timedelta.return_value = datetime.timedelta(seconds=600)
    self.assertEqual(utils.get_last_run_at(),
                     datetime.datetime(2022, 1, 1, 6, 20, 00))

  @mock.patch("{}.utils.datetime".format(INGESTION_SCRIPTS_PATH))
  @mock.patch(
      "{}.utils.get_env_var".format(INGESTION_SCRIPTS_PATH), return_value=10)
  def test_get_last_run_at_for_get_env_var(self, mocked_get_env_var,
                                           mocked_datetime):
    """Test case to verify that the get_last_run_at calls the get_env_var with valid arguments.

    Args:
      mocked_get_env_var (int): Mocked return value of get_env_var()
      mocked_datetime (mock.Mock): Mocked object of datetime module.

    Asserts:
      get_last_run_at() method returns a datetime object based on POLL_INTERVAL
      environment variable.
      get_env_var() method is called with valid parameters.
    """
    mocked_datetime.datetime.now.return_value = datetime.datetime(
        2022, 1, 1, 6, 30, 00)
    mocked_datetime.timedelta.return_value = datetime.timedelta(seconds=600)
    self.assertEqual(utils.get_last_run_at(),
                     datetime.datetime(2022, 1, 1, 6, 20, 00))
    self.assertEqual(mocked_get_env_var.mock_calls[0],
                     mock.call("POLL_INTERVAL", required=False, default=5))
