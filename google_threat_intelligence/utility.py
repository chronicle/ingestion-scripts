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
#
"""Utility functions for Google Threat Intelligence ingestion scripts."""

import concurrent.futures
from datetime import datetime, timedelta, timezone  # pylint: disable=g-importing-member, g-multiple-import
import os
from typing import Callable
from common import utils
import constant


def get_environment_variable(
    name: str, is_required=False, is_secret=False
) -> str:
  """Retrieve the value of the given environment variable.

  If is_secret is set to True, the value of the environment variable is not
  modified.
  Otherwise, the value is converted to lower case.

  Args:
      name (str): The name of the environment variable.
      is_required (bool, optional): If the environment variable is required and
        not set, it raises a RuntimeError. Defaults to False.
      is_secret (bool, optional): If the environment variable is a secret and
        should not be modified. Defaults to False.

  Returns:
      str: The value of the given environment variable or the default value if
      it is not set.

  Raises:
      RuntimeError: If `is_required` is True and the environment variable is not
        set.
  """
  default_value = constant.DEFAULT_VALUES.get(name, "")
  if is_secret:
    if name not in os.environ and is_required:
      raise RuntimeError(f"Environment variable {name} is required.")
    secret_path = os.environ[name]
    if "versions" not in secret_path:
      secret_path = secret_path + "/versions/latest"
    return utils.get_value_from_secret_manager(secret_path)
  env_value = utils.get_env_var(
      name, required=is_required, is_secret=is_secret, default=default_value
  ).strip()
  if not is_secret:
    env_value = env_value.lower()

  return env_value


def run_methods_in_parallel(methods: list[Callable[[], None]]):
  """Run the given methods in parallel."""
  with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = []
    for method in methods:
      futures.append(executor.submit(method))

    # Wait for all methods to complete
    for future in concurrent.futures.as_completed(futures):
      try:
        future.result()
      except Exception as e:  # pylint: disable=broad-except
        utils.cloud_logging(
            f"Exception occurred while executing a method: {e}",
            severity="ERROR",
        )


def check_time_current_hr(time_to_check):
  """Check if the given timestamp string is in the current hour.

  Args:
      time_to_check (str): Timestamp string in yyyymmddhh format.

  Returns:
      bool: True if the timestamp string is in the current hour, False
      otherwise.
  """
  # Current time in UTC, formatted to yyyymmddHH
  current_time_str = datetime.now(timezone.utc).strftime("%Y%m%d%H")

  # Convert both strings to datetime objects for accurate comparison
  current_time = datetime.strptime(current_time_str, "%Y%m%d%H")
  time_to_check_dt = datetime.strptime(time_to_check, "%Y%m%d%H")

  # Compare datetime objects
  return time_to_check_dt >= current_time


def add_one_hour_to_formatted_time(time_to_format):
  """Add 1 hour to a given timestamp string in yyyymmddhh format.

  Args:
      time_to_format (str): Timestamp string in yyyymmddhh format.

  Returns:
      str: Timestamp string with 1 hour added in yyyymmddhh format.
  """
  date_obj = datetime.strptime(time_to_format + "00", "%Y%m%d%H%M")

  # Add 1 hour
  date_obj_plus_one_hour = date_obj + timedelta(hours=1)

  # Format the datetime object back to the desired format (yyyymmddhh)
  updated_time = date_obj_plus_one_hour.strftime("%Y%m%d%H")

  return updated_time


def get_threat_lists_start_time():
  """Determine the start time for fetching threat list events.

  This function retrieves the start time from the environment variable specified
  by
  constant.ENV_VAR_THREAT_LISTS_START_TIME. If the variable is set, it validates
  that
  the time is less than MAX_DAYS_TO_FETCH_THREAT_LISTS days ago. If not set, it
  defaults
  to 1 day ago from the current UTC time.

  Returns:
      str: Start time in 'yyyymmddhh' format for fetching threat list events.

  Raises:
      Exception: If the provided start time is older than the allowed maximum
      days or
      cannot be parsed.
  """
  threat_lists_start_time = get_environment_variable(
      constant.ENV_VAR_THREAT_LISTS_START_TIME
  )

  if threat_lists_start_time:
    try:
      start_time = datetime.strptime(
          threat_lists_start_time, "%Y%m%d%H"
      ).replace(tzinfo=timezone.utc)
      if (
          datetime.now(timezone.utc) - start_time
      ).days > constant.MAX_DAYS_TO_FETCH_THREAT_LISTS:
        raise ValueError(
            "Threat lists start time should be less than"
            f" {constant.MAX_DAYS_TO_FETCH_THREAT_LISTS} days ago."
        )

    except Exception as e:
      utils.cloud_logging(
          "Error occurred while validating threat lists start time,"
          f" error: {e}",
          severity="ERROR",
      )
      raise
  else:
    start_time = datetime.now(timezone.utc) - timedelta(
        days=constant.DEFAULT_HISTORICAL_THREAT_LISTS_DAYS
    )
    threat_lists_start_time = start_time.strftime("%Y%m%d%H")

  return threat_lists_start_time


def convert_epoch_to_utc_string(epoch_seconds):
  """Convert epoch time to a UTC string with the pattern yyyy-MM-dd'T'HH:mm:ss".

  Args:
      epoch_seconds (int): Epoch time in seconds to convert to UTC string.

  Returns:
      str: UTC string with the pattern yyyy-MM-dd'T'HH:mm:ss".
  """
  return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).strftime(
      constant.IOC_STREAM_DATE_PATTERN
  )
