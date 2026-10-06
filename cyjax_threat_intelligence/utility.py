# Copyright 2026 Google LLC
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
"""Utility functions for Cyjax ingestion scripts."""

import datetime
import json
import os
import time
from typing import Any, Optional, Union

from google.cloud import exceptions
from google.cloud import storage
import google.cloud.resourcemanager_v3
import requests

from common import env_constants
from common import utils
import constant as con
import exception_handler


def get_environment_variable(
    name: str, is_required=False, is_secret=False
) -> str:
  """Retrieve environment variable value."""
  default_value = con.DEFAULT_VALUES.get(name, "")
  if is_secret:
    if name not in os.environ:
      if is_required:
        raise RuntimeError(f"Environment variable {name} is required.")
      return default_value
    secret_path = os.environ[name]
    if "versions" not in secret_path:
      secret_path = f"{secret_path}/versions/latest"
    return utils.get_value_from_secret_manager(secret_path)
  env_value = utils.get_env_var(
      name, required=is_required, is_secret=is_secret, default=default_value
  ).strip()
  return env_value


def parse_boolean_env(value: str) -> bool:
  """Parse string to boolean."""
  return value.lower() == "true" if value else False


def validate_integer_env(
    value: Union[int, str, None],
    param_name: str,
    default_value: Optional[str] = None,
) -> Optional[int]:
  """Validate if the given value is an integer.

  Args:
      value: The value to be validated.
      param_name: The name of the parameter for error messages.
      default_value: The default value to use if `value` is
        None.

  Raises:
      ValueError: If `default_value` is provided and cannot be validated.
      exception_handler.CyjaxException: If the value is not a valid integer
          or does not meet the rules.

  Returns:
      Optional[int]: The validated integer value, or None if `value` is
          None and no `default_value` is provided.
  """
  if value is None:
    return (
        None
        if not default_value
        else validate_integer_env(default_value, param_name, None)
    )

  try:
    int_value = value if isinstance(value, int) else int(value)
  except (ValueError, TypeError, AttributeError) as exc:
    raise exception_handler.CyjaxException(
        f"{param_name} must be an integer."
    ) from exc

  if int_value <= 0:
    raise exception_handler.CyjaxException(
        f"{param_name} must be a positive integer (greater than zero)."
    )

  return int_value


def get_last_checkpoint(bucket_name: str, checkpoint_key: str) -> Optional[str]:
  """Retrieve the last checkpoint from bucket for the given checkpoint_key.

  Args:
      bucket_name: The name of the GCS bucket
      checkpoint_key: The API checkpoint_key to retrieve the last
        checkpoint.

  Returns:
      The last checkpoint for the given checkpoint_key, or None if no
      checkpoint exists.

  Raises:
      GCPPermissionDeniedError: If there are permission issues with the GCS
      bucket.
      RuntimeError: If the specified bucket doesn't exist.
      Exception: For other unexpected errors during the process.
  """
  try:
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(con.CHECKPOINT_FILE)

    if blob.exists():
      data = json.loads(
          blob.download_as_text(timeout=con.BLOB_DOWNLOAD_TIMEOUT)
      )
      value = data.get(checkpoint_key, None)
      utils.cloud_logging(
          "Retrieved checkpoint with "
          f"key '{checkpoint_key}' from file "
          f"'{con.CHECKPOINT_FILE}' Checkpoint Data "
          f"Retrieved : {json.dumps(data)}.",
          severity="DEBUG",
      )
      return value

    else:
      utils.cloud_logging(
          f"Checkpoint file '{con.CHECKPOINT_FILE}' in "
          f"'{bucket_name}' does not exist.",
          severity="DEBUG",
      )
      return None

  except json.JSONDecodeError:
    utils.cloud_logging(
        f"Failed to decode JSON content from '{con.CHECKPOINT_FILE}'.",
        severity="WARNING",
    )
    return None

  except exceptions.NotFound as error:
    raise RuntimeError(
        f"The specified bucket '{bucket_name}' does not exist."
    ) from error

  except exceptions.Forbidden as e:
    error_msg = (
        f"Permission denied while accessing GCS bucket '{bucket_name}'. "
    )
    utils.cloud_logging(
        f"{error_msg}. Error: {e}",
        severity="ERROR",
    )
    raise exception_handler.GCPPermissionDeniedError(
        message=error_msg,
        resource=f"gs://{bucket_name}/{con.CHECKPOINT_FILE}",
        permissions=["Storage Admin"],
    ) from e

  except Exception as e:  # pylint: disable=broad-exception-caught
    utils.cloud_logging(
        "Unknown exception occurred while getting last checkpoint. Error"
        f" message: {e}.",
        severity="ERROR",
    )
    return None


def set_last_checkpoint(
    bucket_name: str,
    checkpoint_key: str,
    last_checkpoint: Any,
) -> None:
  """Store the last checkpoint for the given checkpoint_key in bucket.

  Args:
      bucket_name: The name of the GCS bucket
      checkpoint_key: The API checkpoint_key to set the last checkpoint.
      last_checkpoint: The last checkpoint to set.

  Raises:
      GCPPermissionDeniedError: If there are permission issues with
          the GCS bucket.
      RuntimeError: If the specified bucket doesn't exist.
      Exception: For other unexpected errors during the process.
  """
  try:
    custom_retry = storage.retry.DEFAULT_RETRY.with_delay(
        initial=con.RETRY_INITIAL_DELAY,
        maximum=con.RETRY_MAXIMUM_DELAY,
        multiplier=con.RETRY_MULTIPLIER,
    ).with_deadline(con.RETRY_DEADLINE)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(con.CHECKPOINT_FILE)

    bucket_data = {}
    if blob.exists():
      try:
        bucket_data = json.loads(
            blob.download_as_text(timeout=con.BLOB_DOWNLOAD_TIMEOUT)
        )
        utils.cloud_logging(
            f"Read existing checkpoint data from '{con.CHECKPOINT_FILE}'.",
            severity="DEBUG",
        )
      except json.JSONDecodeError:
        utils.cloud_logging(
            f"Failed to decode JSON content from '{con.CHECKPOINT_FILE}'.",
            severity="WARNING",
        )
    else:
      utils.cloud_logging(
          f"Checkpoint file '{con.CHECKPOINT_FILE}' does not "
          "exist, creating new file.",
          severity="DEBUG",
      )

    bucket_data[checkpoint_key] = last_checkpoint
    blob.upload_from_string(
        json.dumps(bucket_data),
        content_type="application/json",
        retry=custom_retry,
        timeout=con.BLOB_UPLOAD_TIMEOUT,
    )
    utils.cloud_logging(
        f"Updated Checkpoint File: '{con.CHECKPOINT_FILE}', "
        f"Key: '{checkpoint_key}' with the value: "
        f"{last_checkpoint} Updated Checkpoint Data : "
        f"{json.dumps(bucket_data)}.",
        severity="DEBUG",
    )

    return None

  except exceptions.Forbidden as e:
    error_msg = (
        f"Permission denied while accessing GCS bucket '{bucket_name}'. "
    )
    utils.cloud_logging(
        f"{error_msg}. Error: {repr(e)}",
        severity="ERROR",
    )
    raise exception_handler.GCPPermissionDeniedError(
        message=error_msg,
        resource=f"gs://{bucket_name}/{con.CHECKPOINT_FILE}",
        permissions=["Storage Admin"],
    ) from e

  except exceptions.NotFound as e:
    error_msg = f"The specified bucket '{bucket_name}' does not exist."
    utils.cloud_logging(error_msg, severity="ERROR")
    raise RuntimeError(error_msg) from e

  except Exception as e:
    utils.cloud_logging(
        f"Error updating checkpoint '{checkpoint_key}' in"
        f" '{con.CHECKPOINT_FILE}': {repr(e)}.",
        severity="ERROR",
    )
    raise


def check_sufficient_permissions_on_service_account():
  """Check if the service account has sufficient permissions.

  This method checks if the service account has sufficient permissions to
  perform necessary operations. It retrieves the IAM policy for the project
  and checks if the service account has the necessary permissions. If not,
  it raises an exception.

  Returns:
    bool: True if the service account has sufficient permissions.

  Raises:
    RuntimeError: If the service account does not have sufficient
    permissions.
  """
  missing_permissions = set()
  service_account = utils.get_env_var(
      env_constants.ENV_CHRONICLE_SERVICE_ACCOUNT, required=False
  )
  if not service_account:
    try:
      client = google.cloud.resourcemanager_v3.ProjectsClient()
      chronicle_project_number = get_environment_variable(
          env_constants.ENV_CHRONICLE_PROJECT_NUMBER
      )
      resource_name = f"projects/{chronicle_project_number}"
      policy = client.get_iam_policy(request={"resource": resource_name})
      service_account_email = requests.get(
          "http://metadata.google.internal/computeMetadata/v1/"
          "instance/service-accounts/default/email",
          headers={"Metadata-Flavor": "Google"},
          timeout=(con.CONNECTION_TIMEOUT, con.READ_TIMEOUT),
      ).text
    except Exception as e:
      utils.cloud_logging(f"Unexpected error: {repr(e)}.")
      raise RuntimeError(
          "An unexpected error occurred during service account permission check"
      ) from e
    service_account_member = f"serviceAccount:{service_account_email}"
    # Check if the service account is roles/owner with all permissions.
    is_owner = any(
        service_account_member in binding.members
        for binding in policy.bindings
        if binding.role == "roles/owner"
    )
    if is_owner:
      utils.cloud_logging(
          "Service account has roles/owner, "
          "which includes all necessary permissions."
      )
      return True
    for permission_name, role in con.PERMISSION_DETAILS.items():
      if not any(
          service_account_member in binding.members
          for binding in policy.bindings
          if binding.role == role
      ):
        missing_permissions.add(permission_name)

    if missing_permissions:
      error_msg = (
          f"Service account - {service_account_email} does not have"
          " sufficient permissions."
      )
      utils.cloud_logging(
          f"Service account - {service_account_email} "
          "does not have sufficient permissions.",
          severity="ERROR",
      )
      raise exception_handler.GCPPermissionDeniedError(
          message=error_msg,
          resource=resource_name,
          permissions=list(missing_permissions),
      )
    else:
      utils.cloud_logging("Service account has sufficient permissions.")
      return True
  else:
    utils.cloud_logging(
        "Permission check skipped as static service account key is"
        f" provided. {service_account}."
    )
    return True


def acquire_process_lock(bucket_name: str) -> bool:
  """Attempt to acquire process lock to prevent overlapping executions.

  Args:
      bucket_name: The name of the GCS bucket

  Returns:
      bool: True if lock acquired successfully, False if another
      process is running

  Raises:
      Exception: If unable to check or set lock due to GCS errors
  """
  try:
    existing_lock = get_last_checkpoint(
        bucket_name, con.CHECKPOINT_KEY_PROCESS_LOCK
    )
    current_time = time.time()

    if existing_lock != "true":
      set_last_checkpoint(
          bucket_name,
          con.CHECKPOINT_KEY_PROCESS_LOCK,
          "true",
      )
      set_last_checkpoint(
          bucket_name,
          con.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
          current_time,
      )
      utils.cloud_logging(
          "Process lock acquired successfully. Setting lock status to true "
          f"and last_run_initiation_time to {current_time}.",
          severity="INFO",
      )
      return True

    last_run_initiation_time = get_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
    )

    if not last_run_initiation_time:
      utils.cloud_logging(
          "Another process is already running. Lock status: true. "
          "Skipping execution to prevent overlapping runs.",
          severity="WARNING",
      )
      return False

    try:
      last_run_time = float(last_run_initiation_time)
      time_diff_minutes = (current_time - last_run_time) / 60
    except (ValueError, TypeError) as e:
      utils.cloud_logging(
          "Invalid last_run_initiation_time value: "
          f"{last_run_initiation_time}. "
          f"Error: {repr(e)}. Treating as if lock is stuck.",
          severity="WARNING",
      )
      return False

    if time_diff_minutes < con.MAX_EXECUTION_TIME_MINUTES:
      utils.cloud_logging(
          "Another process is already running "
          f"(started {time_diff_minutes:.2f} minutes ago). "
          "Lock status: true. Skipping execution to prevent "
          "overlapping runs.",
          severity="WARNING",
      )
      return False

    utils.cloud_logging(
        "Lock is running but last run time was "
        f"{time_diff_minutes:.2f} minutes ago, "
        "which exceeds the limit of "
        f"{con.MAX_EXECUTION_TIME_MINUTES} "
        "minutes. Resetting lock and "
        "last_run_initiation_time.",
        severity="WARNING",
    )
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_PROCESS_LOCK,
        "true",
    )
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
        current_time,
    )
    utils.cloud_logging(
        "Process lock acquired successfully after timeout reset.",
        severity="INFO",
    )
    return True

  except Exception as e:
    utils.cloud_logging(
        f"Failed to acquire process lock: {repr(e)}.",
        severity="ERROR",
    )
    raise


def release_process_lock(bucket_name: str) -> None:
  """Release process lock to allow future executions.

  Args:
      bucket_name: The name of the GCS bucket
  """
  try:
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_PROCESS_LOCK,
        "false",
    )
    utils.cloud_logging(
        "Process lock released successfully. Setting lock status to false.",
        severity="INFO",
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    utils.cloud_logging(
        f"Failed to release process lock: {repr(e)}. "
        "This may prevent future executions until manually "
        "cleared.",
        severity="ERROR",
    )


def get_checkpoints_and_config(
    bucket_name: str,
    historical_ioc_duration: int,
    query: Optional[str],
    indicator_type: Optional[str],
) -> tuple:  # pylint: disable=g-bare-generic
  """Load checkpoints and calculate since/until timestamps with validation.

  Args:
      bucket_name: The name of the GCS bucket
      historical_ioc_duration: Days of historical data to fetch
      query: Filter query for indicators
      indicator_type: Indicator type filter

  Returns:
      A tuple (since, until, starting_page, params_config), where since is the
      start timestamp for the query window, until is the end timestamp for the
      query window, starting_page is the page number to start from, and
      params_config is a dictionary containing query and type parameters.

  """
  last_since = get_last_checkpoint(
      bucket_name,
      con.CHECKPOINT_KEY_SINCE,
  )
  last_until = get_last_checkpoint(
      bucket_name,
      con.CHECKPOINT_KEY_UNTIL,
  )
  last_page_number = get_last_checkpoint(
      bucket_name,
      con.CHECKPOINT_KEY_PAGE_NUMBER,
  )
  last_query = get_last_checkpoint(
      bucket_name,
      con.CHECKPOINT_KEY_QUERY,
  )
  last_indicator_types = get_last_checkpoint(
      bucket_name,
      con.CHECKPOINT_KEY_INDICATOR_TYPES,
  )

  current_time = datetime.datetime.now(datetime.timezone.utc)

  params_config = {
      "query": query,
      "type": indicator_type,
  }

  # Check if configuration parameters have changed
  config_changed = last_query != query or last_indicator_types != indicator_type

  # If any configuration changed and there are incomplete pages, discard them
  if config_changed and last_page_number and int(last_page_number) > 0:
    utils.cloud_logging(
        "Configuration parameters changed. Discarding "
        "incomplete page numbers and starting new window.",
        severity="INFO",
    )
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_PAGE_NUMBER,
        0,
    )
    last_page_number = 0

  # Resume incomplete window if page_number > 0
  if last_page_number and int(last_page_number) > 0:
    since = last_since
    until = last_until
    starting_page = int(last_page_number)
    utils.cloud_logging(
        f"Resuming incomplete window from page {starting_page}. "
        f"Since: {since}, Until: {until}",
        severity="INFO",
    )
  else:
    # Create new window (page_number == 0)
    # If config changed, continue from last_since to avoid missing data
    if config_changed and last_since:
      utils.cloud_logging(
          "Configuration parameters changed. "
          "Continuing from last since timestamp to avoid data loss.",
          severity="INFO",
      )
      since_dt = datetime.datetime.fromisoformat(
          last_since.replace("Z", "+00:00")
      )
    elif last_until:
      since_dt = datetime.datetime.fromisoformat(
          last_until.replace("Z", "+00:00")
      ) + datetime.timedelta(seconds=1)
    # First run - use configured HISTORICAL_IOC_DURATION
    else:
      utils.cloud_logging(
          "First run. Using HISTORICAL_IOC_DURATION of "
          f"{historical_ioc_duration} days.",
          severity="INFO",
      )
      since_dt = current_time - datetime.timedelta(days=historical_ioc_duration)

    until_dt = current_time
    since = since_dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    until = until_dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    starting_page = 1

    # Save all checkpoint values
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_SINCE,
        since,
    )
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_UNTIL,
        until,
    )
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_PAGE_NUMBER,
        1,
    )
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_QUERY,
        query,
    )
    set_last_checkpoint(
        bucket_name,
        con.CHECKPOINT_KEY_INDICATOR_TYPES,
        indicator_type,
    )

    utils.cloud_logging(
        f"Starting new window. Since: {since}, Until: {until}",
        severity="INFO",
    )

  return since, until, starting_page, params_config
