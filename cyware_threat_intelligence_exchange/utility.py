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

# pylint: disable=g-docstring-first-line-too-long

"""Utility functions for Cyware CTIX ingestion scripts."""

import json
import os
import re
import time
import traceback
from typing import Any, Optional, Union

from google.cloud import exceptions
from google.cloud import storage
import google.cloud.resourcemanager_v3
import requests

from common import env_constants
from common import utils
import constant
from exception_handler import CywareCTIXException
from exception_handler import GCPPermissionDeniedError


# Timeout constants (in seconds)
METADATA_REQUEST_TIMEOUT = 5


def get_environment_variable(
    name: str, *, is_required=False, is_secret=False
) -> str:
  """Retrieve environment variable value."""
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
  if name != constant.ENV_LABEL_NAME:
    env_value = env_value.lower()
  return env_value


def parse_boolean_env(value: str) -> bool:
  """Parse string to boolean."""
  return value.lower() == "true" if value else False


def validate_integer_env(
    value: Union[int, str, None],
    param_name: str,
    default_value: Optional[str] = None,
) -> Optional[int]:
  """Validate if the given value is an integer and meets the specified requirements.

  Args:
      value (int|str|None): The value to be validated.
      param_name (str): The name of the parameter for error messages.
      default_value (str, optional): The default value to use if `value` is
        None.

  Raises:
      ValueError: If `default_value` is provided and cannot be validated.
      CywareCTIXException: If the value is not a valid integer
          or does not meet the rules.

  Returns:
      Optional[int]: The validated integer value, or None if `value` is
          None and no `default_value` is provided.
  """
  is_empty = value is None
  if is_empty:
    return (
        None
        if not default_value
        else validate_integer_env(default_value, param_name, None)
    )

  try:
    int_value = value if isinstance(value, int) else int(value)
  except (ValueError, TypeError, AttributeError) as exc:
    utils.cloud_logging(
        f"Error validating {param_name}: {repr(exc)}\n"
        f"Traceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    raise CywareCTIXException(f"{param_name} must be an integer.") from exc

  if int_value < 0:
    raise CywareCTIXException(f"{param_name} must be a non-negative integer.")
  if int_value == 0:
    raise CywareCTIXException(f"{param_name} must be greater than zero.")

  return int_value


def get_tenant_checkpoint_key(tenant_name: str, checkpoint_key: str) -> str:
  """Generate tenant-specific checkpoint key for multi-tenant checkpoint file.

  Args:
      tenant_name: The tenant name
      checkpoint_key: The base checkpoint key (e.g., 'last_from_timestamp')

  Returns:
      str: Tenant-specific checkpoint key
          (e.g., 'tenant_a_last_from_timestamp')
  """
  safe_tenant_name = re.sub(r"[^a-zA-Z0-9_-]", "_", tenant_name)
  return f"{safe_tenant_name}_{checkpoint_key}"


def get_last_checkpoint(
    tenant_name: str, bucket_name: str, checkpoint_key: str
) -> Optional[str]:
  """Retrieve the last checkpoint from bucket for the given checkpoint_key.

  Args:
      tenant_name (str): The tenant name
      bucket_name (str): The name of the GCS bucket
      checkpoint_key (str): The API checkpoint_key to retrieve the last
        checkpoint.

  Returns:
      str: The last checkpoint for the given checkpoint_key, or None if no
      checkpoint exists.

  Raises:
      GCPPermissionDeniedError: If there are permission issues with the GCS
      bucket.
      RuntimeError: If the specified bucket doesn't exist.
      Exception: For other unexpected errors during the process.
  """
  try:
    tenant_checkpoint_key = get_tenant_checkpoint_key(
        tenant_name, checkpoint_key
    )
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(constant.CHECKPOINT_FILE)

    if blob.exists():
      data = json.loads(
          blob.download_as_text(timeout=constant.BLOB_DOWNLOAD_TIMEOUT)
      )
      value = data.get(tenant_checkpoint_key, None)
      utils.cloud_logging(
          f"Retrieved checkpoint for tenant '{tenant_name}' with "
          f"key '{tenant_checkpoint_key}' from file "
          f"'{constant.CHECKPOINT_FILE}' Checkpoint Data "
          f"Retrieved : {json.dumps(data)}",
          severity="DEBUG",
      )
      return value

    else:
      utils.cloud_logging(
          f"Checkpoint file '{constant.CHECKPOINT_FILE}' in "
          f"'{bucket_name}' does not exist.",
          severity="DEBUG",
      )
      return None

  except json.JSONDecodeError:
    utils.cloud_logging(
        f"Failed to decode JSON content from '{constant.CHECKPOINT_FILE}'\n"
        f"Traceback: {traceback.format_exc()}",
        severity="WARNING",
    )
    return None

  except exceptions.NotFound as error:
    utils.cloud_logging(
        f"Bucket not found: {bucket_name}\nTraceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    raise RuntimeError(
        f"The specified bucket '{bucket_name}' does not exist."
    ) from error

  except exceptions.Forbidden as e:
    error_msg = (
        f"Permission denied while accessing GCS bucket '{bucket_name}'. "
    )
    utils.cloud_logging(
        f"{error_msg}. Error: {e}\nTraceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    raise GCPPermissionDeniedError(
        message=error_msg,
        resource=f"gs://{bucket_name}/{constant.CHECKPOINT_FILE}",
        permissions=["Storage Admin"],
    ) from e

  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        "Unknown exception occurred while getting last checkpoint. Error"
        f" message: {e}\n"
        f"Traceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    return None


def set_last_checkpoint(
    tenant_name: str,
    bucket_name: str,
    checkpoint_key: str,
    last_checkpoint: Any,
) -> None:
  """Store the last checkpoint for the given checkpoint_key in bucket.

  Args:
      tenant_name (str): The tenant name
      bucket_name (str): The name of the GCS bucket
      checkpoint_key (str): The API checkpoint_key to set last checkpoint.
      last_checkpoint (Any): The last checkpoint to set.

  Raises:
      GCPPermissionDeniedError: If there are permission issues with
          the GCS bucket.
      RuntimeError: If the specified bucket doesn't exist.
      Exception: For other unexpected errors during the process.
  """
  try:
    tenant_checkpoint_key = get_tenant_checkpoint_key(
        tenant_name, checkpoint_key
    )
    custom_retry = storage.retry.DEFAULT_RETRY.with_delay(
        initial=1.0, maximum=30.0, multiplier=1.5
    ).with_deadline(120.0)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(constant.CHECKPOINT_FILE)

    bucket_data = {}
    if blob.exists():
      try:
        bucket_data = json.loads(
            blob.download_as_text(timeout=constant.BLOB_DOWNLOAD_TIMEOUT)
        )
        utils.cloud_logging(
            f"Read existing checkpoint data from '{constant.CHECKPOINT_FILE}'",
            severity="DEBUG",
        )
      except json.JSONDecodeError:
        utils.cloud_logging(
            "Failed to decode JSON content from "
            f"'{constant.CHECKPOINT_FILE}'\n"
            f"Traceback: {traceback.format_exc()}",
            severity="WARNING",
        )
    else:
      utils.cloud_logging(
          f"Checkpoint file '{constant.CHECKPOINT_FILE}' does not "
          "exist, creating new file",
          severity="DEBUG",
      )

    bucket_data[tenant_checkpoint_key] = last_checkpoint
    blob.upload_from_string(
        json.dumps(bucket_data),
        content_type="application/json",
        retry=custom_retry,
        timeout=30,
    )
    utils.cloud_logging(
        f"Updated Checkpoint File: '{constant.CHECKPOINT_FILE}', "
        f"Key: '{tenant_checkpoint_key}' with the value: "
        f"{last_checkpoint} Updated Checkpoint Data : "
        f"{json.dumps(bucket_data)}",
        severity="DEBUG",
    )

    return None

  except exceptions.Forbidden as e:
    error_msg = (
        f"Permission denied while accessing GCS bucket '{bucket_name}'. "
    )
    utils.cloud_logging(
        f"{error_msg}. Error: {repr(e)}\nTraceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    raise GCPPermissionDeniedError(
        message=error_msg,
        resource=f"gs://{bucket_name}/{constant.CHECKPOINT_FILE}",
        permissions=["Storage Admin"],
    ) from e

  except exceptions.NotFound as e:
    error_msg = f"The specified bucket '{bucket_name}' does not exist."
    utils.cloud_logging(
        f"{error_msg}\nTraceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    raise RuntimeError(error_msg) from e

  except Exception as e:
    utils.cloud_logging(
        f"Error updating checkpoint '{checkpoint_key}' in"
        f" '{constant.CHECKPOINT_FILE}': {repr(e)}\n"
        f"Traceback: {traceback.format_exc()}",
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
  if not service_account:  # If static service account key is not provided
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
          timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
      ).text
    except Exception as e:
      utils.cloud_logging(
          f"Unexpected error: {repr(e)}\nTraceback: {traceback.format_exc()}"
      )
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
    for permission_name, role in constant.PERMISSION_DETAILS.items():
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
          "Service account - %s does not have sufficient permissions.",
          service_account_email,
      )
      raise GCPPermissionDeniedError(
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
        f" provided. {service_account}"
    )
    return True


def acquire_process_lock(tenant_name: str, bucket_name: str) -> bool:
  """Attempt to acquire process lock to prevent overlapping executions.

  Args:
      tenant_name (str): The tenant name
      bucket_name (str): The name of the GCS bucket

  Returns:
      bool: True if lock acquired successfully, False if another
      process is running

  Raises:
      Exception: If unable to check or set lock due to GCS errors
  """
  try:
    existing_lock = get_last_checkpoint(
        tenant_name, bucket_name, constant.CHECKPOINT_KEY_PROCESS_LOCK
    )
    current_time = time.time()

    if existing_lock == "true":
      last_run_initiation_time = get_last_checkpoint(
          tenant_name,
          bucket_name,
          constant.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
      )

      if last_run_initiation_time:
        try:
          last_run_time = float(last_run_initiation_time)
          time_diff_minutes = (current_time - last_run_time) / 60

          if time_diff_minutes >= constant.MAX_EXECUTION_TIME_MINUTES:
            utils.cloud_logging(
                "Lock is running but last run time was "
                f"{time_diff_minutes:.2f} minutes ago, "
                "which exceeds the limit of "
                f"{constant.MAX_EXECUTION_TIME_MINUTES} "
                "minutes. Resetting lock and "
                "last_run_initiation_time.",
                severity="WARNING",
            )
            set_last_checkpoint(
                tenant_name,
                bucket_name,
                constant.CHECKPOINT_KEY_PROCESS_LOCK,
                "true",
            )
            set_last_checkpoint(
                tenant_name,
                bucket_name,
                constant.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
                current_time,
            )
            utils.cloud_logging(
                "Process lock acquired successfully after" + "timeout reset.",
                severity="INFO",
            )
            return True
          else:
            utils.cloud_logging(
                "Another process is already running"
                f"(started {time_diff_minutes:.2f} minutes ago). "
                "Lock status: true. Skipping execution to prevent"
                "overlapping runs.",
                severity="WARNING",
            )
            return False
        except (ValueError, TypeError) as e:
          utils.cloud_logging(
              "Invalid last_run_initiation_time value: "
              f"{last_run_initiation_time}. "
              f"Error: {repr(e)}. Treating as if lock is stuck.\n"
              f"Traceback: {traceback.format_exc()}",
              severity="WARNING",
          )
          return False
      else:
        utils.cloud_logging(
            "Another process is already running. Lock status: true. "
            "Skipping execution to prevent overlapping runs.",
            severity="WARNING",
        )
        return False

    set_last_checkpoint(
        tenant_name,
        bucket_name,
        constant.CHECKPOINT_KEY_PROCESS_LOCK,
        "true",
    )
    set_last_checkpoint(
        tenant_name,
        bucket_name,
        constant.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
        current_time,
    )
    utils.cloud_logging(
        "Process lock acquired successfully. Setting lock status to true"
        f"and last_run_initiation_time to {current_time}.",
        severity="INFO",
    )
    return True

  except Exception as e:
    utils.cloud_logging(
        f"Failed to acquire process lock: {repr(e)}\n"
        f"Traceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    raise


def release_process_lock(tenant_name: str, bucket_name: str) -> None:
  """Release process lock to allow future executions.

  Args:
      tenant_name (str): The tenant name
      bucket_name (str): The name of the GCS bucket
  """
  try:
    set_last_checkpoint(
        tenant_name,
        bucket_name,
        constant.CHECKPOINT_KEY_PROCESS_LOCK,
        "false",
    )
    utils.cloud_logging(
        "Process lock released successfully. Setting lock status to false.",
        severity="INFO",
    )
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        f"Failed to release process lock: {repr(e)}. "
        "This may prevent future executions until manually "
        "cleared.\n"
        f"Traceback: {traceback.format_exc()}",
        severity="ERROR",
    )


def clear_checkpoint_if_exists(
    checkpoint_key: str,
    checkpoint_name: str,
    tenant_name: str,
    bucket_name: str,
) -> None:
  """Clear a checkpoint if it exists.

  Args:
      checkpoint_key: Constant key for the checkpoint
      checkpoint_name: Human-readable name for logging
      tenant_name: The tenant name
      bucket_name: The name of the GCS bucket
  """
  existing_value = get_last_checkpoint(
      tenant_name,
      bucket_name,
      checkpoint_key,
  )
  if existing_value:
    set_last_checkpoint(
        tenant_name,
        bucket_name,
        checkpoint_key,
        None,
    )
    utils.cloud_logging(f"Removed {checkpoint_name} checkpoint.")
