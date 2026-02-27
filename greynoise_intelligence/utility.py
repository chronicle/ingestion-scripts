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
"""Utility functions for GreyNoise ingestion scripts."""

import json
import os
from typing import Any

import google.cloud.exceptions
import google.cloud.resourcemanager_v3
import google.cloud.storage
import requests

from common import env_constants
from common import utils
import constant
import exception_handler

GCPPermissionDeniedError = exception_handler.GCPPermissionDeniedError
# Timeout constants (in seconds)
GCS_BLOB_EXISTS_TIMEOUT = 30
GCS_DOWNLOAD_TIMEOUT = 60
GCS_UPLOAD_TIMEOUT = 60
METADATA_REQUEST_TIMEOUT = 5


def get_environment_variable(
    name: str, is_required: bool = False, is_secret: bool = False
) -> str:
  """Retrieve the value of the given environment variable.

  If is_secret is set to True, the value of the environment variable is not
  modified.
  Otherwise, the value is converted to lower case.

  Args:
      name: The name of the environment variable.
      is_required: If the environment variable is required and
        not set, it raises a RuntimeError. Defaults to False.
      is_secret: If the environment variable is a secret and
        should not be modified. Defaults to False.

  Returns:
      The value of the given environment variable or the default
          value if it is not set.

  Raises:
      RuntimeError: If `is_required` is True and the environment variable is
          not set.
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


def _get_gcs_client() -> google.cloud.storage.Client:
  """Initialize and return a GCS client with error handling.

  Returns:
      Initialized GCS client

  Raises:
      GCPPermissionDeniedError: If there are authentication/authorization
          issues
      Exception: For other unexpected errors during client initialization
  """
  try:
    return google.cloud.storage.Client()
  except Exception as e:
    error_msg = f"Failed to initialize GCS client: {str(e)}"
    if "403" in str(e) or "permission" in str(e).lower():
      raise GCPPermissionDeniedError(error_msg) from e
    utils.cloud_logging(error_msg, severity="ERROR")
    raise Exception(  # pylint: disable=broad-exception-raised
        error_msg
    ) from e


def load_state_from_gcs(object_name: str) -> dict[str, Any] | None:
  """Load state from a GCS bucket.

  Args:
      object_name: Name of the object to load from the bucket

  Returns:
      Parsed JSON content if object exists and is valid, None
          if object doesn't exist

  Raises:
      GCPPermissionDeniedError: For authentication/authorization issues
      json.JSONDecodeError: If the file contains invalid JSON
      Exception: For other unexpected errors during the operation
  """
  bucket_name = None
  error_msg = ""  # pylint: disable=unused-variable
  try:
    utils.cloud_logging(
        f"Loading state from GCS Bucket: {object_name}", severity="DEBUG"
    )
    bucket_name = utils.get_env_var(env_constants.ENV_GCP_BUCKET_NAME)
    client = _get_gcs_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(object_name)

    # Check if blob exists with timeout
    try:
      if not blob.exists(timeout=GCS_BLOB_EXISTS_TIMEOUT):
        utils.cloud_logging(
            f"State file {object_name} does not exist in bucket {bucket_name}"
        )
        return None
    except Exception as e:
      error_msg = (
          f"Failed to check if blob {object_name} exists: {str(e)}"
      )
      utils.cloud_logging(error_msg, severity="ERROR")
      raise Exception(error_msg) from e  # pylint: disable=broad-exception-raised

    # Download content with timeout
    try:
      data = blob.download_as_text(timeout=GCS_DOWNLOAD_TIMEOUT)
      if not data:
        utils.cloud_logging(
            f"Empty content in state file {object_name}",
            severity="WARNING",
        )
        return None

      utils.cloud_logging(
          f"Successfully read state file: {object_name}", severity="DEBUG"
      )
      return json.loads(data)

    except json.JSONDecodeError as e:
      error_msg = f"Failed to parse JSON from {object_name}: {str(e)}"
      utils.cloud_logging(error_msg, severity="ERROR")
      raise json.JSONDecodeError(
          f"Invalid JSON in {object_name}", e.doc, e.pos
      ) from e
  except google.cloud.exceptions.Forbidden as e:
    error_msg = (
        f"Permission denied while accessing GCS bucket '{bucket_name}'. "
    )
    utils.cloud_logging(
        f"{error_msg}. Error: {e}",
        severity="ERROR",
    )
    raise GCPPermissionDeniedError(
        message=error_msg,
        resource=f"gs://{bucket_name}/{object_name}",
        permissions=["Storage Admin"],
    ) from e
  except google.cloud.exceptions.NotFound as e:
    error_msg = f"The specified bucket '{bucket_name}' does not exist."
    utils.cloud_logging(error_msg, severity="ERROR")
    raise RuntimeError(error_msg) from e
  except GCPPermissionDeniedError:
    raise
  except Exception as e:
    error_msg = f"Failed to load state from GCS: {str(e)}"
    utils.cloud_logging(error_msg, severity="ERROR")
    raise Exception(  # pylint: disable=broad-exception-raised
        error_msg
    ) from e


def save_state_to_gcs(object_name: str, state: dict[str, Any]) -> None:
  """Save state to a GCS bucket.

  Args:
      object_name: Name of the object to save to in the bucket
      state: Dictionary containing the state to be saved

  Raises:
      GCPPermissionDeniedError: For authentication/authorization issues
      Exception: For other unexpected errors during the operation
  """
  bucket_name = None
  error_msg = ""  # pylint: disable=unused-variable
  try:
    bucket_name = utils.get_env_var(env_constants.ENV_GCP_BUCKET_NAME)
    client = _get_gcs_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(object_name)

    try:
      json_data = json.dumps(state)
    except (TypeError, ValueError) as e:
      error_msg = f"Failed to serialize state to JSON: {str(e)}"
      utils.cloud_logging(error_msg, severity="ERROR")
      raise ValueError(error_msg) from e

    # Upload with timeout and retry configuration
    try:
      blob.upload_from_string(
          json_data,
          content_type="application/json",
          timeout=GCS_UPLOAD_TIMEOUT,
      )
      utils.cloud_logging(f"Successfully saved state to {object_name}")

    except Exception as e:

      error_msg = f"Failed to save state to {object_name}: {str(e)}"

      utils.cloud_logging(error_msg, severity="ERROR")
      raise Exception(  # pylint: disable=broad-exception-raised
          error_msg
      ) from e

  except google.cloud.exceptions.Forbidden as e:
    error_msg = (
        f"Permission denied while accessing GCS bucket '{bucket_name}'. "
    )
    utils.cloud_logging(
        f"{error_msg}. Error: {e}",
        severity="ERROR",
    )
    raise GCPPermissionDeniedError(
        message=error_msg,
        resource=f"gs://{bucket_name}/{object_name}",
        permissions=["Storage Admin"],
    ) from e
  except google.cloud.exceptions.NotFound as e:
    error_msg = f"The specified bucket '{bucket_name}' does not exist."
    utils.cloud_logging(error_msg, severity="ERROR")
    raise RuntimeError(error_msg) from e
  except GCPPermissionDeniedError:
    raise
  except Exception as e:
    error_msg = f"Unexpected error while saving state to GCS: {str(e)}"
    utils.cloud_logging(error_msg, severity="ERROR")
    raise Exception(  # pylint: disable=broad-exception-raised
        error_msg
    ) from e


def check_sufficient_permissions_on_service_account():
  """Check if the service account has sufficient permissions.

  This method checks if the service account has sufficient permissions to
  perform necessary operations. It retrieves the IAM policy for the project
  and checks if the service account has the necessary permissions. If not,
  it raises an exception.

  Returns:
      True if the service account has sufficient permissions

  Raises:
      RuntimeError: If the service account does not have sufficient
          permissions.
      Exception: For other unexpected errors during the operation
  """
  missing_permissions = set()
  try:
    client = google.cloud.resourcemanager_v3.ProjectsClient()
    chronicle_project_number = get_environment_variable(
        env_constants.ENV_CHRONICLE_PROJECT_NUMBER
    )
    resource_name = f"projects/{chronicle_project_number}"
    policy = client.get_iam_policy(request={"resource": resource_name})

    # Get service account email from metadata server with timeout
    try:
      response = requests.get(
          "http://metadata.google.internal/computeMetadata/v1/instance/"
          "service-accounts/default/email",
          headers={"Metadata-Flavor": "Google"},
          timeout=METADATA_REQUEST_TIMEOUT,
      )
      response.raise_for_status()
      service_account_email = response.text
    except requests.exceptions.RequestException as e:
      error_msg = (
          "Failed to retrieve service account email from "
          f"metadata server: {str(e)}"
      )
      utils.cloud_logging(error_msg, severity="ERROR")
      raise Exception(  # pylint: disable=broad-exception-raised
          error_msg
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
          f"Service account - {service_account_email} does not have "
          "sufficient permissions."
      )
      utils.cloud_logging(f"{error_msg}", severity="ERROR")
      raise GCPPermissionDeniedError(
          message=error_msg, permissions=list(missing_permissions)
      )
    else:
      utils.cloud_logging("Service account has sufficient permissions.")
      return True
  except Exception as e:
    utils.cloud_logging(f"Unexpected error: {e}", severity="ERROR")
    raise Exception(  # pylint: disable=broad-exception-raised
        f"Unexpected error: {e}"
    ) from e
