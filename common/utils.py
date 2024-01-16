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
"""Utility functions required for ingestion scripts."""

import datetime
import json
import os
from typing import Dict, Any

from google.cloud import secretmanager

from common import env_constants


def get_env_var(
    name: str,
    required: bool = True,
    default: Any = None,
    is_secret: bool = False,
) -> Any:
  """Gets an environment variable.

  Args:
    name (str): Name of the environment variable.
    required (Optional[bool]): Script will exit with RuntimeError if this is
      True and variable is not set. Defaults to True.
    default (Optional[Any]): Default value to return in case the env variable is
      not set. Defaults to None.
    is_secret (bool): Script will get data from Google Cloud Secret Manager in
      case it is set to true.

  Returns:
    Any: Value of the environment variable.

  Raises:
    RuntimeError: Raises when required name is not in environment variable.
  """
  if name not in os.environ and required:
    raise RuntimeError(f"Environment variable {name} is required.")
  if is_secret:
    return get_value_from_secret_manager(os.environ[name])
  if name not in os.environ or (name in os.environ and
                                not os.environ[name].strip()):
    return default
  return os.environ[name]


def get_last_run_at() -> datetime.datetime:
  """Calculates the start time for data collection based on POLL_INTERVAL environment variable.

  If the POLL_INTERVAL environment variable is not set, then the function will
  return the start time as the last 5 minutes from the current time.

  Returns:
    datetime.datetime: Start time for data collection.

  Raises:
    RuntimeError: If the value of the POLL_INTERVAL is negative or zero.
  """
  try:
    # If the POLL_INTERVAL is not passed, the default value will considered as
    # last 5 minutes from the current time.
    poll_interval = get_env_var(
        env_constants.ENV_POLL_INTERVAL, required=False, default=5)

    if int(poll_interval) <= 0:
      raise ValueError

    return datetime.datetime.now(
        datetime.timezone.utc) - datetime.timedelta(minutes=int(poll_interval))
  except ValueError as error:
    raise RuntimeError(
        "Invalid value provided for the POLL_INTERVAL environment variable. A "
        "POLL_INTERVAL should be a non-zero positive integer value.") from error


def get_value_from_secret_manager(resource_path: str) -> str:
  """Retrieve the value of the secret from the Google Cloud Secret Manager.

  Args:
    resource_path (str): Path of the secret with version included. Ex.:
      "projects/<project_id>/secrets/<secret_name>/versions/1",
      "projects/<project_id>/secrets/<secret_name>/versions/latest"

  Returns:
    str: Payload for secret.
  """
  # Create the Secret Manager client.
  client = secretmanager.SecretManagerServiceClient()

  # Access the secret version.
  response = client.access_secret_version(name=resource_path)
  return response.payload.data.decode("UTF-8")


def load_service_account(service_account: str,
                         product_name: str) -> Dict[str, Any]:
  """Load a service account string to the dictionary.

  Args:
      service_account (str): Service account string.
      product_name (str): The name of the product whose service_account string
        is serialized.

  Returns:
      service_account_dict (Dict): Parsed service account dictionary from
      given string.

  Raises:
      RuntimeError: If the provided service account string is not JSON
      serializable.
  """
  try:
    return json.loads(service_account)
  except json.JSONDecodeError as error:
    print("Could not load the service account string.")
    raise RuntimeError(
        f"Invalid Service Account JSON provided for {product_name}.") from error


def cloud_logging(message: str, severity: str = "INFO") -> None:
  """Function for logging in google cloud function.

  Args:
    message (str): The message to log
    severity (str): severity of the message. Defaults to "INFO".
  """
  print(json.dumps({"severity": severity, "message": message}))
