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
# pylint: disable=line-too-long
"""Utility functions for Vectra XDR ingestion scripts."""

import concurrent.futures
import json
import time
from typing import Callable

from google.api_core.exceptions import NotFound  # pylint: disable=g-importing-member
import google.auth
from google.cloud import secretmanager

from common import status
from common import utils
import constant
import exception

default = google.auth.default


class SecretManagerClient:
  """A client for interacting with Google Cloud Secret Manager."""

  def __init__(self):
    # Get default credentials for the client
    credentials, _ = default()
    # Create a Secret Manager client
    self.client = secretmanager.SecretManagerServiceClient(
        credentials=credentials
    )
    self.project_id = get_environment_variable(
        constant.ENV_GCP_PROJECT_NUMBER, is_required=True
    )
    utils.cloud_logging("Secret Manager Client Initialized.")

  def get_secrets(self, secret_name, secret_format_is_json_type=True):
    """Retrieves the secret from Google Cloud Secret Manager.

    Args:
        secret_name (str): The name of the secret.
        secret_format_is_json_type (bool, optional): If the secret is in JSON
          format. Defaults to True.

    Returns:
        dict: The secret payload as a dictionary.

    Raises:
        VectraException: If the secret is not found or an unknown exception
        occurs.
    """
    try:
      if "project" not in secret_name:
        secret_name = f"projects/{self.project_id}/secrets/{secret_name}"
      if "versions" not in secret_name:
        secret_name = secret_name + "/versions/latest"
      secret_payload = self.client.access_secret_version(name=secret_name)
      secret_payload = secret_payload.payload.data.decode("UTF-8")
      if secret_format_is_json_type:
        secret_payload = json.loads(secret_payload)
      return secret_payload
    except NotFound as e:
      utils.cloud_logging("Secret not found while retrieving the secret.")
      raise exception.VectraException(e) from None
    except Exception as e:
      utils.cloud_logging(
          "Unknown exception occurred while retrieving the secret. Error"
          f" message: {e}"
      )
      raise exception.VectraException(e) from None

  def set_or_update_secrets(self, secret_name: str, secret_payload: dict):  # pylint: disable=g-bare-generic
    """Sets or updates the secret in Google Cloud Secret Manager.

    Args:
        secret_name (str): The name of the secret.
        secret_payload (dict): The secret payload as a dictionary.

    Raises:
        VectraException: If an unknown exception occurs.
    """
    secret_data = json.dumps(secret_payload)
    payload = secretmanager.SecretPayload(data=secret_data.encode("UTF-8"))
    try:
      parent = self.client.secret_path(self.project_id, secret_name)
      version_list = list(self.client.list_secret_versions(request={"parent": parent}))
      self.client.add_secret_version(
          parent=parent,
          payload=payload,
      )
      if version_list:
        latest_version_name = version_list[0].name
        self.client.disable_secret_version(request={"name": latest_version_name})
    except NotFound:
      utils.cloud_logging(
          "Secret not found while updating the secret. Hence creating a new"
          " secret."
      )
      secret = self.client.create_secret(
          parent=f"projects/{self.project_id}",
          secret_id=secret_name,
          secret=secretmanager.Secret(
              replication=secretmanager.Replication(
                  automatic=secretmanager.Replication.Automatic()
              )
          ),
      )
      self.client.add_secret_version(parent=secret.name, payload=payload)
    except Exception as e:
      utils.cloud_logging(
          "Unknown exception occurred while updating the secret. Error"
          f" message: {e}"
      )
      raise exception.VectraException(e) from None


class HandleExceptions:
  """A class to handle exceptions based on different actions."""

  def __init__(self, url, error, response, error_msg="An error occurred"):
    """Initializes the HandleExceptions class.

    Args:
        url (str): API name.
        error (Exception): The error that occurred.
        response (Response): The response object.
        error_msg (str, optional): A default error message. Defaults to "An
          error occurred".
    """
    self.url = url
    self.error = error
    self.response = response
    self.error_msg = error_msg

  def do_process(self):
    """Processes the error by calling the appropriate handler."""
    if self.response.status_code >= status.STATUS_INTERNAL_SERVER_ERROR:
      utils.cloud_logging(
          "It seems like the Vectra server is experiencing some issues,"
          f" Status: {self.response.status_code}"
      )
      raise exception.InternalSeverError(
          "It seems like the Vectra server is experiencing some issues,"
          f" Status: {self.response.status_code}"
      )
    try:
      _exception, _error_msg = self.get_handler()  # pylint: disable=invalid-name
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Unknown exception occurred while getting the handler. Error"
          f" message: {e}"
      )
      _exception, _error_msg = self.common_exception()  # pylint: disable=invalid-name

    raise _exception(_error_msg)

  def get_handler(self):
    """Retrieves the appropriate handler function based on the api_name.

    Returns:
        function: The handler function corresponding to the api_name.
    """
    if constant.VECTRA_ACCESS_TOKEN_ENDPOINT in self.url:
      return self.auth_handle()
    return self.common_exception()

  def common_exception(self):
    """Handles common exceptions that don't have a specific handler.

    If the response status code is 400, it calls the appropriate handler for bad
    request errors.
    Otherwise, it calls the general error handler.

    Returns:
        tuple: A tuple containing the exception class and the formatted error
        message.
    """
    if self.response.status_code == status.STATUS_BAD_REQUEST:
      return self._handle_bad_request_error()
    elif self.response.status_code == status.STATUS_UNAUTHORIZED:
      return exception.UnauthorizeException, "UnauthorizeException"

    return self._handle_general_error()

  def _handle_general_error(self):
    """Handles general errors by formatting the error message and returning the appropriate exception.

    Returns:
        tuple: A tuple containing the exception class and the formatted error
        message.
    """
    error_msg = "{error_msg}: {error} - {text}".format(
        error_msg=self.error_msg, error=self.error, text=self.response.content
    )

    return exception.VectraException, error_msg

  def _handle_bad_request_error(self):
    """Handles bad request errors by extracting the error message from the response.

    Returns:
        tuple: A tuple containing the exception class and the formatted error
        message.
    """
    error_response = self.response.json()

    if isinstance(error_response, list) and error_response:
      # If the response is a list, return the first error message
      return exception.BadRequestException, error_response[0]
    elif isinstance(error_response, dict):
      if "_meta" in error_response:
        # Remove the _meta key from the error response
        del error_response["_meta"]

      # Extract the error message from the response
      error_msg = error_response.get(list(error_response.keys())[0])
      return exception.BadRequestException, error_msg

    # If no error message is found, return the general error message
    return self._handle_general_error()

  def auth_handle(self):
    """Handles connectivity exceptions that don't have a specific handler.

    If the response status code is 400, it calls the appropriate handler for bad
    request errors.
    Otherwise, it calls the common error handler.

    Returns:
        tuple: A tuple containing the exception class and the formatted error
        message.
    """
    res = self.response.json()
    error_msg = res.get("error")
    if self.response.status_code == status.STATUS_BAD_REQUEST:
      return exception.RefreshTokenException, error_msg
    elif self.response.status_code == status.STATUS_UNAUTHORIZED:
      if constant.ERRORS["REFRESH_TOKEN_EXPIRE_MESSAGE"] in error_msg:
        return exception.RefreshTokenException, error_msg
      return exception.UnauthorizeException, error_msg

    return self.common_exception()


def get_environment_variable(
    name: str, is_required=False, is_secret=False
) -> str:
  """Retrieves the value of the given environment variable.

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
  """
  default_value = constant.DEFAULT_VALUES.get(name, "")
  env_value = utils.get_env_var(
      name, required=is_required, default=default_value
  ).strip()
  if not is_secret:
    env_value = env_value.lower()

  return env_value


def run_methods_with_intervals(methods: list[Callable[[], None]]):
  """Run the given methods in parallel with a specified interval."""

  with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = []
    for idx, method in enumerate(methods):
      # Schedule each method with a delay
      futures.append(executor.submit(delayed_execution, method))
      if idx != len(methods) - 1:
        utils.cloud_logging(
            "Sleeping for {} seconds".format(constant.METHOD_INTERVAL)
        )
        time.sleep(constant.METHOD_INTERVAL)

    # Wait for all methods to complete
    for future in concurrent.futures.as_completed(futures):
      try:
        future.result()  # Raise exceptions if any occurred
      except Exception as e:  # pylint: disable=broad-except
        utils.cloud_logging(
            f"Exception occurred while executing a method: {e}",
            severity="ERROR",
        )


def delayed_execution(method: Callable[[], None]):
  """Executes a method after a specified delay."""
  if callable(method):
    method_name = getattr(method, "__name__", str(method))
  else:
    raise ValueError("Method is not callable")
  utils.cloud_logging("Executing {} method".format(method_name))
  method()
  utils.cloud_logging("Completed {} method".format(method_name))
