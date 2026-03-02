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

# pylint: disable=g-bad-exception-name

"""Exception handler for Cyware CTIX ingestion script."""

import traceback
import requests


from common import utils
import constant


class CywareCTIXException(Exception):
  """An error occurred with the Cyware CTIX API."""

  def __init__(self, message):
    """Initialize CywareCTIXException.

    Args:
        message: Explanation of the error
    """
    self.message = message
    super().__init__(message)


class GCPPermissionDeniedError(Exception):
  """Insufficient GCP permissions.

  Attributes:
      message: Explanation of the error
      resource: The GCP resource that caused the error
      permissions: List of required permissions that were missing
  """

  def __init__(
      self,
      message: str,
      resource: str | None = None,
      permissions: list[str] | None = None,
  ) -> None:
    """Initialize GCPPermissionDeniedError.

    Args:
        message: Explanation of the error
        resource: The GCP resource that caused the error
        permissions: List of required permissions that were missing
    """
    self.message = message
    self.resource = resource
    self.permissions = permissions or []
    super().__init__(self.message)

  def __str__(self) -> str:
    """Return string representation of the error.

    Returns:
        Formatted error message with resource and permissions
    """
    msg = self.message
    if self.resource:
      msg += f" for resource: {self.resource}"
    if self.permissions:
      msg += f"\nRequired permissions: {', '.join(self.permissions)}"
    return msg


class RunTimeExceeded(Exception):
  """Execution time limit was exceeded."""

  def __init__(self, message: str = "Execution time limit exceeded") -> None:
    """Initialize RunTimeExceeded.

    Args:
        message: Explanation of the error
    """
    self.message = message
    super().__init__(self.message)


def exception_handler(*args, **kwargs):  # pylint: disable=unused-argument
  """Handle API call exceptions using Decorator factory.

  This decorator catches various `requests.exceptions` and a
  general `Exception` during an API call. It logs the error and
  returns a dictionary with error details instead of raising the
  exception.

  Args:
    *args: Variable positional arguments.
    **kwargs: Variable keyword arguments, expected to include "action_name".

  Returns:
    A decorator function that wraps the API call. The wrapped function returns
    a dict containing status, retry, and error fields based on the scenario.
  """
  function_name = kwargs["action_name"]

  def new_handler(func):
    def inner(*args, **kwargs):
      result = {"status": False, "retry": False, "error": ""}
      try:
        return func(*args, **kwargs)
      except requests.exceptions.ConnectTimeout as e:
        utils.cloud_logging(
            "[{0}] API call failed. Failed due to connection timeout. "
            "Error = {1}\n"
            "Traceback: {2}".format(
                function_name, repr(e), traceback.format_exc()
            ),
            severity="ERROR",
        )
        result["retry"] = True
        result["error"] = (
            "API call failed. Failed due to connection timeout.{0}".format(
                constant.CHECK_LOGS_FOR_MORE_DETAILS
            )
        )
      except requests.exceptions.ReadTimeout as e:
        utils.cloud_logging(
            "[{0}] API call failed. Failed due to read timeout. "
            "Error = {1}\n"
            "Traceback: {2}".format(
                function_name, repr(e), traceback.format_exc()
            ),
            severity="ERROR",
        )
        result["retry"] = True
        result["error"] = (
            "API call failed. Failed due to read timeout.{0}".format(
                constant.CHECK_LOGS_FOR_MORE_DETAILS
            )
        )
      except requests.exceptions.TooManyRedirects as e:
        utils.cloud_logging(
            "[{0}] API call failed. Failed due to too many "
            "redirects. Error - {1}\n"
            "Traceback: {2}".format(
                function_name, repr(e), traceback.format_exc()
            ),
            severity="ERROR",
        )
        result["error"] = (
            "API call failed. Failed due to too many redirects.{0}".format(
                constant.CHECK_LOGS_FOR_MORE_DETAILS
            )
        )
      except requests.exceptions.HTTPError as e:
        utils.cloud_logging(
            "[{0}] API call failed. Failed due to HTTP error. "
            "Error = {1}\n"
            "Traceback: {2}".format(
                function_name, repr(e), traceback.format_exc()
            ),
            severity="ERROR",
        )
        result["error"] = (
            "API call failed. Failed due to HTTP error.{0}".format(
                constant.CHECK_LOGS_FOR_MORE_DETAILS
            )
        )
      except requests.exceptions.SSLError as e:
        utils.cloud_logging(
            "[{0}] API call failed. Failed due to SSL error. "
            "Error = {1}\n"
            "Traceback: {2}".format(
                function_name, repr(e), traceback.format_exc()
            ),
            severity="ERROR",
        )
        result["error"] = "API call failed. Failed due to SSL error.{0}".format(
            constant.CHECK_LOGS_FOR_MORE_DETAILS
        )
      except Exception as e:  # pylint: disable=broad-except
        utils.cloud_logging(
            "[{0}] Exception occurred. Error = {1}\nTraceback: {2}".format(
                function_name, repr(e), traceback.format_exc()
            )
        )
        result["error"] = "API call failed.{0}".format(
            constant.CHECK_LOGS_FOR_MORE_DETAILS
        )
      return result

    return inner

  return new_handler
