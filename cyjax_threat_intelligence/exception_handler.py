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
# pylint: disable=g-bad-exception-name
"""Custom exception classes for Cyjax integration."""

from typing import Any, Dict

import requests


class ResponseErrorException(Exception):
  """Exception for API response errors."""

  def __init__(self, status_code: int, msg: str) -> None:
    """Initialize ResponseErrorException.

    Args:
        status_code (int): HTTP status code.
        msg (str): Error message.
    """
    self.status_code = status_code
    self.msg = msg
    super().__init__(msg)


class UnauthorizedException(requests.RequestException):
  """Exception for unauthorized requests."""

  def __init__(self) -> None:
    """Initialize UnauthorizedException."""
    super().__init__("You are unauthorized to perform this request.")


class ForbiddenException(requests.RequestException):
  """Exception for forbidden requests."""

  def __init__(self) -> None:
    """Initialize ForbiddenException."""
    super().__init__(
        "You do not have enough permission to access this resource."
    )


class NotFoundException(requests.RequestException):
  """Exception for not found requests."""

  def __init__(self) -> None:
    """Initialize NotFoundException."""
    super().__init__("Not found.")


class TooManyRequestsException(requests.RequestException):
  """Exception for rate limit errors."""

  def __init__(self) -> None:
    """Initialize TooManyRequestsException."""
    super().__init__("Too many requests sent.")


class ValidationException(requests.RequestException):
  """Exception for validation errors."""

  def __init__(
      self, json: Dict[str, Any]
  ) -> None:  # pylint: disable=g-bare-generic
    """Initialize ValidationException.

    Args:
        json (dict): Response JSON containing error details.
    """
    error = json.get("message") if "message" in json else "Validation error"
    super().__init__(error)


class ApiKeyNotFoundException(Exception):
  """Exception when API key is not found."""

  def __init__(self) -> None:
    """Initialize ApiKeyNotFoundException."""
    super().__init__("API key not found. Please set API key.")


class InvalidDateFormatException(Exception):
  """Exception for invalid date format."""

  def __init__(self, msg: str) -> None:
    """Initialize InvalidDateFormatException.

    Args:
        msg: Error message.
    """
    self.msg = msg
    super().__init__(msg)


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


class CyjaxException(Exception):
  """Custom exception for Cyjax API errors."""

  def __init__(self, message: str) -> None:
    """Initialize CyjaxException.

    Args:
        message: Explanation of the error.
    """
    self.message = message
    super().__init__(message)


class RunTimeExceeded(Exception):
  """Execution time limit exceeded."""

  def __init__(self, message: str = "Execution time limit exceeded") -> None:
    """Initialize RunTimeExceeded.

    Args:
        message: Explanation of the error
    """
    self.message = message
    super().__init__(self.message)
