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

"""Exception handler for GreyNoise ingestion script."""


class GCPPermissionDeniedError(Exception):
  """GCP permissions are insufficient.

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
    """Initialize the instance.

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


class LiveInvestigationError(Exception):
  """Exception raised when live investigation fails."""
