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

"""Custom exceptions for Vectra XDR ingestion script."""


class VectraException(Exception):
  """Base exception for Vectra XDR ingestion script."""


class UnauthorizeException(VectraException):
  """Unauthorized user."""


class RefreshTokenException(VectraException):
  """Exception if refresh token is expired or invalid."""


class RateLimitException(VectraException):
  """Exception for rate limit."""


class InternalSeverError(VectraException):
  """Internal Server Error."""


class BadRequestException(VectraException):
  """Exception for bad request."""
