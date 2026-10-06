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

# pylint: disable=line-too-long
# pylint: disable=g-importing-member
# pylint: disable=invalid-name
# pylint: disable=g-multiple-import
# pylint: disable=unused-argument
# pylint: disable=g-import-not-at-top
# pylint: disable=g-bad-import-order
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=g-bad-exception-name

"""Unit tests for exception_handler module."""

import unittest
import exception_handler


class TestResponseErrorException(unittest.TestCase):
  """Test ResponseErrorException."""

  def test_init(self):
    """Test initialization."""
    exc = exception_handler.ResponseErrorException(404, "Not found")
    self.assertEqual(exc.status_code, 404)
    self.assertEqual(exc.msg, "Not found")
    self.assertEqual(str(exc), "Not found")


class TestUnauthorizedException(unittest.TestCase):
  """Test UnauthorizedException."""

  def test_init(self):
    """Test initialization."""
    exc = exception_handler.UnauthorizedException()
    self.assertIn("unauthorized", str(exc).lower())


class TestForbiddenException(unittest.TestCase):
  """Test ForbiddenException."""

  def test_init(self):
    """Test initialization."""
    exc = exception_handler.ForbiddenException()
    self.assertIn("permission", str(exc).lower())


class TestNotFoundException(unittest.TestCase):
  """Test NotFoundException."""

  def test_init(self):
    """Test initialization."""
    exc = exception_handler.NotFoundException()
    self.assertIn("not found", str(exc).lower())


class TestTooManyRequestsException(unittest.TestCase):
  """Test TooManyRequestsException."""

  def test_init(self):
    """Test initialization."""
    exc = exception_handler.TooManyRequestsException()
    self.assertIn("too many", str(exc).lower())


class TestValidationException(unittest.TestCase):
  """Test ValidationException."""

  def test_init_with_message(self):
    """Test initialization with message."""
    json_data = {"message": "Validation failed"}
    exc = exception_handler.ValidationException(json_data)
    self.assertIn("Validation failed", str(exc))

  def test_init_without_message(self):
    """Test initialization without message."""
    json_data = {"error": "Some error"}
    exc = exception_handler.ValidationException(json_data)
    self.assertIn("Validation error", str(exc))


class TestApiKeyNotFoundException(unittest.TestCase):
  """Test ApiKeyNotFoundException."""

  def test_init(self):
    """Test initialization."""
    exc = exception_handler.ApiKeyNotFoundException()
    self.assertIn("API key", str(exc))


class TestInvalidDateFormatException(unittest.TestCase):
  """Test InvalidDateFormatException."""

  def test_init(self):
    """Test initialization."""
    exc = exception_handler.InvalidDateFormatException("Invalid format")
    self.assertEqual(exc.msg, "Invalid format")
    self.assertEqual(str(exc), "Invalid format")


class TestGCPPermissionDeniedError(unittest.TestCase):
  """Test GCPPermissionDeniedError."""

  def test_init_minimal(self):
    """Test initialization with minimal params."""
    exc = exception_handler.GCPPermissionDeniedError("Permission denied")
    self.assertEqual(exc.message, "Permission denied")
    self.assertIsNone(exc.resource)
    self.assertEqual(exc.permissions, [])

  def test_init_full(self):
    """Test initialization with all params."""
    exc = exception_handler.GCPPermissionDeniedError(
        "Permission denied",
        resource="gs://bucket",
        permissions=["read", "write"],
    )
    self.assertEqual(exc.message, "Permission denied")
    self.assertEqual(exc.resource, "gs://bucket")
    self.assertEqual(exc.permissions, ["read", "write"])

  def test_str_minimal(self):
    """Test string representation minimal."""
    exc = exception_handler.GCPPermissionDeniedError("Error")
    self.assertEqual(str(exc), "Error")

  def test_str_with_resource(self):
    """Test string representation with resource."""
    exc = exception_handler.GCPPermissionDeniedError(
        "Error", resource="gs://bucket"
    )
    self.assertIn("gs://bucket", str(exc))

  def test_str_with_permissions(self):
    """Test string representation with permissions."""
    exc = exception_handler.GCPPermissionDeniedError(
        "Error", permissions=["read"]
    )
    self.assertIn("read", str(exc))


class TestCyjaxException(unittest.TestCase):
  """Test CyjaxException."""

  def test_init(self):
    """Test initialization."""
    exc = exception_handler.CyjaxException("Custom error")
    self.assertEqual(exc.message, "Custom error")
    self.assertEqual(str(exc), "Custom error")


class TestRunTimeExceeded(unittest.TestCase):
  """Test RunTimeExceeded."""

  def test_init_default(self):
    """Test initialization with default message."""
    exc = exception_handler.RunTimeExceeded()
    self.assertIn("limit exceeded", str(exc).lower())

  def test_init_custom(self):
    """Test initialization with custom message."""
    exc = exception_handler.RunTimeExceeded("Custom timeout")
    self.assertEqual(str(exc), "Custom timeout")


if __name__ == "__main__":
  unittest.main()
