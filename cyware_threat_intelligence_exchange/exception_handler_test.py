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
# pylint: disable=broad-exception-raised

import unittest
from unittest.mock import patch, MagicMock
import sys

# Mock requests module before importing exception_handler
mock_requests = MagicMock()
mock_requests_exceptions = MagicMock()


class MockConnectTimeout(Exception):
  pass


class MockReadTimeout(Exception):
  pass


class MockTooManyRedirects(Exception):
  pass


class MockHTTPError(Exception):
  pass


class MockSSLError(Exception):
  pass


mock_requests_exceptions.ConnectTimeout = MockConnectTimeout
mock_requests_exceptions.ReadTimeout = MockReadTimeout
mock_requests_exceptions.TooManyRedirects = MockTooManyRedirects
mock_requests_exceptions.HTTPError = MockHTTPError
mock_requests_exceptions.SSLError = MockSSLError
mock_requests.exceptions = mock_requests_exceptions

sys.modules["requests"] = mock_requests
sys.modules["requests.exceptions"] = mock_requests_exceptions

# Mock common modules
INGESTION_SCRIPTS_PATH = ""
sys.modules["common"] = MagicMock()
sys.modules["common.utils"] = MagicMock()

import exception_handler
import constant


class TestCywareCTIXException(unittest.TestCase):
  """Test cases for CywareCTIXException."""

  def test_initialization_with_message(self):
    """Test CywareCTIXException initialization with message."""
    error_message = "CTIX API error occurred"
    exception = exception_handler.CywareCTIXException(error_message)

    self.assertEqual(exception.message, error_message)
    self.assertEqual(str(exception), error_message)

  def test_inheritance_from_exception(self):
    """Test that CywareCTIXException inherits from Exception."""
    exception = exception_handler.CywareCTIXException("Test error")
    self.assertIsInstance(exception, Exception)

  def test_can_be_raised_and_caught(self):
    """Test that exception can be raised and caught."""
    with self.assertRaises(exception_handler.CywareCTIXException) as context:
      raise exception_handler.CywareCTIXException("Test CTIX error")
    self.assertEqual(context.exception.message, "Test CTIX error")

  def test_empty_message(self):
    """Test exception with empty message."""
    exception = exception_handler.CywareCTIXException("")
    self.assertEqual(exception.message, "")
    self.assertEqual(str(exception), "")


class TestGCPPermissionDeniedError(unittest.TestCase):
  """Test cases for GCPPermissionDeniedError exception."""

  def test_basic_initialization(self):
    """Test basic exception initialization with message only."""
    error = exception_handler.GCPPermissionDeniedError("Access denied")
    self.assertEqual(error.message, "Access denied")
    self.assertIsNone(error.resource)
    self.assertEqual(error.permissions, [])

  def test_initialization_with_resource(self):
    """Test exception initialization with resource."""
    error = exception_handler.GCPPermissionDeniedError(
        "Access denied", resource="gs://bucket/file"
    )
    self.assertEqual(error.message, "Access denied")
    self.assertEqual(error.resource, "gs://bucket/file")
    self.assertEqual(error.permissions, [])

  def test_initialization_with_permissions(self):
    """Test exception initialization with permissions list."""
    perms = ["Storage Admin", "Secret Manager Secret Accessor"]
    error = exception_handler.GCPPermissionDeniedError(
        "Access denied", permissions=perms
    )
    self.assertEqual(error.message, "Access denied")
    self.assertIsNone(error.resource)
    self.assertEqual(error.permissions, perms)

  def test_initialization_with_all_parameters(self):
    """Test exception initialization with all parameters."""
    perms = ["Storage Admin", "Viewer"]
    error = exception_handler.GCPPermissionDeniedError(
        "Access denied", resource="gs://bucket/file", permissions=perms
    )
    self.assertEqual(error.message, "Access denied")
    self.assertEqual(error.resource, "gs://bucket/file")
    self.assertEqual(error.permissions, perms)

  def test_str_representation_basic(self):
    """Test string representation with message only."""
    error = exception_handler.GCPPermissionDeniedError("Access denied")
    self.assertEqual(str(error), "Access denied")

  def test_str_representation_with_resource(self):
    """Test string representation with resource."""
    error = exception_handler.GCPPermissionDeniedError(
        "Access denied", resource="gs://bucket/file"
    )
    expected = "Access denied for resource: gs://bucket/file"
    self.assertEqual(str(error), expected)

  def test_str_representation_with_permissions(self):
    """Test string representation with permissions."""
    perms = ["Storage Admin", "Viewer"]
    error = exception_handler.GCPPermissionDeniedError(
        "Access denied", permissions=perms
    )
    expected = "Access denied\nRequired permissions: Storage Admin, Viewer"
    self.assertEqual(str(error), expected)

  def test_str_representation_with_all(self):
    """Test string representation with all parameters."""
    perms = ["Storage Admin", "Viewer"]
    error = exception_handler.GCPPermissionDeniedError(
        "Access denied", resource="gs://bucket/file", permissions=perms
    )
    expected = (
        "Access denied for resource: gs://bucket/file\n"
        "Required permissions: Storage Admin, Viewer"
    )
    self.assertEqual(str(error), expected)

  def test_permissions_default_to_empty_list(self):
    """Test that permissions default to empty list, not None."""
    error = exception_handler.GCPPermissionDeniedError("Access denied")
    self.assertIsInstance(error.permissions, list)
    self.assertEqual(len(error.permissions), 0)

  def test_gcp_error_inheritance_from_exception(self):
    """Test that GCPPermissionDeniedError inherits from Exception."""
    error = exception_handler.GCPPermissionDeniedError("Access denied")
    self.assertIsInstance(error, Exception)

  def test_gcp_error_can_be_raised_and_caught(self):
    """Test that exception can be raised and caught."""
    with self.assertRaises(
        exception_handler.GCPPermissionDeniedError
    ) as context:
      raise exception_handler.GCPPermissionDeniedError("Test error")
    self.assertEqual(context.exception.message, "Test error")


class TestExceptionHandlerDecorator(unittest.TestCase):
  """Test cases for exception_handler decorator."""

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  def test_decorator_with_successful_function(self, mock_logging):
    """Test decorator with function that executes successfully."""

    @exception_handler.exception_handler(action_name="Test API")
    def successful_function():
      return {"status": True, "data": "success"}

    result = successful_function()
    self.assertTrue(result["status"])
    self.assertEqual(result["data"], "success")
    mock_logging.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}exception_handler.requests.exceptions.ConnectTimeout",
      MockConnectTimeout,
  )
  def test_decorator_with_connect_timeout(self, mock_logging):
    """Test decorator handles ConnectTimeout exception."""

    @exception_handler.exception_handler(action_name="Test API")
    def timeout_function():
      raise MockConnectTimeout("Connection timeout")

    result = timeout_function()
    self.assertFalse(result["status"])
    self.assertTrue(result["retry"])
    self.assertIn("connection timeout", result["error"])
    mock_logging.assert_called_once()
    self.assertIn("connection timeout", mock_logging.call_args[0][0].lower())

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.requests.exceptions.ReadTimeout", MockReadTimeout)
  def test_decorator_with_read_timeout(self, mock_logging):
    """Test decorator handles ReadTimeout exception."""

    @exception_handler.exception_handler(action_name="Test API")
    def timeout_function():
      raise MockReadTimeout("Read timeout")

    result = timeout_function()
    self.assertFalse(result["status"])
    self.assertTrue(result["retry"])
    self.assertIn("read timeout", result["error"])
    mock_logging.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}exception_handler.requests.exceptions.TooManyRedirects",
      MockTooManyRedirects,
  )
  def test_decorator_with_too_many_redirects(self, mock_logging):
    """Test decorator handles TooManyRedirects exception."""

    @exception_handler.exception_handler(action_name="Test API")
    def redirect_function():
      raise MockTooManyRedirects("Too many redirects")

    result = redirect_function()
    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("too many redirects", result["error"])
    mock_logging.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.requests.exceptions.HTTPError", MockHTTPError)
  def test_decorator_with_http_error(self, mock_logging):
    """Test decorator handles HTTPError exception."""

    @exception_handler.exception_handler(action_name="Test API")
    def http_error_function():
      raise MockHTTPError("HTTP error")

    result = http_error_function()
    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("HTTP error", result["error"])
    mock_logging.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.requests.exceptions.SSLError", MockSSLError)
  def test_decorator_with_ssl_error(self, mock_logging):
    """Test decorator handles SSLError exception."""

    @exception_handler.exception_handler(action_name="Test API")
    def ssl_error_function():
      raise MockSSLError("SSL error")

    result = ssl_error_function()
    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("SSL error", result["error"])
    mock_logging.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  def test_decorator_with_general_exception(self, mock_logging):
    """Test decorator handles general Exception."""

    @exception_handler.exception_handler(action_name="Test API")
    def general_error_function():
      raise Exception(
          "General error")  # pylint: disable=broad-exception-raised

    result = general_error_function()
    self.assertFalse(result["status"])
    self.assertFalse(result["retry"])
    self.assertIn("API call failed", result["error"])
    mock_logging.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  def test_decorator_with_function_arguments(self, mock_logging):
    """Test decorator with function that takes arguments."""

    @exception_handler.exception_handler(action_name="Test API")
    def function_with_args(arg1, arg2, kwarg1=None):
      return {"status": True, "result": f"{arg1}-{arg2}-{kwarg1}"}

    result = function_with_args("a", "b", kwarg1="c")
    self.assertTrue(result["status"])
    self.assertEqual(result["result"], "a-b-c")

  @patch(f"{INGESTION_SCRIPTS_PATH}exception_handler.utils.cloud_logging")
  def test_decorator_error_includes_check_logs_message(self, mock_logging):
    """Test that error messages include check logs directive."""

    @exception_handler.exception_handler(action_name="Test API")
    def error_function():
      raise MockConnectTimeout("Connection timeout")

    result = error_function()
    self.assertIn(constant.CHECK_LOGS_FOR_MORE_DETAILS, result["error"])


class TestRunTimeExceeded(unittest.TestCase):
  """Test cases for RunTimeExceeded exception."""

  def test_runtime_exceeded_with_default_message(self):
    """Test RunTimeExceeded with default message."""
    exc = exception_handler.RunTimeExceeded()
    self.assertEqual(exc.message, "Execution time limit exceeded")
    self.assertIn("Execution time limit exceeded", str(exc))

  def test_runtime_exceeded_with_custom_message(self):
    """Test RunTimeExceeded with custom message."""
    custom_msg = "Custom timeout message"
    exc = exception_handler.RunTimeExceeded(custom_msg)
    self.assertEqual(exc.message, custom_msg)
    self.assertIn(custom_msg, str(exc))


if __name__ == "__main__":
  unittest.main()
