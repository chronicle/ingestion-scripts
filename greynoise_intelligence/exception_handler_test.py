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

"""Unit tests for exception_handler module."""

import unittest

from exception_handler import GCPPermissionDeniedError
from exception_handler import LiveInvestigationError


class TestGCPPermissionDeniedError(unittest.TestCase):
  """Test cases for GCPPermissionDeniedError exception."""

  def test_basic_initialization(self):
    """Test basic exception initialization with message only."""
    error = GCPPermissionDeniedError("Access denied")
    self.assertEqual(error.message, "Access denied")
    self.assertIsNone(error.resource)
    self.assertEqual(error.permissions, [])

  def test_initialization_with_resource(self):
    """Test exception initialization with resource."""
    error = GCPPermissionDeniedError(
        "Access denied", resource="gs://bucket/file"
    )
    self.assertEqual(error.message, "Access denied")
    self.assertEqual(error.resource, "gs://bucket/file")
    self.assertEqual(error.permissions, [])

  def test_initialization_with_permissions(self):
    """Test exception initialization with permissions list."""
    perms = ["Storage Admin", "Viewer"]
    error = GCPPermissionDeniedError("Access denied", permissions=perms)
    self.assertEqual(error.message, "Access denied")
    self.assertIsNone(error.resource)
    self.assertEqual(error.permissions, perms)

  def test_initialization_with_all_parameters(self):
    """Test exception initialization with all parameters."""
    perms = ["Storage Admin", "Viewer"]
    error = GCPPermissionDeniedError(
        "Access denied", resource="gs://bucket/file", permissions=perms
    )
    self.assertEqual(error.message, "Access denied")
    self.assertEqual(error.resource, "gs://bucket/file")
    self.assertEqual(error.permissions, perms)

  def test_str_representation_basic(self):
    """Test string representation with message only."""
    error = GCPPermissionDeniedError("Access denied")
    self.assertEqual(str(error), "Access denied")

  def test_str_representation_with_resource(self):
    """Test string representation with resource."""
    error = GCPPermissionDeniedError(
        "Access denied", resource="gs://bucket/file"
    )
    expected = "Access denied for resource: gs://bucket/file"
    self.assertEqual(str(error), expected)

  def test_str_representation_with_permissions(self):
    """Test string representation with permissions."""
    perms = ["Storage Admin", "Viewer"]
    error = GCPPermissionDeniedError("Access denied", permissions=perms)
    expected = "Access denied\nRequired permissions: Storage Admin, Viewer"
    self.assertEqual(str(error), expected)

  def test_str_representation_with_all(self):
    """Test string representation with all parameters."""
    perms = ["Storage Admin", "Viewer"]
    error = GCPPermissionDeniedError(
        "Access denied", resource="gs://bucket/file", permissions=perms
    )
    expected = (
        "Access denied for resource: gs://bucket/file\n"
        "Required permissions: Storage Admin, Viewer"
    )
    self.assertEqual(str(error), expected)

  def test_permissions_default_to_empty_list(self):
    """Test that permissions default to empty list, not None."""
    error = GCPPermissionDeniedError("Access denied")
    self.assertIsInstance(error.permissions, list)
    self.assertEqual(len(error.permissions), 0)

  def test_inheritance_from_exception(self):
    """Test that GCPPermissionDeniedError inherits from Exception."""
    error = GCPPermissionDeniedError("Access denied")
    self.assertIsInstance(error, Exception)

  def test_can_be_raised_and_caught(self):
    """Test that exception can be raised and caught."""
    with self.assertRaises(GCPPermissionDeniedError) as context:
      raise GCPPermissionDeniedError("Test error")
    self.assertEqual(context.exception.message, "Test error")


class TestLiveInvestigationError(unittest.TestCase):
  """Test cases for LiveInvestigationError exception."""

  def test_basic_initialization(self):
    """Test basic exception initialization."""
    error = LiveInvestigationError("Investigation failed")
    self.assertEqual(str(error), "Investigation failed")

  def test_inheritance_from_exception(self):
    """Test that LiveInvestigationError inherits from Exception."""
    error = LiveInvestigationError("Investigation failed")
    self.assertIsInstance(error, Exception)

  def test_can_be_raised_and_caught(self):
    """Test that exception can be raised and caught."""
    with self.assertRaises(LiveInvestigationError) as context:
      raise LiveInvestigationError("Test error")
    self.assertEqual(str(context.exception), "Test error")

  def test_empty_message(self):
    """Test exception with empty message."""
    error = LiveInvestigationError("")
    self.assertEqual(str(error), "")

  def test_multiple_arguments(self):
    """Test exception with multiple arguments."""
    error = LiveInvestigationError("Error 1", "Error 2")
    # Exception can accept multiple args
    self.assertIsInstance(error, Exception)


if __name__ == "__main__":
  unittest.main()
