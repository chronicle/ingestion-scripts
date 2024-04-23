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
"""Unit test case file for main module of GCS ingestion script."""

import datetime
import gzip
import sys

import unittest
from unittest import mock

INGESTION_SCRIPTS_PATH = ""
SCRIPT_PATH = ""

# Mock the chronicle library
sys.modules[f"{INGESTION_SCRIPTS_PATH}common.ingest"] = mock.MagicMock()
sys.modules[f"{INGESTION_SCRIPTS_PATH}common.utils"] = mock.MagicMock()

import main

# CONSTANTS
ENV_VARS = ['{"SERVICE_ACC": "DUMMY"}', "GCP_COMPUTE", "Bucket Name"]
INGESTION_COMPLETE_MSG = "Ingestion completed."


class MockBlob:
  """Mock class for blob object."""

  def __init__(self, created_time):
    self.time_created = created_time
    self.name = "mock_blob_name"

  # GCS sends a blob list in a text separated by a new line,
  # the below function return the gzipped text of valid blob jsons.
  def download_as_bytes(self):
    return gzip.compress(b"{}\n{}\n")

  # GCS sends a blob list in a text separated by a new line,
  # the below function return the gzipped text of invalid blob jsons.
  def download_as_bytes_error(self):
    return gzip.compress(b"{''}\n{}\n")


class MockBucketObject:
  """Mock class for bucket object's list_blobs function."""

  # The GCS list_blobs return all the blobs, but script ingest newer blobs only.
  # The below function return some old and new sample blobs.
  def list_blobs(self):
    start_time = datetime.datetime.now(datetime.timezone.utc)
    older_blob1 = start_time - datetime.timedelta(minutes=20)
    older_blob2 = start_time - datetime.timedelta(minutes=20)
    newer_blob1 = start_time + datetime.timedelta(seconds=1)
    newer_blob2 = start_time + datetime.timedelta(seconds=2)
    return [
        MockBlob(older_blob1),
        MockBlob(older_blob2),
        MockBlob(newer_blob1),
        MockBlob(newer_blob2)
    ]


class MockStorageClient:
  """Mock class for cloud storage client's get_bucket function."""

  def get_bucket(self, name):  # pylint: disable=unused-argument
    return MockBucketObject()


class MockStorageClientError:
  """Mock class for cloud storage client's get_bucket function which raises exception."""

  def __init__(self, error="exception"):
    self.error = error

  def get_bucket(self, name):  # pylint: disable=unused-argument
    if self.error == "not_found_error":
      raise main.exceptions.NotFound("The specified bucket does not exist")
    raise Exception()


class TestGCSIngestion(unittest.TestCase):
  """Test cases for GCS_Ingestion."""

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.storage.Client.from_service_account_info")
  def test_storage_client_for_exception(self, mock_storage_client, mock_utils):
    """Test case to verify storage client raises error."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_request = mock.MagicMock()

    mock_storage_client.side_effect = Exception()
    with self.assertRaises(Exception) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception), "Error occurred while creating the GCS Client.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.storage.Client.from_service_account_info")
  def test_storage_client_for_value_error(self, mock_storage_client,
                                          mock_utils):
    """Test case to verify storage client raises error."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_request = mock.MagicMock()

    mock_storage_client.side_effect = ValueError()
    with self.assertRaises(RuntimeError) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception), "Invalid Google Cloud Service Account provided.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.storage.Client.from_service_account_info")
  def test_bucket_object_for_bucket_not_found_error(self, mock_storage_client,
                                                    mock_utils):
    """Test case to verify bucket object raises error when specified bucket does not exist."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_storage_client.return_value = MockStorageClientError("not_found_error")

    mock_request = mock.MagicMock()
    with self.assertRaises(RuntimeError) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "The specified bucket 'bucket name' does not exist.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.storage.Client.from_service_account_info")
  def test_bucket_object_for_error(self, mock_storage_client, mock_utils):
    """Test case to verify bucket object raises error."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_storage_client.return_value = MockStorageClientError()

    mock_request = mock.MagicMock()
    with self.assertRaises(Exception) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "Error occurred while creating the object for 'bucket name'")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  @mock.patch(f"{SCRIPT_PATH}main.storage.Client.from_service_account_info")
  def test_ingest_for_error(self, mock_storage_client, mock_ingest, mock_utils):
    """Test case to verify get_and_ingest_logs for failure."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_utils.get_last_run_at.return_value = datetime.datetime.now(
        datetime.timezone.utc) - datetime.timedelta(minutes=15)
    mock_storage_client.return_value = MockStorageClient()
    mock_ingest.ingest.side_effect = Exception(
        "Unable to push the data to the Chronicle.")
    mock_request = mock.MagicMock()

    with self.assertRaises(Exception) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "Unable to push the data to the Chronicle.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  @mock.patch(f"{SCRIPT_PATH}main.storage.Client.from_service_account_info")
  def test_ingestion_successful(self, mock_storage_client, mock_ingest,
                                mock_utils):
    """Test case to verify for successful ingestion of logs."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_utils.get_last_run_at.return_value = datetime.datetime.now(
        datetime.timezone.utc) - datetime.timedelta(minutes=15)
    mock_storage_client.return_value = MockStorageClient()
    mock_request = mock.MagicMock()
    assert main.main(mock_request) == INGESTION_COMPLETE_MSG
    assert mock_ingest.call_count == 2  # Called for 2 newer blobs only.

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.storage.Client.from_service_account_info")
  def test_json_decode_error(self, mock_storage_client, mock_utils):
    """Test case to verify json loads for failure."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_utils.get_last_run_at.return_value = datetime.datetime.now(
        datetime.timezone.utc) - datetime.timedelta(minutes=15)
    mock_storage_client.return_value = MockStorageClient()
    MockBlob.download_as_bytes = MockBlob.download_as_bytes_error

    mock_request = mock.MagicMock()
    with self.assertRaises(RuntimeError) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "Could not load the log data from blob mock_blob_name.")

  @mock.patch(f"{SCRIPT_PATH}main.utils.get_env_var")
  @mock.patch(f"{SCRIPT_PATH}main.utils.get_last_run_at")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  @mock.patch(f"{SCRIPT_PATH}main.storage.Client.from_service_account_info")
  def test_get_env_variable_for_secret(self, mock_storage_client, mock_ingest,    # pylint: disable=unused-argument
                                       mock_get_last_run, mock_get_env_var):
    """Test case to verify is_secret in get_env_vars."""
    mock_get_last_run.return_value = datetime.datetime.now(
        datetime.timezone.utc) - datetime.timedelta(minutes=15)
    mock_storage_client.return_value = MockStorageClient()
    mock_request = mock.MagicMock()
    main.main(mock_request)
    self.assertEqual(
        mock_get_env_var.mock_calls[0],
        mock.call("GCP_SERVICE_ACCOUNT_SECRET_PATH", is_secret=True))
