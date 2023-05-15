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
"""Unit test case file for main module of AzureEventHub script."""
import sys
import unittest
from unittest import mock

INGESTION_SCRIPTS_PATH = ""
SCRIPT_PATH = ""

# CONSTANTS.
ENV_VARS = ["AZURE_AD"]

sys.modules[f"{INGESTION_SCRIPTS_PATH}common.ingest"] = mock.MagicMock()
sys.modules[f"{INGESTION_SCRIPTS_PATH}common.utils"] = mock.MagicMock()

import main


class TestEventHubToChronicleIngestion(unittest.TestCase):
  """Test cases for Azure EventHub ingestion script."""

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  def test_ingestion_successful(self, mock_ingest, mock_utils):
    """Test case to verify for successful ingestion of logs."""
    mock_utils.get_env_var.side_effect = ENV_VARS

    events = [mock.MagicMock()]
    events[0].get_body.return_value = b'{"records": []}'
    main.main(events)
    assert mock_ingest.call_count == 1

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  def test_json_decode_error(self, mock_utils):
    """Test case to verify json loads for failure."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    events = [mock.MagicMock()]
    events[0].get_body.return_value = b'{"records": [}'
    with self.assertRaises(RuntimeError) as error:
      main.main(events)

    self.assertEqual(
        str(error.exception),
        "The log data from Azure EventHub is not JSON serializable.",
    )

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  def test_list_data_parsing(self, mock_ingest, mock_utils):
    """Test case to verify json loads for failure."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    events = [mock.MagicMock()]
    events[0].get_body.return_value = b'{"records": ["e1", "e2", "e3"]}'
    main.main(events)
    args, kwargs = mock_ingest.call_args  # pylint: disable=unused-variable

    events_expected = ["e1", "e2", "e3"]
    assert mock_ingest.call_count == 1
    self.assertEqual(
        args[0], events_expected
    )

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  def test_str_data_parsing(self, mock_ingest, mock_utils):
    """Test case to verify json loads for failure."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    events = [mock.MagicMock()]
    events[0].get_body.return_value = b'{"records": "e1"}'
    main.main(events)
    args, kwargs = mock_ingest.call_args  # pylint: disable=unused-variable

    events_expected = ["e1"]
    assert mock_ingest.call_count == 1
    self.assertEqual(
        args[0], events_expected
    )

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  def test_ingest_for_error(self, mock_ingest, mock_utils):
    """Test case to verify error is raised for failure in ingest."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_ingest.ingest.side_effect = Exception("Custom error for testing")
    events = [mock.MagicMock()]
    events[0].get_body.return_value = b'{"records": []}'

    with self.assertRaises(Exception) as error:
      main.main(events)

    self.assertEqual(
        str(error.exception),
        "Unable to push the data to the Chronicle. Error: Custom error for"
        " testing",
    )
