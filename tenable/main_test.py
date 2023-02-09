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
"""Unit test case file for main module of Tenable ingestion script."""

import sys

import unittest
from unittest import mock

INGESTION_SCRIPTS_PATH = ""
SCRIPT_PATH = ""

# Mock the chronicle library
sys.modules[f"{INGESTION_SCRIPTS_PATH}common.ingest"] = mock.MagicMock()

import main

# Message for ingestion completed.
INGESTION_COMPLETE = "Ingestion completed."


class TestTenableIngestion(unittest.TestCase):
  """Test cases for Tenable ingestion script."""

  def test_validate_params_for_invalid_arguments(self):
    """Test case to verify that the client should raise InvalidValueError when invalid parameters provided.
    """
    self.assertRaises(main.InvalidValueError, main.validate_params, ["op"],
                      ["assets"])
    self.assertRaises(main.InvalidValueError, main.validate_params, ["open"],
                      ["dummy"])

  def test_valid_params_success(self):
    """Test case to verify for correct parameters."""
    assert main.validate_params(["open"], ["assets"]) is None

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  def test_get_and_ingest_assets_for_success(self, mock_ingest):
    """Test case to verify function get_and_ingest_events for success."""
    client = mock.MagicMock()
    client.exports.assets.return_value = ["mock"]

    assert main.get_and_ingest_assets(client) is None
    assert mock_ingest.ingest.call_count == 1

  def test_get_and_ingest_assets_for_invalid_credentials(self):
    """Test case to verify get_and_ingest_events for invalid credentials."""
    client = mock.MagicMock()
    client.exports.assets.side_effect = main.errors.UnauthorizedError(
        mock.MagicMock())

    with self.assertRaises(RuntimeError):
      main.get_and_ingest_assets(client)

  def test_get_and_ingest_assets_for_export_error(self):
    """Test case to verify get_and_ingest_events for exports error."""
    client = mock.MagicMock()
    client.exports.assets.side_effect = main.errors.TioExportsError(
        mock.MagicMock(), mock.MagicMock())

    with self.assertRaises(RuntimeError):
      main.get_and_ingest_assets(client)

  def test_get_and_ingest_assets_for_exception(self):
    """Test case to verify get_and_ingest_events for Exception."""
    tio = mock.MagicMock()
    tio.exports.assets.side_effect = Exception()

    with self.assertRaises(Exception):
      main.get_and_ingest_assets(tio)

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  def test_get_and_ingest_assets_for_failure(self, mock_ingest):
    """Test case to verify get_and_ingest_events for failure."""
    client = mock.MagicMock()
    client.exports.assets.return_value = ["mock"]
    mock_ingest.ingest.side_effect = Exception()

    with self.assertRaises(RuntimeError):
      main.get_and_ingest_assets(client)

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  def test_get_and_ingest_vulnerabilities_for_success(self, mock_ingest):
    """Test case to verify get_and_ingest_vulnerabilities for success."""
    client = mock.MagicMock()
    client.exports.vulns.return_value = ["vulnerabilities"]

    assert main.get_and_ingest_vulnerabilities(client, ["open"]) is None
    assert mock_ingest.ingest.call_count == 1

  def test_get_and_ingest_vulnerabilities_for_invalid_credentials(self):
    """Test case to verify get_and_ingest_vulnerabilities for invalid credentials.
    """
    client = mock.MagicMock()
    client.exports.vulns.side_effect = main.errors.UnauthorizedError(
        mock.MagicMock())

    with self.assertRaises(RuntimeError):
      main.get_and_ingest_vulnerabilities(client, ["dummy"])

  def test_get_and_ingest_vulnerabilities_for_exports_error(self):
    """Test case to verify get_and_ingest_vulnerabilities for exports error."""
    client = mock.MagicMock()
    client.exports.vulns.side_effect = main.errors.TioExportsError(
        mock.MagicMock(), mock.MagicMock())

    with self.assertRaises(RuntimeError):
      main.get_and_ingest_vulnerabilities(client, ["dummy"])

  def test_get_and_ingest_vulnerabilities_for_exception(self):
    """Test case to verify get_and_ingest_vulnerabilities for Exception."""
    tio = mock.MagicMock()
    tio.exports.vulns.side_effect = Exception()

    with self.assertRaises(Exception):
      main.get_and_ingest_vulnerabilities(tio, ["dummy"])

  @mock.patch(f"{SCRIPT_PATH}main.ingest")
  def test_get_and_ingest_vulnerabilities_for_failure(self, mock_ingest):
    """Test case to verify get_and_ingest_events for failure."""
    client = mock.MagicMock()
    client.exports.vulns.return_value = ["dummy"]
    mock_ingest.ingest.side_effect = Exception()

    with self.assertRaises(RuntimeError):
      main.get_and_ingest_vulnerabilities(client, ["dummy"])

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_assets")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_vulnerabilities")
  def test_main_for_assets(
      self,
      mock_get_and_ingest_vulnerabilities,
      mock_get_and_ingest_assets,
      mock_utils,
  ):
    """Test case to verify that only assets function is called when data type is assets.
    """
    mock_utils.get_env_var.side_effect = [
        "access_key", "secret_key", "assets", "open"
    ]
    mock_request = mock.MagicMock()

    assert main.main(mock_request) == INGESTION_COMPLETE
    assert mock_get_and_ingest_assets.call_count == 1
    assert mock_get_and_ingest_vulnerabilities.call_count == 0

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_vulnerabilities")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_assets")
  def test_main_for_vulnerabilities(
      self,
      mock_get_and_ingest_assets,
      mock_get_and_ingest_vulnerabilities,
      mock_utils,
  ):
    """Test case to verify that only vulnerabilities function is called when data type is vulnerabilities.
    """
    mock_utils.get_env_var.side_effect = [
        "access_key", "secret_key", "vulnerabilities", "open"
    ]
    mock_request = mock.MagicMock()

    assert main.main(mock_request) == INGESTION_COMPLETE
    assert mock_get_and_ingest_vulnerabilities.call_count == 1
    assert mock_get_and_ingest_assets.call_count == 0

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_vulnerabilities")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_assets")
  def test_main_for_assets_and_vulnerabilities(
      self,
      mock_get_and_ingest_assets,
      mock_get_and_ingest_vulnerabilities,
      mock_utils,
  ):
    """Test case to verify that both assets and vulnerabilities function is called when both the data types are provided.
    """
    mock_utils.get_env_var.side_effect = [
        "access_key", "secret_key", "assets, vulnerabilities", "open"
    ]
    mock_request = mock.MagicMock()

    assert main.main(mock_request) == INGESTION_COMPLETE
    assert mock_get_and_ingest_vulnerabilities.call_count == 1
    assert mock_get_and_ingest_assets.call_count == 1

  @mock.patch(f"{SCRIPT_PATH}main.utils.get_env_var")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_vulnerabilities")
  @mock.patch(f"{SCRIPT_PATH}main.get_and_ingest_assets")
  @mock.patch(f"{SCRIPT_PATH}main.validate_params")
  def test_get_env_for_secret(
      self,
      mocked_validate_params,
      unused_mock_get_and_ingest_assets,
      unused_mock_get_and_ingest_vulnerabilities,
      mocked_get_env_var,
  ):
    """Test case to verify that validate_params() is called once, and get_env_var called with valid parameters.
    """
    mock_request = mock.MagicMock()

    main.main(mock_request)
    expected_mock_calls = [
        mock.call("TENABLE_ACCESS_KEY"),
        mock.call("TENABLE_SECRET_KEY_PATH", is_secret=True),
        mock.call(
            "TENABLE_DATA_TYPE",
            required=False,
            default=main.DEFAULT_TENABLE_DATA_TYPE),
        mock.call(
            "TENABLE_VULNERABILITY",
            required=False,
            default=main.DEFAULT_TENABLE_VULNERABILITY)
    ]
    assert mocked_get_env_var.mock_calls[:4] == expected_mock_calls
    assert mocked_validate_params.call_count == 1
