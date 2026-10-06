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
# pylint: disable=redefined-outer-name

"""Unit tests for greynoise_client module."""

import unittest
from unittest import mock
import sys

# Mock google modules needed by common.utils
mock_google = mock.MagicMock()
mock_cloud = mock.MagicMock()
mock_secretmanager = mock.MagicMock()
mock_google.cloud = mock_cloud
mock_cloud.secretmanager = mock_secretmanager
sys.modules["google"] = mock_google
sys.modules["google.cloud"] = mock_cloud
sys.modules["google.cloud.secretmanager"] = mock_secretmanager


import greynoise_client
import constant
INGESTION_SCRIPTS_PATH = ""


class TestGreyNoiseUtility(unittest.TestCase):
  """Test cases for GreyNoiseUtility class."""

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(api, "GreyNoise", autospec=True)
  @mock.patch.object(api, "APIConfig", autospec=True)
  def test_initialization(self, mock_api_config, mock_greynoise, mock_log):
    """Test GreyNoiseUtility initialization."""
    api_key = "test_api_key_12345"
    mock_config_instance = mock.Mock()
    mock_api_config.return_value = mock_config_instance
    mock_client_instance = mock.Mock()
    mock_greynoise.return_value = mock_client_instance

    utility = greynoise_client.GreyNoiseUtility(api_key)

    # Verify APIConfig was called with correct parameters
    mock_api_config.assert_called_once_with(
        api_key=api_key,
        integration_name=constant.GREYNOISE_INTEGRATION_NAME,
    )

    # Verify GreyNoise client was initialized
    mock_greynoise.assert_called_once_with(mock_config_instance)

    # Verify logging was called
    mock_log.assert_called_once_with("GreyNoise Client Initialized.")

    # Verify instance attributes
    self.assertEqual(utility.api_config, mock_config_instance)
    self.assertEqual(utility.greynoise_client, mock_client_instance)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(api, "GreyNoise", autospec=True)
  @mock.patch.object(api, "APIConfig", autospec=True)
  def test_gnql_query_default_parameters(
      self, mock_api_config, mock_greynoise, mock_log
  ):
    """Test gnql_query with default parameters."""
    mock_client = mock.Mock()
    mock_greynoise.return_value = mock_client
    mock_response = {
        "data": [{"ip": "1.2.3.4"}],
        "request_metadata": {"complete": True},
    }
    mock_client.query.return_value = mock_response

    utility = greynoise_client.GreyNoiseUtility("test_key")
    query = "classification:malicious"
    result = utility.gnql_query(query)

    # Verify query was called with correct parameters
    mock_client.query.assert_called_once_with(
        query,
        exclude_raw=True,
        size=constant.GNQL_PAGE_SIZE,
        scroll=None,
    )
    self.assertEqual(result, mock_response)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(api, "GreyNoise", autospec=True)
  @mock.patch.object(api, "APIConfig", autospec=True)
  def test_gnql_query_with_scroll(
      self, mock_api_config, mock_greynoise, mock_log
  ):
    """Test gnql_query with scroll parameter."""
    mock_client = mock.Mock()
    mock_greynoise.return_value = mock_client
    mock_response = {
        "data": [{"ip": "1.2.3.4"}],
        "request_metadata": {"complete": False, "scroll": "next_token"},
    }
    mock_client.query.return_value = mock_response

    utility = greynoise_client.GreyNoiseUtility("test_key")
    query = "classification:malicious"
    scroll_token = "scroll_token_123"
    result = utility.gnql_query(query, scroll=scroll_token)

    # Verify query was called with scroll parameter
    mock_client.query.assert_called_once_with(
        query,
        exclude_raw=True,
        size=constant.GNQL_PAGE_SIZE,
        scroll=scroll_token,
    )
    self.assertEqual(result, mock_response)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(api, "GreyNoise", autospec=True)
  @mock.patch.object(api, "APIConfig", autospec=True)
  def test_gnql_query_with_custom_page_size(
      self, mock_api_config, mock_greynoise, mock_log
  ):
    """Test gnql_query with custom page size."""
    mock_client = mock.Mock()
    mock_greynoise.return_value = mock_client
    mock_response = {"data": [], "request_metadata": {"complete": True}}
    mock_client.query.return_value = mock_response

    utility = greynoise_client.GreyNoiseUtility("test_key")
    query = "classification:malicious"
    custom_page_size = 500
    result = utility.gnql_query(query, page_size=custom_page_size)

    # Verify query was called with custom page size
    mock_client.query.assert_called_once_with(
        query,
        exclude_raw=True,
        size=custom_page_size,
        scroll=None,
    )
    self.assertEqual(result, mock_response)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(api, "GreyNoise", autospec=True)
  @mock.patch.object(api, "APIConfig", autospec=True)
  def test_gnql_query_with_all_parameters(
      self, mock_api_config, mock_greynoise, mock_log
  ):
    """Test gnql_query with all parameters specified."""
    mock_client = mock.Mock()
    mock_greynoise.return_value = mock_client
    mock_response = {"data": [], "request_metadata": {"complete": True}}
    mock_client.query.return_value = mock_response

    utility = greynoise_client.GreyNoiseUtility("test_key")
    query = "classification:malicious"
    scroll_token = "scroll_123"
    page_size = 250

    result = utility.gnql_query(
        query, scroll=scroll_token, page_size=page_size
    )

    # Verify query was called with all parameters
    mock_client.query.assert_called_once_with(
        query,
        exclude_raw=True,
        size=page_size,
        scroll=scroll_token,
    )
    self.assertEqual(result, mock_response)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(api, "GreyNoise", autospec=True)
  @mock.patch.object(api, "APIConfig", autospec=True)
  def test_lookup_ips_single_ip(
      self, mock_api_config, mock_greynoise, mock_log
  ):
    """Test lookup_ips with a single IP address."""
    mock_client = mock.Mock()
    mock_greynoise.return_value = mock_client
    mock_response = [
        {
            "ip": "1.2.3.4",
            "internet_scanner_intelligence": {"found": True},
        }
    ]
    mock_client.ip_multi.return_value = mock_response

    utility = greynoise_client.GreyNoiseUtility("test_key")
    ip_list = ["1.2.3.4"]
    result = utility.lookup_ips(ip_list)

    # Verify ip_multi was called correctly
    mock_client.ip_multi.assert_called_once_with(
        ip_list, include_invalid=True
    )
    self.assertEqual(result, mock_response)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(api, "GreyNoise", autospec=True)
  @mock.patch.object(api, "APIConfig", autospec=True)
  def test_lookup_ips_multiple_ips(
      self, mock_api_config, mock_greynoise, mock_log
  ):
    """Test lookup_ips with multiple IP addresses."""
    mock_client = mock.Mock()
    mock_greynoise.return_value = mock_client
    mock_response = [
        {
            "ip": "1.2.3.4",
            "internet_scanner_intelligence": {"found": True},
        },
        {
            "ip": "5.6.7.8",
            "internet_scanner_intelligence": {"found": True},
        },
    ]
    mock_client.ip_multi.return_value = mock_response

    utility = greynoise_client.GreyNoiseUtility("test_key")
    ip_list = ["1.2.3.4", "5.6.7.8"]
    result = utility.lookup_ips(ip_list)

    # Verify ip_multi was called correctly
    mock_client.ip_multi.assert_called_once_with(
        ip_list, include_invalid=True
    )
    self.assertEqual(result, mock_response)

  @mock.patch.object(utils, "cloud_logging")
  @mock.patch.object(api, "GreyNoise", autospec=True)
  @mock.patch.object(api, "APIConfig", autospec=True)
  def test_lookup_ips_empty_list(
      self, mock_api_config, mock_greynoise, mock_log
  ):
    """Test lookup_ips with empty IP list."""
    mock_client = mock.Mock()
    mock_greynoise.return_value = mock_client
    mock_response = []
    mock_client.ip_multi.return_value = mock_response

    utility = greynoise_client.GreyNoiseUtility("test_key")
    ip_list = []
    result = utility.lookup_ips(ip_list)

    # Verify ip_multi was called even with empty list
    mock_client.ip_multi.assert_called_once_with(
        ip_list, include_invalid=True
    )
    self.assertEqual(result, mock_response)

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}greynoise_client.utils.cloud_logging",
      autospec=True,
  )
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}greynoise_client.api.GreyNoise", autospec=True
  )
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}greynoise_client.api.APIConfig", autospec=True
  )
  def test_lookup_ips_include_invalid_flag(
      self, mock_api_config, mock_greynoise, mock_log
  ):
    """Test that lookup_ips always includes invalid IPs."""
    mock_client = mock.Mock()
    mock_greynoise.return_value = mock_client
    mock_response = [{"ip": "invalid_ip", "error": "Invalid IP address"}]
    mock_client.ip_multi.return_value = mock_response

    utility = greynoise_client.GreyNoiseUtility("test_key")
    ip_list = ["invalid_ip"]
    result = utility.lookup_ips(ip_list)

    # Verify include_invalid is always True
    mock_client.ip_multi.assert_called_once_with(
        ip_list, include_invalid=True
    )
    self.assertEqual(result, mock_response)


if __name__ == "__main__":
  unittest.main()
