# Copyright 2024 Google LLC
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
# pylint: disable=g-importing-member
# pylint: disable=invalid-name
# pylint: disable=g-multiple-import
# pylint: disable=unused-argument
"""Unit tests for the teamcymru client script."""

import unittest
from unittest.mock import MagicMock, Mock, patch

import requests
import requests.adapters

from teamcymru_scout_client import TeamCymruScoutClient, divide_chunks
from teamcymru_scout_constants import Endpoints, Rest

INGESTION_SCRIPTS_PATH = ""


class CustomHTTPError(requests.exceptions.HTTPError):
  def __init__(self, status_code, method, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.response = Mock()
    self.response.status_code = status_code
    self.request = Mock()
    self.request.method = method


class TestTeamCymruScoutClient(unittest.TestCase):
  """Test cases for the teamcymru client script."""

  def test_divide_chunks(self):
    """Test case for the divide_chunks function."""
    input_list = list(range(10))
    chunk_size = 3
    expected_output = [
        list(range(3)),
        list(range(3, 6)),
        list(range(6, 9)),
        [9],
    ]
    actual_output = list(divide_chunks(input_list, chunk_size))
    self.assertEqual(actual_output, expected_output)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_session(self, mock_session, mock_cloud_logging):
    """Test case for the __get_session method."""
    mock_session_instance = Mock()
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    session = client._TeamCymruScoutClient__get_session(
        retries=3,
        backoff_factor=60,
        status_forcelist=Rest.STATUS_FORCELIST,
        allowed_methods=["GET", "POST", "HEAD"],
    )
    self.assertEqual(session, mock_session_instance)
    mock_cloud_logging.assert_called_with(
        "Session initialized with retries=3, "
        "backoff_factor=60, "
        f"status_forcelist={Rest.STATUS_FORCELIST}, "
        f"allowed_methods=['GET', 'POST', 'HEAD']",
        severity="DEBUG",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get(self, mock_session, mock_cloud_logging):
    """Test case for the get method."""
    mock_response = Mock()
    mock_response.json.return_value = {"data": "response"}
    mock_response.status_code = 200
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    response = client.get(Endpoints.USAGE)
    self.assertEqual(response, {"data": "response"})
    mock_cloud_logging.assert_called_with(
        "HttpRequest, "
        "type=Get, "
        f"url={Endpoints.USAGE}, "
        f"status={mock_response.status_code}",
        severity="DEBUG",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_proxy_error(self, mock_session, mock_cloud_logging):
    """Test case for the get method when it encounters a ProxyError."""
    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = requests.exceptions.ProxyError(
        "Proxy error"
    )
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    with self.assertRaises(requests.exceptions.ProxyError):
      client.get(Endpoints.USAGE)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_ssl_error(self, mock_session, mock_cloud_logging):
    """Test case for the get method when it encounters an SSLError."""
    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = requests.exceptions.SSLError(
        "SSL error"
    )
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    with self.assertRaises(requests.exceptions.SSLError):
      client.get(Endpoints.USAGE)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_connection_error(self, mock_session, mock_cloud_logging):
    """Test case for the get method when it encounters a ConnectionError."""
    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = requests.exceptions.ConnectionError(
        "Connection error"
    )  # noqa:E501  # noqa:E501
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    with self.assertRaises(requests.exceptions.ConnectionError):
      client.get(Endpoints.USAGE)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_http_error(self, mock_session, mock_cloud_logging):
    """Test case for the get method when it encounters an HTTPError."""
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=Mock(status_code=401)
    )  # noqa:E501  # noqa:E501
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    with self.assertRaises(requests.exceptions.HTTPError):
      client.get(Endpoints.USAGE)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_usage(self, mock_session, mock_cloud_logging):
    """Test case for the get_usage method."""
    mock_response = Mock()
    mock_response.json.return_value = {"data": "usage"}
    mock_response.status_code = 200
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    response = client.get_usage()
    self.assertEqual(response, {"data": "usage"})

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_foundation_ip_data(self, mock_session, mock_cloud_logging):
    """Test case for the get_foundation_ip_data method."""
    mock_response = Mock()
    mock_response.json.return_value = {"data": [{"ip": "1.1.1.1"}]}
    mock_response.status_code = 200
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    ip_data = list(client.get_foundation_ip_data(["1.1.1.1"]))
    self.assertEqual(ip_data, [{"ip": "1.1.1.1"}])

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_details_domain_data(self, mock_session, mock_cloud_logging):
    """Test if get_details_domain_data makes a successful request."""
    mock_response = Mock()
    mock_response.json.return_value = {
        "query": "example.com",
        "ips": [{"data": "domain details"}],
    }
    mock_response.status_code = 200
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {
            "auth_type": "basic_auth",
            "username": "user",
            "password": "pass",
        }  # noqa:E501
    )
    domain_data = list(client.get_details_domain_data(["example.com"]))
    self.assertEqual(
        domain_data, [{"data": "domain details", "query": "example.com"}]
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_details_ip_data(self, mock_session, mock_cloud_logging):
    """Test if get_details_ip_data makes a successful request."""
    mock_response = Mock()
    mock_response.json.return_value = {"data": "ip details"}
    mock_response.status_code = 200
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    ip_data = list(client.get_details_ip_data(["1.1.1.1"]))
    self.assertEqual(ip_data, [{"data": "ip details"}])

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.sys")
  def test_get_details_ip_data_threshold_size(
      self, mock_sys, mock_session, mock_cloud_logging
  ):
    """Test if get_details_ip_data makes a successful request."""
    mock_response = Mock()
    mock_response.json.return_value = {"data": "ip details"}
    mock_response.status_code = 200
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    mock_sys.getsizeof.return_value = 950000
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    list(client.get_details_ip_data(["1.1.1.1"], is_live_investigation=True))
    mock_cloud_logging.assert_called_with(
        "Skipping enrichment for IP 1.1.1.1 due to its response size exceeding the limit of 0.95 MB. "  # pylint: disable=line-too-long
        "Try again by setting a smaller threshold size in the environment variable IP_ENRICHMENT_SIZE.",  # pylint: disable=line-too-long
        severity="WARNING",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_rate_limit_reached(self, mock_session, mock_cloud_logging):
    """Test if get method handles HTTPError correctly for rate limit exceeded."""  # pylint: disable=line-too-long
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=Mock(status_code=429)
    )  # noqa:E501  # noqa:E501
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    # Expect HTTPError to be raised
    with self.assertRaises(requests.exceptions.HTTPError):
      # Make a request to the IP details endpoint
      client.get(Endpoints.IP_DETAILS)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_other_http_error(self, mock_session, mock_cloud_logging):
    """Test if get method handles HTTPError correctly for status code other than 429."""  # pylint: disable=line-too-long
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=Mock(status_code=402)
    )  # noqa:E501  # noqa:E501
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "api_key", "api_key": "key"}
    )  # noqa:E501
    with self.assertRaises(requests.exceptions.HTTPError):
      client.get(Endpoints.USAGE)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_other_exception(self, mock_session, mock_cloud_logging):
    """Test if get method handles other exceptions correctly."""
    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = Exception("Test Exception")
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    with self.assertRaises(Exception):
      client.get(Endpoints.USAGE)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_session_incase_of_no_retry(
      self, mock_session, mock_cloud_logging
  ):  # noqa:E501
    """Test case for the get_session method when retry is set to False."""
    mock_response = Mock()
    mock_response.json.return_value = {"data": [{"ip": "1.1.1.1"}]}
    mock_response.status_code = 200
    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    client.get_usage(retry=False)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  @patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  def test_get_session_incase_of_no_retry_with_exception(
      self, mock_session, mock_cloud_logging
  ):
    """Test case for the get_session method when retry is set to False and an exception is raised."""
    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = Exception("Test Exception")
    mock_session.return_value = mock_session_instance
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    with self.assertRaises(Exception):
      client.get_usage(retry=False)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  def test_get_foundation_ip_data_success(self, mock_cloud_logging):
    """Test case for get_foundation_ip_data when successful."""
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    ip_list = ["1.2.3.4", "5.6.7.8"]
    client.get = MagicMock(
        return_value={"data": ["foundation_data_1", "foundation_data_2"]}
    )
    result = list(client.get_foundation_ip_data(ip_list))
    self.assertEqual(result, ["foundation_data_1", "foundation_data_2"])
    mock_cloud_logging.assert_called_with(
        "Started collecting IP Foundation data.", severity="INFO"
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  def test_get_foundation_ip_data_exception(self, mock_cloud_logging):
    """Test case for the get_foundation_ip_data method when an exception occurs."""
    # Setup
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    ip_list = ["1.2.3.4", "5.6.7.8"]
    client.get = MagicMock(side_effect=Exception("Error occurred"))

    # Exercise
    # Assert
    with self.assertRaises(Exception):
      list(client.get_foundation_ip_data(ip_list))

    # Verify that the correct error message and severity level are logged
    mock_cloud_logging.assert_called_with(
        "Error occurred while getting foundation IP data: Error occurred",
        severity="ERROR",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  def test_get_details_domain_data_empty_list(self, mock_cloud_logging):
    """Test case for the get_details_domain_data method when an empty list is provided."""
    # Setup
    client = TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    domain_list = []  # Empty list of domains

    # Execute
    result = list(client.get_details_domain_data(domain_list))

    # Assert
    self.assertEqual(result, [])  # Expected result is an empty list

  def test_get_details_domain_data_single_domain(self):
    """Test case for the get_details_domain_data method when a single domain is provided.
    """  # noqa:E501
    # Setup
    client = TeamCymruScoutClient(
        {
            "auth_type": "basic_auth",
            "username": "user",
            "password": "pass",
        }  # noqa:E501
    )
    domain_list = ["example.com"]  # Single domain
    client.get = Mock(
        return_value={
            "query": "example.com",
            "ips": [{"data": "Domain Details for example.com"}],
        }  # noqa:E501
    )

    # Execute
    # Call the method with the single domain
    result = list(client.get_details_domain_data(domain_list))

    # Assert
    # Verify that the result is an array with the expected data
    self.assertEqual(
        result,
        [{"data": "Domain Details for example.com", "query": "example.com"}]
    )

  def test_get_details_domain_data_multiple_domains(self):
    """Test case for the get_details_domain_data method when multiple domains are provided."""
    # Setup
    client = TeamCymruScoutClient(
        {
            "auth_type": "basic_auth",
            "username": "user",
            "password": "pass",
        }  # noqa:E501
    )
    domain_list = ["example1.com", "example2.com", "example3.com"]
    client.get = Mock(
        side_effect=[
            {"query": "example1.com",
             "ips": [{"data": "Domain Details for ip"}]},
            {"query": "example2.com",
             "ips": [{"data": "Domain Details for ip"}]},
            {"query": "example3.com",
             "ips": [{"data": "Domain Details for ip"}]},
        ]
    )

    result = list(client.get_details_domain_data(domain_list))

    expected_result = [
        {"data": "Domain Details for ip", "query": "example1.com"},
        {"data": "Domain Details for ip", "query": "example2.com"},
        {"data": "Domain Details for ip", "query": "example3.com"},
    ]
    self.assertEqual(result, expected_result)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  def test_get_domain_data_exception(self, mock_cloud_logging):
    """Test case for the get_details_domain_data method when an exception occurs."""
    client = TeamCymruScoutClient(
        {
            "auth_type": "basic_auth",
            "username": "user",
            "password": "pass",
        }  # noqa:E501
    )
    # Set the IP list to a single domain
    ip_list = ["example.com"]
    # Mock the get function to raise an exception
    client.get = MagicMock(side_effect=Exception("Error occurred"))

    # Execute
    # Call the method with the single domain
    with self.assertRaises(Exception):
      list(client.get_details_domain_data(ip_list))

    # Assert
    # Verify that the correct error message and severity level are logged
    mock_cloud_logging.assert_called_with(
        "Error occurred while getting domain details data: Error occurred",
        severity="ERROR",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.utils.cloud_logging"
  )  # noqa:E501
  def test_get_details_ip_data_exception(self, mock_cloud_logging):
    """Test case for the get_details_ip_data method when an exception occurs."""
    client = TeamCymruScoutClient(
        {
            "auth_type": "basic_auth",
            "username": "user",
            "password": "pass",
        }
    )
    # Set the IP list to two IP addresses
    ip_list = ["10.0.0.1"]
    # Mock the get function to raise an exception
    client.get = MagicMock(side_effect=Exception("Error occurred"))

    list(client.get_details_ip_data(ip_list))

    # Verify that the correct error message and severity level are logged
    mock_cloud_logging.assert_called_with(
        "Skipping 10.0.0.1 from enrichment due to an unexpected "
        "issue has occurred while getting IP details: Error occurred",
        severity="WARNING",
    )
