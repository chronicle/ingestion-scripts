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
# pylint: disable=g-bad-import-order
# pylint: disable=g-import-not-at-top
# pylint: disable=unused-argument
# pylint: disable=line-too-long
# pylint: disable=invalid-name
"""Unittest cases for main."""

import datetime
import os
import requests
import sys
import unittest
from unittest import mock

import fetch_logs
import teamcymru_scout_client
import teamcymru_scout_env_constants

INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest"] = mock.Mock()

os.environ["REDIS_HOST"] = "1.2.3.4"
os.environ["REDIS_PORT"] = "1234"

import main

rate_limit_usage = {
    "used_queries": 50000,
    "remaining_queries": 0,
    "query_limit": 50000
}


class TestTeamCymruScoutIngestion(unittest.TestCase):
  """Test cases for the teamcymru scout logs ingestion script."""  # noqa:E501

  def test_check_valid_arguments_true(self):
    """Test case for check_valid_arguments function when argument value is True."""  # pylint: disable=line-too-long
    with mock.patch(
        f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging"
    ) as mock_cloud_logging:  # noqa:E501
      argument_name = "test_arg"
      argument_value = "True"
      result = main.check_valid_arguments(argument_name, argument_value)
      self.assertTrue(result)
      mock_cloud_logging.assert_not_called()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_check_valid_arguments_false(self, mock_cloud_logging):
    """Test case for check_valid_arguments function when argument value is False."""  # pylint: disable=line-too-long
    argument_name = "test_arg"
    argument_value = "False"
    result = main.check_valid_arguments(argument_name, argument_value)
    self.assertFalse(result)
    mock_cloud_logging.assert_not_called()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_check_valid_arguments_invalid(self, mock_cloud_logging):
    """Test case for check_valid_arguments function when argument value is invalid."""  # pylint: disable=line-too-long
    argument_name = "test_arg"
    argument_value = "Invalid"
    result = main.check_valid_arguments(argument_name, argument_value)
    self.assertFalse(result)
    mock_cloud_logging.assert_called_once_with(
        f"Please provide boolean value for {argument_name} argument. "
        "Default value will be considered as False.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_add_ips_to_redis_success(
      self, mock_cloud_logging, mock_client, mock_get_env_var
  ):
    """Test case for add_ips_to_redis function when all operations are successful."""  # pylint: disable=line-too-long
    mock_get_env_var.return_value = "30"
    mock_redis_client = mock.Mock()
    mock_client.hset = mock_redis_client.hset
    mock_client.expire = mock_redis_client.expire
    redis_ips_list = [{"value": "192.168.1.1", "data": "some_data"}]

    main.add_ips_to_redis(redis_ips_list)

    mock_get_env_var.assert_called_once_with(
        teamcymru_scout_env_constants.ENV_PROVISIONAL_TTL,
        required=False,
        default="30",
    )
    mock_redis_client.hset.assert_called_once_with(
        "192.168.1.1", mapping={"value": "192.168.1.1", "data": "some_data"}
    )
    mock_redis_client.expire.assert_called_once_with("192.168.1.1", 30 * 86400)
    mock_cloud_logging.assert_not_called()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_add_ips_to_redis_redis_exception(
      self, mock_cloud_logging, mock_client, mock_get_env_var
  ):
    """Test case for add_ips_to_redis function when Redis error occurs."""
    mock_get_env_var.return_value = "30"
    mock_redis_client = mock.Mock()
    mock_client.hset = mock_redis_client.hset
    mock_client.expire = mock_redis_client.expire
    mock_redis_client.hset.side_effect = Exception("Redis error")
    redis_ips_list = [{"value": "192.168.1.1", "data": "some_data"}]

    with self.assertRaises(Exception) as context:
      main.add_ips_to_redis(redis_ips_list)

    self.assertEqual(str(context.exception), "Redis error")
    mock_get_env_var.assert_called_once_with(
        teamcymru_scout_env_constants.ENV_PROVISIONAL_TTL,
        required=False,
        default="30",
    )
    mock_redis_client.hset.assert_called_once_with(
        "192.168.1.1", mapping={"value": "192.168.1.1", "data": "some_data"}
    )
    mock_cloud_logging.assert_called_once_with(
        "Error occurred while storing enriched ip in the memory "
        "store. Error: Redis error",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_ips_to_redis")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_ingest_into_chronicle_with_enriched_events(
      self, mock_cloud_logging, mock_add_ips_to_redis, mock_ingest
  ):
    """Test case for ingest_into_chronicle function when all operations are successful."""
    enriched_events = [{"event": "event_data"}]
    event_type = "test_event"
    redis_ip_list = [{"value": "1.1.1.1"}]

    response = main.ingest_into_chronicle(
        enriched_events, event_type, redis_ip_list
    )

    mock_ingest.assert_called_once_with(
        enriched_events,
        teamcymru_scout_env_constants.CHRONICLE_DATA_TYPE,
    )
    mock_cloud_logging.assert_any_call(
        f"Enriched {event_type} data successfully ingested into Chronicle."
    )
    mock_add_ips_to_redis.assert_called_once_with(redis_ip_list)
    self.assertEqual(response, f"Ingestion for {event_type} is completed\n")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_ingest_into_chronicle_with_no_enriched_events(
      self, mock_cloud_logging, mock_ingest
  ):
    """Test case for ingest_into_chronicle function when no enriched events are present."""
    enriched_events = []
    event_type = "test_event"

    response = main.ingest_into_chronicle(enriched_events, event_type)

    mock_ingest.assert_not_called()
    mock_cloud_logging.assert_any_call(
        f"No enriched {event_type} data to ingest into Chronicle.",
        severity="INFO",
    )
    self.assertEqual(
        response,
        f"Ingestion for {event_type} is completed with no enriched data\n"
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_ips_to_redis")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_ingest_into_chronicle_with_add_ips_to_redis_exception(
      self, mock_cloud_logging, mock_add_ips_to_redis, mock_ingest
  ):
    """Test case for ingest_into_chronicle function when Redis error occurs."""
    enriched_events = [{"event": "event_data"}]
    event_type = "test_event"
    redis_ip_list = [{"value": "1.1.1.1"}]
    mock_add_ips_to_redis.side_effect = Exception("Redis error")

    response = main.ingest_into_chronicle(
        enriched_events, event_type, redis_ip_list
    )

    mock_ingest.assert_called_once_with(
        enriched_events,
        teamcymru_scout_env_constants.CHRONICLE_DATA_TYPE,
    )
    mock_cloud_logging.assert_any_call(
        f"Enriched {event_type} data successfully ingested into Chronicle."
    )
    self.assertEqual(
        response,
        f"Ingestion for {event_type} is completed but error "
        "occurred while storing enriched IPs in Redis.\n",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_ingest_into_chronicle_with_ingestion_exception(
      self, mock_cloud_logging, mock_ingest
  ):
    """Test case for ingest_into_chronicle function when ingestion error occurs."""  # pylint: disable=line-too-long
    enriched_events = [{"event": "event_data"}]
    event_type = "test_event"
    mock_ingest.side_effect = Exception("Ingestion error")

    response = main.ingest_into_chronicle(enriched_events, event_type)

    mock_ingest.assert_called_once_with(
        enriched_events,
        teamcymru_scout_env_constants.CHRONICLE_DATA_TYPE,
    )
    mock_cloud_logging.assert_any_call(
        "Error occurred while ingesting enriched test_event data: "
        "Ingestion error",
        severity="ERROR",
    )
    self.assertEqual(
        response,
        f"Ingestion for {event_type} is not "
        "completed.\n"
    )

  def test_valid_ipv4_address(self):
    """Test case for is_valid_indicator function for IPv4 address."""
    self.assertTrue(main.is_valid_indicator("192.168.0.1", "IP"))

  def test_valid_ipv6_address(self):
    """Test case for is_valid_indicator function for IPv6 address."""
    self.assertTrue(
        main.is_valid_indicator("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "IP")
    )

  def test_invalid_ip_address(self):
    """Test case for is_valid_indicator function for invalid IP address."""
    self.assertFalse(main.is_valid_indicator("999.999.999.999", "IP"))

  def test_valid_domain_name(self):
    """Test case for is_valid_indicator function for valid domain name."""
    self.assertTrue(main.is_valid_indicator("example.com", "DOMAIN"))

  def test_invalid_domain_name(self):
    """Test case for is_valid_indicator function for invalid domain name."""
    self.assertFalse(main.is_valid_indicator("invalid_domain", "DOMAIN"))

  def test_invalid_indicator_type(self):
    """Test case for is_valid_indicator function for invalid indicator type."""
    self.assertFalse(main.is_valid_indicator("example.com", "INVALID"))

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  def test_ip_present_in_cache(self, mock_client):
    """Test case for is_ip_present_in_cache function."""
    mock_client.exists.return_value = "some_value"
    self.assertTrue(main.is_ip_present_in_cache("192.168.0.1"))
    mock_client.exists.assert_called_once_with("192.168.0.1")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  def test_ip_not_present_in_cache(self, mock_client):
    """Test case for is_ip_present_in_cache function."""
    mock_client.exists.return_value = None
    self.assertFalse(main.is_ip_present_in_cache("192.168.0.1"))
    mock_client.exists.assert_called_once_with("192.168.0.1")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  def test_redis_connection_error(self, mock_client):
    """Test case for is_ip_present_in_cache function."""
    mock_client.exists.side_effect = Exception("Connection Error")
    with self.assertRaises(RuntimeError) as context:
      main.is_ip_present_in_cache("192.168.0.1")
    self.assertIn(
        "Error in Connecting to Redis: Connection Error", str(context.exception)
    )
    mock_client.exists.assert_called_once_with("192.168.0.1")

  def test_foundation_rate_limit_exceeded(self):
    """Test case for is_rate_limit_exceeded function."""
    account_usage_details = {
        "used_queries": 5204,
        "remaining_queries": 44796,
        "query_limit": 50000,
        "foundation_api_usage": {
            "used_queries": 60,
            "remaining_queries": 0,
            "query_limit": 60,
        },
    }
    self.assertTrue(
        main.is_rate_limit_exceeded(account_usage_details, "foundation")
    )

  def test_foundation_rate_limit_not_exceeded(self):
    """Test case for is_rate_limit_exceeded function."""
    account_usage_details = {
        "used_queries": 5204,
        "remaining_queries": 44796,
        "query_limit": 50000,
        "foundation_api_usage": {
            "used_queries": 59,
            "remaining_queries": 1,
            "query_limit": 60,
        },
    }
    self.assertFalse(
        main.is_rate_limit_exceeded(account_usage_details, "foundation")
    )

  def test_search_rate_limit_exceeded(self):
    """Test case for is_rate_limit_exceeded function."""
    account_usage_details = {
        "used_queries": 100,
        "remaining_queries": 0,
        "query_limit": 100,
        "foundation_api_usage": {
            "used_queries": 59,
            "remaining_queries": 1,
            "query_limit": 60,
        },
    }
    self.assertTrue(
        main.is_rate_limit_exceeded(account_usage_details, "search")
    )

  def test_search_rate_limit_not_exceeded(self):
    """Test case for is_rate_limit_exceeded function."""
    account_usage_details = {
        "used_queries": 99,
        "remaining_queries": 1,
        "query_limit": 100,
        "foundation_api_usage": {
            "used_queries": 59,
            "remaining_queries": 1,
            "query_limit": 60,
        },
    }
    self.assertFalse(
        main.is_rate_limit_exceeded(account_usage_details, "search")
    )

  def test_generic_rate_limit_exceeded(self):
    """Test case for is_rate_limit_exceeded function."""
    account_usage_details = {
        "used_queries": 100,
        "remaining_queries": 0,
        "query_limit": 100,
        "foundation_api_usage": {
            "used_queries": 59,
            "remaining_queries": 1,
            "query_limit": 60,
        },
    }
    self.assertTrue(main.is_rate_limit_exceeded(account_usage_details))

  def test_generic_rate_limit_not_exceeded(self):
    """Test case for is_rate_limit_exceeded function."""
    account_usage_details = {
        "used_queries": 99,
        "remaining_queries": 1,
        "query_limit": 100,
        "foundation_api_usage": {
            "used_queries": 59,
            "remaining_queries": 1,
            "query_limit": 60,
        },
    }
    self.assertFalse(main.is_rate_limit_exceeded(account_usage_details))

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.is_valid_indicator")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_validate_ip_indicators(
      self,
      mock_cloud_logging,
      mock_is_valid_indicator
  ):
    """Test case for validate_indicators function."""
    indicators = {
        "192.168.0.1": "IP", "256.256.256.256": "IP", "8.8.8.8": "IP"
    }
    mock_is_valid_indicator.side_effect = lambda x, y: x != "256.256.256.256"

    valid_indicators = main.validate_indicators(indicators, "IP")
    expected_valid_indicators = ["192.168.0.1", "8.8.8.8"]

    self.assertEqual(valid_indicators, expected_valid_indicators)
    mock_cloud_logging.assert_called_with(
        "Skipping invalid IP indicator: 256.256.256.256", severity="WARNING"
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.is_valid_indicator")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_validate_domain_indicators(
      self, mock_cloud_logging, mock_is_valid_indicator
  ):
    """Test case for validate_indicators function."""
    indicators = {"example.com": "DOMAIN", "invalid_domain": "DOMAIN"}
    mock_is_valid_indicator.side_effect = lambda x, y: x == "example.com"

    valid_indicators = main.validate_indicators(indicators, "DOMAIN")
    expected_valid_indicators = ["example.com"]

    self.assertEqual(valid_indicators, expected_valid_indicators)
    mock_cloud_logging.assert_called_with(
        "Skipping invalid domain indicator: invalid_domain", severity="WARNING"
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.is_valid_indicator")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_empty_indicators(self, mock_cloud_logging, mock_is_valid_indicator):
    """Test case for validate_indicators function."""
    indicators = {}

    valid_indicators = main.validate_indicators(indicators, "IP")
    self.assertEqual(valid_indicators, [])

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.is_valid_indicator")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_extract_valid_ips_and_domains(
      self, mock_cloud_logging, mock_is_valid_indicator
  ):
    """Test case for extract_ips_and_domains function."""
    data_list = ["192.168.1.1", "example.com", "256.256.256.256", "test.org"]
    mock_is_valid_indicator.side_effect = lambda x, y: (
        x == "192.168.1.1"
        if y == "IP" else x == "example.com" or x == "test.org"
    )

    ips_list, domain_list = main.extract_ips_and_domains(data_list)

    expected_ips_list = ["192.168.1.1"]
    expected_domain_list = ["example.com", "test.org"]

    self.assertEqual(ips_list, expected_ips_list)
    self.assertEqual(domain_list, expected_domain_list)
    mock_cloud_logging.assert_called_with(
        "Skipping invalid indicator 256.256.256.256 "
        "from live investigation which is not an IP or Domain",
        severity="WARNING",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_filter_public_ip_indicators_success(self, mock_cloud_logging):
    """Test case for filter public ip indicators function."""
    data_list = ["8.8.8.8", "100.64.0.0"]
    public_ip_list = main.filter_public_ips(data_list)
    self.assertEqual(public_ip_list, ["8.8.8.8"])
    mock_cloud_logging.assert_called_with(
        "Skipping 100.64.0.0 from enrichment as "
        "it is not a public IP address.",
        severity="INFO",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_filter_public_ip_indicators_failure(self, mock_cloud_logging):
    """Test case for filter public ip indicators function."""
    data_list = ["invalid_ip"]
    public_ip_list = main.filter_public_ips(data_list)
    self.assertEqual(public_ip_list, [])
    mock_cloud_logging.assert_called_once()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.is_valid_indicator")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_no_valid_indicators(
      self,
      mock_cloud_logging,
      mock_is_valid_indicator
  ):
    """Test case for extract_ips_and_domains function."""
    data_list = ["invalid_indicator_1", "invalid_indicator_2"]
    mock_is_valid_indicator.side_effect = lambda x, y: False

    ips_list, domain_list = main.extract_ips_and_domains(data_list)

    self.assertEqual(ips_list, [])
    self.assertEqual(domain_list, [])
    mock_cloud_logging.assert_called_with(
        "Skipping invalid indicator invalid_indicator_2 "
        "from live investigation which is not an IP or Domain",
        severity="WARNING",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.is_valid_indicator")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_all_valid_indicators(
      self,
      mock_cloud_logging,
      mock_is_valid_indicator
  ):
    """Test case for extract_ips_and_domains function."""
    data_list = ["192.168.1.1", "example.com"]
    mock_is_valid_indicator.side_effect = lambda x, y: (
        x == "192.168.1.1" if y == "IP" else x == "example.com"
    )

    ips_list, domain_list = main.extract_ips_and_domains(data_list)

    expected_ips_list = ["192.168.1.1"]
    expected_domain_list = ["example.com"]

    self.assertEqual(ips_list, expected_ips_list)
    self.assertEqual(domain_list, expected_domain_list)
    mock_cloud_logging.assert_not_called()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.is_valid_indicator")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_mixed_valid_and_invalid_indicators(
      self, mock_cloud_logging, mock_is_valid_indicator
  ):
    """Test case for extract_ips_and_domains function."""
    data_list = ["192.168.1.1", "example.com", "invalid_ip", "invalid_domain"]
    mock_is_valid_indicator.side_effect = lambda x, y: (
        x == "192.168.1.1" if y == "IP" else x == "example.com"
    )

    ips_list, domain_list = main.extract_ips_and_domains(data_list)

    expected_ips_list = ["192.168.1.1"]
    expected_domain_list = ["example.com"]

    self.assertEqual(ips_list, expected_ips_list)
    self.assertEqual(domain_list, expected_domain_list)

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.is_ip_present_in_cache", return_value=False
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.TeamCymruScoutClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  def test_main_ip_enrichment(
      self,
      mock_client,
      mock_get_env_var,
      mock_session,
      mock_reference_list,
      mock_is_ip_present_in_cache,
  ):
    """Test case for main function."""
    mock_get_env_var.side_effect = [
        "test-scout",
        "basic_auth",
        "abc",
        "pass",
        "200",
        "malicious",
        "ref_list",
        "false",
    ]
    account_usage = {
        "used_queries": 661,
        "remaining_queries": 49339,
        "query_limit": 50000,
        "foundation_api_usage": {
            "used_queries": 2596,
            "remaining_queries": 7404,
            "query_limit": 10000,
        },
    }
    foundation_detail = [
        {
            "ip": "8.8.8.8",
            "country_code": "",
            "as_info": None,
            "insights": {
                "overall_rating": "suspicious",
                "insights": [
                    {
                        "rating": "suspicious",
                        "message": '8.8.8.8 has been identified as a "bogon", indicating private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598, as well as netblocks that have not been allocated to a Regional Internet Registry (RIR) by the Internet Assigned Numbers Authority.',   # pylint: disable=line-too-long
                    }
                ],
            },
        }
    ]
    enrichment_detail = [
        {
            "request_id": "839f07be-d964-502d-b310-2b2ddb6d6d8e",
            "ip": "8.8.8.8",
            "size": 1000,
            "start_date": "2024-07-06",
            "end_date": "2024-08-04",
        }
    ]
    mock_session.return_value.get_usage.return_value = account_usage
    mock_session.return_value.get_foundation_ip_data.return_value = (
        foundation_detail
    )
    mock_session.return_value.get_details_ip_data.return_value = enrichment_detail  # pylint: disable=line-too-long
    mock_reference_list.return_value = ["8.8.8.8"]
    result = main.main(requests.Request(data='{"ip_enrichment": true}'))
    self.assertEqual(
        result,
        "Ingestion for ip_enrichment is completed\nIngestion for account_usage_details is completed\n",  # pylint: disable=line-too-long
    )

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.is_ip_present_in_cache", return_value=False
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.TeamCymruScoutClient"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  def test_main_live_investigation(
      self,
      mock_client,
      mock_get_env_var,
      mock_session,
      mock_reference_list,
      mock_is_ip_present_in_cache,
  ):
    """Test case for main function."""
    mock_get_env_var.side_effect = [
        "test-scout",
        "api_key",
        "abc",
        "200",
        "suspicious,malicious",
        "ref_list",
    ]
    account_usage = {
        "used_queries": 661,
        "remaining_queries": 49339,
        "query_limit": 50000,
        "foundation_api_usage": {
            "used_queries": 2596,
            "remaining_queries": 7404,
            "query_limit": 10000,
        },
    }
    enrichment_detail = [
        {
            "request_id": "839f07be-d964-502d-b310-2b2ddb6d6d8e",
            "ip": "8.8.8.8",
            "size": 1000,
            "start_date": "2024-07-06",
            "end_date": "2024-08-04",
        }
    ]
    domain_detail = [
        {
            "ip": "93.184.215.14",
            "query": "test.com",
            "country_codes": ["US"],
            "as_info": [{"asn": 15133, "as_name": "EDGECAST, US"}],
        }
    ]

    mock_session.return_value.get_usage.return_value = account_usage
    mock_session.return_value.get_details_ip_data.return_value = enrichment_detail
    mock_session.return_value.get_details_domain_data.return_value = domain_detail
    mock_reference_list.return_value = ["8.8.8.8", "test.com"]
    result = main.main(requests.Request(data='{"live_investigation": true}'))
    self.assertEqual(
        result,
        "Ingestion for live_investigation is completed.\nIngestion for account_usage_details is completed\n",
    )

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.is_ip_present_in_cache", return_value=False
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.TeamCymruScoutClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  def test_main_domain_search(
      self,
      mock_client,
      mock_get_env_var,
      mock_session,
      mock_reference_list,
      mock_is_ip_present_in_cache,
  ):
    """Test case for main function."""
    mock_get_env_var.side_effect = [
        "test-scout",
        "api_key",
        "abc",
        "200",
        "suspicious,malicious",
        "ref_list",
    ]
    account_usage = {
        "used_queries": 661,
        "remaining_queries": 49339,
        "query_limit": 50000,
        "foundation_api_usage": {
            "used_queries": 2596,
            "remaining_queries": 7404,
            "query_limit": 10000,
        },
    }
    domain_detail = [
        {
            "ip": "93.184.215.14",
            "query": "test.com",
            "country_codes": ["US"],
            "as_info": [{"asn": 15133, "as_name": "EDGECAST, US"}],
        }
    ]

    mock_session.return_value.get_usage.return_value = account_usage
    mock_session.return_value.get_details_domain_data.return_value = domain_detail
    mock_reference_list.return_value = ["test.com"]
    result = main.main(requests.Request(data='{"domain_search": true}'))
    self.assertEqual(
        result,
        "Ingestion for domain_search is completed\nIngestion for account_usage_details is completed\n",
    )

  @mock.patch.object(fetch_logs.FetchEvents, "fetch_data_and_checkpoint")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.is_ip_present_in_cache", return_value=False
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.TeamCymruScoutClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client", new_callable=mock.MagicMock)
  def test_main_scheduled_feature(
      self,
      mock_storage_client,
      mock_client,
      mock_get_env_var,
      mock_session,
      mock_is_ip_present_in_cache,
      mock_fetch_logs,
  ):
    """Test case for main function."""
    mock_get_env_var.side_effect = [
        "test-scout",
        "api_key",
        "abc",
        "200",
        "suspicious,malicious",
        "bucket",
        "file_path",
    ]
    account_usage = {
        "used_queries": 661,
        "remaining_queries": 49339,
        "query_limit": 50000,
        "foundation_api_usage": {
            "used_queries": 2596,
            "remaining_queries": 7404,
            "query_limit": 10000,
        },
    }
    domain_detail = [
        {
            "ip": "93.184.215.14",
            "query": "test.com",
            "country_codes": ["US"],
            "as_info": [{"asn": 15133, "as_name": "EDGECAST, US"}],
        }
    ]
    foundation_detail = [
        {
            "ip": "8.8.8.8",
            "country_code": "",
            "as_info": None,
            "insights": {
                "overall_rating": "suspicious",
                "insights": [
                    {
                        "rating": "suspicious",
                        "message": '8.8.8.8 has been identified as a "bogon", indicating private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598, as well as netblocks that have not been allocated to a Regional Internet Registry (RIR) by the Internet Assigned Numbers Authority.',
                    }
                ],
            },
        }
    ]
    enrichment_detail = [
        {
            "request_id": "839f07be-d964-502d-b310-2b2ddb6d6d8e",
            "ip": "8.8.8.8",
            "size": 1000,
            "start_date": "2024-07-06",
            "end_date": "2024-08-04",
        }
    ]
    checkpoint_time = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    mock_session.return_value.get_usage.return_value = account_usage
    mock_session.return_value.get_foundation_ip_data.return_value = (
        foundation_detail
    )
    mock_session.return_value.get_details_ip_data.return_value = enrichment_detail
    mock_session.return_value.get_details_domain_data.return_value = domain_detail
    mock_fetch_logs.return_value = (
        ["8.8.8.8"],
        ["test.com"],
        mock.MagicMock(),
        checkpoint_time,
    )
    result = main.main(requests.Request(data=""))
    self.assertEqual(
        result,
        "Ingestion for ip_enrichment is completed\n"
        "Ingestion for domain_search is completed\n"
        "Ingestion for account_usage_details is completed\n",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.redis_client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_add_ips_to_redis_invalid_ttl(
      self, mock_cloud_logging, mock_get_env_var, mock_client
  ):
    """Test case for add_ips_to_redis function."""
    mock_get_env_var.return_value = "-1"
    mock_client.hset = mock.Mock()
    mock_client.expire = mock.Mock()
    main.add_ips_to_redis([{"value": "8.8.8.8"}])
    mock_cloud_logging.assert_any_call(
        "Invalid value provided for the PROVISIONAL_TTL environment "
        "variable. A PROVISIONAL_TTL should be a non-zero positive "
        "integer value. Default value will be considered as 30 days.",
        severity="WARNING",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.enrich_and_ingest_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_get_and_ingest_events_with_exception(
      self, mock_cloud_logging, mock_enrich_and_ingest_domains
  ):
    """Test case for get_and_ingest_events function."""
    mock_enrich_and_ingest_domains.side_effect = Exception("test")
    result = main.get_and_ingest_events(
        mock.MagicMock(),
        ["test.com"],
        "domain_search",
        "adhoc",
        {},
        [],
    )
    mock_cloud_logging.assert_called_once_with(
        "Error occurred while enriching and ingesting data for domain_search in adhoc, Error: test",
        severity="ERROR",
    )
    self.assertEqual(result, "Ingestion for domain_search is not completed.\n")

  def test_live_investigation_with_empty_list(self):
    """Test case for live_investigation function."""
    result = main.live_investigation(
        mock.MagicMock(), ["invalid"], "live_investigation", {}, []
    )
    self.assertEqual(
        result,
        "Skipping live_investigation as no valid indicators are provided for live investigation.\n",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.enrich_and_ingest_domains")
  def test_live_investigation_with_error(self, mock_enrich_and_ingest_domains):
    """Test case for live_investigation function."""
    mock_enrich_and_ingest_domains.return_value = "Ingestion is not completed.\n"
    result = main.live_investigation(
        mock.MagicMock(), ["test.com"], "live_investigation", {}, []
    )
    self.assertEqual(result, "Ingestion for live_investigation is not completed.\n")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_enrich_and_ingest_ips_with_rate_limit_exceeded(self, mock_cloud_logging):
    """Test case for enrich_and_ingest_ips function."""
    foundation_detail = {
        "used_queries": 661,
        "remaining_queries": 49339,
        "query_limit": 50000,
        "foundation_api_usage": {
            "used_queries": 2596,
            "remaining_queries": 0,
            "query_limit": 2596,
        },
    }
    result = main.enrich_and_ingest_ips(
        mock.MagicMock(), ["8.8.8.8"], "ip_enrichment", foundation_detail, []
    )
    self.assertEqual(result, "Ingestion for ip_enrichment is not completed.\n")
    mock_cloud_logging.assert_called_once_with(
        "Skipping IP enrichment as rate limit is exceeded. "
        f"latest usage details: {foundation_detail}",
        severity="WARNING",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.validate_indicators")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_enrich_and_ingest_ips_exception(
      self, mock_cloud_logging, mock_validate_indicators
  ):
    """Test case for enrich_and_ingest_ips function."""
    mock_validate_indicators.side_effect = Exception("test")
    result = main.enrich_and_ingest_ips(
        mock.MagicMock(), ["8.8.8.8"], "live_investigation", {}, []
    )
    mock_cloud_logging.assert_called_once_with(
        "Error occurred while getting details for live_investigation: test",
        severity="ERROR",
    )
    self.assertEqual(result, "Ingestion for live_investigation is not completed.\n")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.validate_indicators")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_enrich_and_ingest_domains_exception(
      self, mock_cloud_logging, mock_validate_indicators
  ):
    """Test case for enrich_and_ingest_domains function."""
    mock_validate_indicators.side_effect = Exception("test")
    result = main.enrich_and_ingest_domains(
        mock.MagicMock(), ["test.com"], "live_investigation"
    )
    mock_cloud_logging.assert_called_once_with(
        "Error occurred while getting details for live_investigation: test",
        severity="ERROR",
    )
    self.assertEqual(result, "Ingestion for live_investigation is not completed.\n")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}teamcymru_scout_client.requests.Session")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest_into_chronicle")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_ingest_updated_usage_details_exception(
      self, mock_cloud_logging, mock_client, mock_ingest_into_chronicle
  ):
    """Test case for ingest_updated_usage_details function."""
    mock_client.side_effect = Exception("test")
    client = teamcymru_scout_client.TeamCymruScoutClient(
        {"auth_type": "basic_auth", "username": "user", "password": "pass"}
    )
    result = main.ingest_updated_usage_details(client, "scout", "api_key")
    mock_cloud_logging.assert_any_call(
        "Failed to the get/ingest latest account usage details. Error: test",
        severity="ERROR",
    )
    self.assertEqual(
        result, "Ingestion for account_usage_details is not completed.\n"
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest_updated_usage_details")
  def test_scheduled_function_success(
      self,
      mock_ingest_updated_usage_details,
      mock_get_and_ingest_events,
      mock_FetchEvents,
      mock_storage_Client,
      mock_get_env_var,
      mock_cloud_logging,
  ):
    """Test case for scheduled_function function."""
    mock_client = mock.MagicMock()
    mock_account_usage_details = {"account_name": "test_account"}
    auth_type = "test_auth"
    ip_enrichment_tags = ["test_tag"]

    # Mock environment variables
    mock_get_env_var.side_effect = ["test_bucket", "test_log_type_file"]

    # Mock storage client and bucket
    mock_bucket = mock.MagicMock()
    mock_blob = mock.MagicMock()
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "log_type_data"
    mock_bucket.blob.return_value = mock_blob
    mock_storage_Client.return_value.get_bucket.return_value = mock_bucket

    # Mock fetch events
    mock_FetchEvents.return_value.fetch_data_and_checkpoint.return_value = (
        ["1.1.1.1"],
        ["example.com"],
        mock_blob,
        {"time": "next_time"},
    )

    # Mock ingest events
    mock_get_and_ingest_events.return_value = "Ingestion completed.\n"
    mock_ingest_updated_usage_details.return_value = "Updated usage details."

    result = main.scheduled_function(
        client=mock_client,
        account_usage_details=mock_account_usage_details,
        auth_type=auth_type,
        ip_enrichment_tags=ip_enrichment_tags,
    )

    self.assertIn("Ingestion completed.\n", result)
    mock_cloud_logging.assert_any_call(
        "Running in Scheduled Enrichment Mode", severity="INFO"
    )
    mock_cloud_logging.assert_any_call("Fetching events from Chronicle.")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents")
  def test_scheduled_function_no_data(
      self,
      mock_FetchEvents,
      mock_storage_Client,
      mock_get_env_var,
      mock_cloud_logging,
  ):
    """Test case for scheduled_function function."""
    mock_client = mock.MagicMock()
    mock_account_usage_details = {"account_name": "test_account"}
    auth_type = "test_auth"
    ip_enrichment_tags = ["test_tag"]

    # Mock environment variables
    mock_get_env_var.side_effect = ["test_bucket", "test_log_type_file"]

    # Mock storage client and bucket
    mock_bucket = mock.MagicMock()
    mock_blob = mock.MagicMock()
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "log_type_data"
    mock_bucket.blob.return_value = mock_blob
    mock_storage_Client.return_value.get_bucket.return_value = mock_bucket

    # Mock fetch events
    mock_FetchEvents.return_value.fetch_data_and_checkpoint.return_value = (
        [],
        [],
        mock_blob,
        {"time": "next_time"},
    )

    result = main.scheduled_function(
        client=mock_client,
        account_usage_details=mock_account_usage_details,
        auth_type=auth_type,
        ip_enrichment_tags=ip_enrichment_tags,
    )

    self.assertIn("Ingestion not completed.", result)
    mock_cloud_logging.assert_any_call(
        "Running in Scheduled Enrichment Mode", severity="INFO"
    )
    mock_cloud_logging.assert_any_call("Fetching events from Chronicle.")
    mock_cloud_logging.assert_any_call(
        "No data found in Chronicle for configured log types in given time range. "
        "The start time for next execution is updated to next_time."
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents")
  def test_scheduled_function_error(
      self,
      mock_FetchEvents,
      mock_storage_Client,
      mock_get_env_var,
      mock_cloud_logging,
  ):
    """Test case for scheduled_function function."""
    mock_client = mock.MagicMock()
    mock_account_usage_details = {"account_name": "test_account"}
    auth_type = "test_auth"
    ip_enrichment_tags = ["test_tag"]

    # Mock environment variables
    mock_get_env_var.side_effect = ["test_bucket", "test_log_type_file"]

    # Mock storage client and bucket
    mock_bucket = mock.MagicMock()
    mock_blob = mock.MagicMock()
    mock_blob.exists.side_effect = Exception("Bucket access error")
    mock_bucket.blob.return_value = mock_blob
    mock_storage_Client.return_value.get_bucket.return_value = mock_bucket

    result = main.scheduled_function(
        client=mock_client,
        account_usage_details=mock_account_usage_details,
        auth_type=auth_type,
        ip_enrichment_tags=ip_enrichment_tags,
    )

    self.assertIn("Ingestion not completed.", result)
    mock_cloud_logging.assert_any_call(
        "Running in Scheduled Enrichment Mode", severity="INFO"
    )
    mock_cloud_logging.assert_any_call(
        "An error occurred: Bucket access error", severity="ERROR"
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  def test_scheduled_function_empty_bucket_name(
      self, mock_get_env_var, mock_cloud_logging
  ):
    """Test case for scheduled_function function."""
    mock_client = mock.MagicMock()
    mock_account_usage_details = {"account_name": "test_account"}
    auth_type = "test_auth"
    ip_enrichment_tags = ["test_tag"]

    # Mock environment variables
    mock_get_env_var.side_effect = [""]

    result = main.scheduled_function(
        client=mock_client,
        account_usage_details=mock_account_usage_details,
        auth_type=auth_type,
        ip_enrichment_tags=ip_enrichment_tags,
    )

    self.assertIn("Ingestion not completed.\n", result)
    mock_cloud_logging.assert_any_call(
        "Empty value is provided for the GCP_BUCKET_NAME environment variable.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  def test_scheduled_function_invalid_log_types(
      self, mock_storage_Client, mock_get_env_var, mock_cloud_logging
  ):
    """Test case for scheduled_function function."""
    mock_client = mock.MagicMock()
    mock_account_usage_details = {"account_name": "test_account"}
    auth_type = "test_auth"
    ip_enrichment_tags = ["test_tag"]

    # Mock environment variables
    mock_get_env_var.side_effect = ["test_bucket", "test_log_type_file"]

    # Mock storage client and bucket
    mock_bucket = mock.MagicMock()
    mock_blob = mock.MagicMock()
    mock_blob.exists.return_value = False
    mock_bucket.blob.return_value = mock_blob
    mock_storage_Client.return_value.get_bucket.return_value = mock_bucket

    result = main.scheduled_function(
        client=mock_client,
        account_usage_details=mock_account_usage_details,
        auth_type=auth_type,
        ip_enrichment_tags=ip_enrichment_tags,
    )

    self.assertIn("Ingestion not completed.\n", result)
    mock_cloud_logging.assert_any_call(
        "Log type file is not provided or invalid value is provided. Considering all log type to fetch events from Chronicle.",
        severity="WARNING",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents")
  def test_scheduled_function_fetch_events_error(
      self,
      mock_FetchEvents,
      mock_storage_Client,
      mock_get_env_var,
      mock_cloud_logging,
  ):
    """Test case for scheduled_function function."""
    mock_client = mock.MagicMock()
    mock_account_usage_details = {"account_name": "test_account"}
    auth_type = "test_auth"
    ip_enrichment_tags = ["test_tag"]

    # Mock environment variables
    mock_get_env_var.side_effect = ["test_bucket", "test_log_type_file"]

    # Mock storage client and bucket
    mock_bucket = mock.MagicMock()
    mock_blob = mock.MagicMock()
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "log_type_data"
    mock_bucket.blob.return_value = mock_blob
    mock_storage_Client.return_value.get_bucket.return_value = mock_bucket

    # Mock fetch events to raise an error
    mock_FetchEvents.return_value.fetch_data_and_checkpoint.side_effect = Exception(
        "Fetch error"
    )

    result = main.scheduled_function(
        client=mock_client,
        account_usage_details=mock_account_usage_details,
        auth_type=auth_type,
        ip_enrichment_tags=ip_enrichment_tags,
    )

    self.assertIn("Ingestion not completed.\n", result)
    mock_cloud_logging.assert_any_call(
        "Error in fetching events: Fetch error", severity="ERROR"
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents")
  def test_scheduled_function_fetch_events_value_error(
      self,
      mock_FetchEvents,
      mock_storage_Client,
      mock_get_env_var,
      mock_cloud_logging,
  ):
    """Test case for scheduled_function function."""
    mock_client = mock.MagicMock()
    mock_account_usage_details = {"account_name": "test_account"}
    auth_type = "test_auth"
    ip_enrichment_tags = ["test_tag"]

    # Mock environment variables
    mock_get_env_var.side_effect = ["test_bucket", "test_log_type_file"]

    # Mock storage client and bucket
    mock_bucket = mock.MagicMock()
    mock_blob = mock.MagicMock()
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "log_type_data"
    mock_bucket.blob.return_value = mock_blob
    mock_storage_Client.return_value.get_bucket.return_value = mock_bucket

    # Mock fetch events to raise an error
    mock_FetchEvents.return_value.fetch_data_and_checkpoint.side_effect = (
        ValueError("Fetch error")
    )

    result = main.scheduled_function(
        client=mock_client,
        account_usage_details=mock_account_usage_details,
        auth_type=auth_type,
        ip_enrichment_tags=ip_enrichment_tags,
    )

    self.assertIn("Ingestion not completed.\n", result)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest_updated_usage_details")
  def test_scheduled_function_general_exception(
      self,
      mock_ingest_updated_usage_details,
      mock_get_and_ingest_events,
      mock_FetchEvents,
      mock_storage_Client,
      mock_get_env_var,
      mock_cloud_logging,
  ):
    """Test case for scheduled_function function."""
    mock_client = mock.MagicMock()
    mock_account_usage_details = {"account_name": "test_account"}
    auth_type = "test_auth"
    ip_enrichment_tags = ["test_tag"]

    # Mock environment variables
    mock_get_env_var.side_effect = ["test_bucket", "test_log_type_file"]

    # Mock storage client and bucket
    mock_bucket = mock.MagicMock()
    mock_blob = mock.MagicMock()
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "log_type_data"
    mock_bucket.blob.return_value = mock_blob
    mock_storage_Client.return_value.get_bucket.return_value = mock_bucket

    # Mock fetch events
    mock_FetchEvents.return_value.fetch_data_and_checkpoint.return_value = (
        ["1.1.1.1"],
        ["example.com"],
        mock_blob,
        {"time": "next_time"},
    )

    # Mock get_and_ingest_events to raise a general exception
    mock_get_and_ingest_events.side_effect = Exception("Unexpected error")

    result = main.scheduled_function(
        client=mock_client,
        account_usage_details=mock_account_usage_details,
        auth_type=auth_type,
        ip_enrichment_tags=ip_enrichment_tags,
    )

    self.assertIn("Ingestion is not completed.\n", result)
    mock_cloud_logging.assert_any_call(
        "Error while executing scheduled function. Error: Unexpected error",  # noqa:E501
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_env_var_not_set(self, mock_cloud_logging, mock_get_env_var):
    """Test case for get_reference_list function."""
    mock_get_env_var.return_value = ""

    with self.assertRaises(Exception) as context:
      main.get_reference_list("TEST_ENV_VAR")

    self.assertIn(
        "Environment variable TEST_ENV_VAR is not set or empty value is provided.",
        str(context.exception),
    )
    mock_cloud_logging.assert_called_with(
        "Environment variable TEST_ENV_VAR for the reference list name is not set or empty value is provided.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  def test_no_data_found_in_reference_list(
      self, mock_get_reference_list, mock_cloud_logging, mock_get_env_var
  ):
    """Test case for get_reference_list function."""
    mock_get_env_var.return_value = "test_list"
    mock_get_reference_list.return_value = []

    result = main.get_reference_list("TEST_ENV_VAR")

    self.assertEqual(result, [])
    mock_cloud_logging.assert_called_with(
        "No data found in reference list test_list",
        severity="WARNING",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  def test_data_found_in_reference_list(
      self, mock_get_reference_list, mock_cloud_logging, mock_get_env_var
  ):
    """Test case for get_reference_list function."""
    mock_get_env_var.return_value = "test_list"
    mock_get_reference_list.return_value = ["data1", "data2"]

    result = main.get_reference_list("TEST_ENV_VAR")

    self.assertEqual(result, ["data1", "data2"])

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  def test_exception_while_fetching_reference_list(
      self, mock_get_reference_list, mock_cloud_logging, mock_get_env_var
  ):
    """Test case for get_reference_list function."""
    mock_get_env_var.side_effect = ["test_list"]
    mock_get_reference_list.side_effect = Exception("Unexpected error")

    with self.assertRaises(Exception) as context:
      main.get_reference_list("TEST_ENV_VAR")

    self.assertIn("Unexpected error", str(context.exception))
    mock_cloud_logging.assert_called_with(
        "An error occurred while fetching reference list test_list, Error : Unexpected error",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_reference_list")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest_updated_usage_details")
  def test_ip_enrichment_exception(
      self,
      mock_ingest_updated_usage_details,
      mock_get_and_ingest_events,
      mock_get_reference_list,
      mock_cloud_logging,
  ):
    """Test case for get_and_ingest_events function."""
    mock_get_reference_list.side_effect = Exception("Reference list error")
    mock_ingest_updated_usage_details.return_value = "Usage details updated."

    result = main.adhoc_function(
        teamcymru_scout_client=mock.MagicMock(),
        account_usage_details={"account_name": "test_account"},
        auth_type="test_auth",
        ip_enrichment_enabled=True,
        domain_search_enabled=False,
        live_investigation_enabled=False,
        ip_enrichment_tags=["tag1"],
    )

    self.assertIn("Ingestion for ip_enrichment is not completed.", result)
    mock_cloud_logging.assert_any_call(
        "Running in Adhoc Enrichment Mode", severity="INFO"
    )
    mock_cloud_logging.assert_any_call(
        "An error occurred while fetching reference list IP_ENRICHMENT_LIST,Error : Reference list error",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_reference_list")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest_updated_usage_details")
  def test_domain_search_exception(
      self,
      mock_ingest_updated_usage_details,
      mock_get_and_ingest_events,
      mock_get_reference_list,
      mock_cloud_logging,
  ):
    """Test case for get_and_ingest_events function."""
    mock_get_reference_list.side_effect = Exception("Reference list error")
    mock_ingest_updated_usage_details.return_value = "Usage details updated."

    result = main.adhoc_function(
        teamcymru_scout_client=mock.MagicMock(),
        account_usage_details={"account_name": "test_account"},
        auth_type="test_auth",
        ip_enrichment_enabled=False,
        domain_search_enabled=True,
        live_investigation_enabled=False,
        ip_enrichment_tags=["tag1"],
    )

    self.assertIn("Ingestion for domain_search is not completed.", result)
    mock_cloud_logging.assert_any_call(
        "Running in Adhoc Enrichment Mode", severity="INFO"
    )
    mock_cloud_logging.assert_any_call(
        "An error occurred while fetching reference list DOMAIN_SEARCH_LIST,Error : Reference list error",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_reference_list")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest_updated_usage_details")
  def test_live_investigation_exception(
      self,
      mock_ingest_updated_usage_details,
      mock_get_and_ingest_events,
      mock_get_reference_list,
      mock_cloud_logging,
  ):
    """Test case for get_and_ingest_events function."""
    mock_get_reference_list.side_effect = Exception("Reference list error")
    mock_ingest_updated_usage_details.return_value = "Usage details updated."

    result = main.adhoc_function(
        teamcymru_scout_client=mock.MagicMock(),
        account_usage_details={"account_name": "test_account"},
        auth_type="test_auth",
        ip_enrichment_enabled=False,
        domain_search_enabled=False,
        live_investigation_enabled=True,
        ip_enrichment_tags=["tag1"],
    )

    self.assertIn("Ingestion for live_investigation is not completed.", result)
    mock_cloud_logging.assert_any_call(
        "Running in Adhoc Enrichment Mode", severity="INFO"
    )
    mock_cloud_logging.assert_called_with(
        "An error occurred while fetching reference list LIVE_INVESTIGATION_LIST,Error: Reference list error",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_empty_account_name(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = [""]
    request = mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertIn("Ingestion not completed due to empty account name", result)
    mock_cloud_logging.assert_any_call(
        "Empty value is provided for the TEAMCYMRU_SCOUT_ACCOUNT_NAME environment variable.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_empty_auth_name(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = ["scout", ""]
    request = mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertIn("Ingestion not completed due to empty auth type", result)
    mock_cloud_logging.assert_any_call(
        "Empty value is provided for the TEAMCYMRU_SCOUT_AUTH_TYPE environment variable.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_empty_username(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = ["scout", "basic_auth", ""]
    request = mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertIn("Ingestion not completed due to empty username", result)
    mock_cloud_logging.assert_any_call(
        "Empty value is provided for the TEAMCYMRU_SCOUT_API_USERNAME environment variable.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_empty_password(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = ["scout", "basic_auth", "abc", ""]
    request = mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertIn("Ingestion not completed due to empty password", result)
    mock_cloud_logging.assert_any_call(
        "Empty value is provided for the TEAMCYMRU_SCOUT_API_PASSWORD environment variable.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_empty_api_key(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = ["scout", "api_key", ""]
    request = mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertIn("Ingestion not completed due to empty api key", result)
    mock_cloud_logging.assert_any_call(
        "Empty value is provided for the TEAMCYMRU_SCOUT_API_KEY environment variable.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_invalid_auth_type(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = ["scout", "api_key1"]
    request = mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertIn("Ingestion not completed due to invalid auth type.", result)
    mock_cloud_logging.assert_any_call(
        "Invalid auth type: api_key1 configured in environment variable. "  # noqa:E501
        "Supported auth types: basic_auth, api_key",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_invalid_threshold(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = ["scout", "api_key", "abc", "10001"]
    request = mock.MagicMock()
    request.data = None

    result = main.main(request)
    self.assertIn("Ingestion not completed due to invalid threshold size.", result)
    mock_cloud_logging.assert_any_call(
        "Invalid value provided for the "
        "IP_ENRICHMENT_SIZE "
        "environment variable. A valid value should be an integer "
        "greater than 0 and less than or equal to 1000.",
        severity="ERROR",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_invalid_request_data(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = [
        "scout",
        "api_key",
        "abc",
        "999",
        "suspicious,malicious",
    ]
    request = requests.Request(data="abc")

    result = main.main(request)
    self.assertIn(
        "Ingestion not completed due to invalid json in request body.", result
    )
    mock_cloud_logging.assert_any_call(
        "Please pass a valid json in the request body.", severity="ERROR"
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_main_invalid_adhoc_feature(self, mock_cloud_logging, mock_get_env_var):
    """Test case for main function."""
    mock_get_env_var.side_effect = [
        "scout",
        "api_key",
        "abc",
        "999",
        "suspicious,malicious",
    ]
    request = requests.Request(data='{"ip": true}')

    result = main.main(request)
    self.assertIn(
        "Ingestion not completed due to error in request body parameter.", result
    )
    mock_cloud_logging.assert_any_call(
        "Skipping invalid configured feature: ip: True.",  # noqa:E501
        severity="WARNING",
    )
    mock_cloud_logging.assert_any_call(
        "Not a single valid feature set to True in the request body. valid features: ip_enrichment, domain_search, live_investigation",  # noqa:E501
        severity="ERROR",
    )

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.is_rate_limit_exceeded", return_value=True
  )
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.get_scout_client_and_usage_details",
      return_value=(rate_limit_usage, mock.MagicMock()),
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_is_limit_exceeded_adhoc(
      self,
      mock_cloud_logging,
      mock_get_env_var,
      mock_get_scout_client_and_usage_details,
      mock_is_rate_limit_exceeded,
  ):
    """Test case for main function."""
    mock_get_env_var.side_effect = [
        "scout",
        "api_key",
        "abc",
        "999",
        "suspicious,malicious",
    ]
    request = requests.Request(data='{"ip_enrichment": true}')

    result = main.main(request)
    self.assertIn("Ingestion not completed due to rate limit exceeded.", result)
    mock_cloud_logging.assert_any_call(
        "Stopping Enrichment due to rate limit exceeded. "
        f"latest usage details: {rate_limit_usage}",
        severity="WARNING",
    )

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.is_rate_limit_exceeded", return_value=True
  )
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.get_scout_client_and_usage_details",
      return_value=(rate_limit_usage, mock.MagicMock()),
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_is_limit_exceeded_scheduled(
      self,
      mock_cloud_logging,
      mock_get_env_var,
      mock_get_scout_client_and_usage_details,
      mock_is_rate_limit_exceeded,
  ):
    """Test case for main function."""
    mock_get_env_var.side_effect = [
        "scout",
        "api_key",
        "abc",
        "999",
        "suspicious,malicious",
    ]
    request = requests.Request(data=None)

    result = main.main(request)
    self.assertIn("Ingestion not completed due to rate limit exceeded.", result)
    mock_cloud_logging.assert_any_call(
        "Stopping Enrichment due to rate limit exceeded. "
        f"latest usage details: {rate_limit_usage}",
        severity="WARNING",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_is_limit_exceeded_no_account_name(
      self, mock_cloud_logging, mock_get_env_var
  ):
    """Test case for main function."""
    mock_get_env_var.side_effect = Exception("e")
    request = requests.Request(data=None)

    result = main.main(request)
    self.assertIn("Ingestion not completed.", result)
    mock_cloud_logging.assert_any_call(
        "Unexpected error occurred. Error: e", severity="ERROR"
    )
