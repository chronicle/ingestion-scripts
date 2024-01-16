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
"""Unittest cases for Domaintools ingestion scripts."""

import os
import sys
import unittest
from unittest import mock

from domaintools.exceptions import NotAuthorizedException
from domaintools.exceptions import ServiceUnavailableException
import requests

os.environ["CHRONICLE_CUSTOMER_ID"] = "test_id"
os.environ["CHRONICLE_SERVICE_ACCOUNT"] = """{
    "project_id": "1234"
}"""
os.environ["DOMAINTOOLS_API_USERNAME"] = "test_username"
os.environ["DOMAINTOOLS_API_KEY"] = "test_key"
os.environ["REDIS_HOST"] = "1.2.3.4"
os.environ["REDIS_PORT"] = "1234"

INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest"] = mock.Mock()

DNSDB_TEST_DATA = [
    b'{"cond":"begin"}',
    b'{"obj":{"count":357,"time_first":1614295495,"time_last":1701905071,"rrname":"screenshots.ar.test.com"}}',
    b'{"obj":{"count":3495,"time_first":1614295497,"time_last":1701905071,"rrname":"screenshots.ar.test2.com."}}',
    b'{"obj":{"count":104,"time_first":1311185207,"time_last":1701910597,"rrname":"marketing.test2.com."}}',
    b'{"obj":{"count":588,"time_first":1393454260,"time_last":1701910597,"rrname":"marketing.test.com."}}',
    b'{"obj":{"count":296,"time_first":1585079396,"time_last":1701906724,"rrname":"covid-19.test.com."}}',
    b'{"obj":{"count":300,"time_first":1585079396,"time_last":1701906724,"rrname":"covid-20.test.com."}}',
    b'{"obj":{"count":482,"time_first":1585079396,"time_last":1701906728,"rrname":"covid-21.test.com."}}',
    b'{"obj":{"count":374,"time_first":1585079396,"time_last":1701906724,"rrname":"covid-22.test.com."}}',
    b'{"obj":{"count":98,"time_first":1585079396,"time_last":1701906723,"rrname":"covid-23.test.com."}}',
    b'{"obj":{"count":15,"time_first":1585079396,"time_last":1701906724,"rrname":"covid-24.test.com."}}',
    b'{"cond":"succeeded"}',
]

import main


def generate_domains(count):
  """Generate dummy domain names."""
  domain_list = []
  for i in range(count):
    domain_list.append("test_domain_{0}".format(i))
  return domain_list


@mock.patch(
    f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var",
)
class TestDomaintoolsLogsIngestion(unittest.TestCase):
  """Test cases for Domaintools logs ingestion script."""

  # main method test cases
  def test_invalid_provisional_ttl(self, mocked_get_env_var):
    """Test case to verify invalid Provisional TTL values provided."""
    mocked_get_env_var.side_effect = ["test"]
    response = main.main(request="")
    assert main.client.connection_pool.connection_kwargs["decode_responses"]
    self.assertEqual(
        response,
        "Ingestion not Completed",
    )

  def test_invalid_non_provisional_ttl(self, mocked_get_env_var):
    """Test case to verify invalid Non Provisional TTL values provided."""
    mocked_get_env_var.side_effect = ["5", "test"]
    response = main.main(request="")
    self.assertEqual(
        response,
        "Ingestion not Completed",
    )

  def test_invalid_fetch_subdomains_for_max_domains(self, mocked_get_env_var):
    """Test case to verify invalid FETCH_SUBDOMAINS_FOR_MAX_DOMAINS values provided."""
    mocked_get_env_var.side_effect = ["5", "10", "test"]
    response = main.main(request="")
    self.assertEqual(
        response,
        "Ingestion not Completed",
    )

  def test_empty_redis_host(self, mocked_get_env_var):
    """Test case to verify empty REDIS_HOST values provided."""
    mocked_get_env_var.side_effect = ["5", "10", "100", ""]
    response = main.main(request="")
    self.assertEqual(
        response,
        "Ingestion not Completed",
    )

  def test_empty_redis_port(self, mocked_get_env_var):
    """Test case to verify empty REDIS_PORT values provided."""
    mocked_get_env_var.side_effect = ["5", "10", "100", "1.2.3.4", ""]
    response = main.main(request="")
    self.assertEqual(
        response,
        "Ingestion not Completed",
    )

  def test_empty_domaintools_username(self, mocked_get_env_var):
    """Test case to verify empty DOMAINTOOLS_API_USERNAME values provided."""
    mocked_get_env_var.side_effect = ["5", "10", "100", "1.2.3.4", "1000", ""]
    response = main.main(request="")
    self.assertEqual(
        response,
        "Ingestion not Completed",
    )

  def test_empty_domaintools_key(self, mocked_get_env_var):
    """Test case to verify empty DOMAINTOOLS_API_KEY values provided."""
    mocked_get_env_var.side_effect = [
        "5",
        "10",
        "100",
        "1.2.3.4",
        "1000",
        "test_username",
        "",
    ]
    response = main.main(request="")
    self.assertEqual(
        response,
        "Ingestion not Completed",
    )

  # scheduled_cloud_function method
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents.fetch_data_and_checkpoint"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch("google.cloud.storage.Blob")
  def test_scheduled_cloud_function_success(
      self,
      mock_blob,
      mock_storage_client,
      mock_fetch_data_and_checkpoint,
      mock_get_and_ingest_events,
      mocked_get_env_var,
  ):
    """Test case when scheduled_cloud_function passess successfully."""
    mocked_get_env_var.side_effect = [
        "test-bucket",
        "test-bucket/temp/log_types.txt",
    ]
    mock_file_content = "{'time': '2022-10-11T15:10:14Z'}"

    # Set up the mock blob and its open method
    mock_blob_instance = mock_blob.return_value
    mock_blob_instance.open.return_value.__enter__.return_value.read.return_value = (
        mock_file_content
    )

    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.exists.return_value = (
        True
    )
    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.download_as_text.return_value = (
        "Test_label"
    )
    mock_fetch_data_and_checkpoint.return_value = (
        ["test.com"],
        mock_blob_instance,
        {"time": "2023-12-12T15:30:10Z"},
    )
    mock_get_and_ingest_events.return_value = True

    response = main.scheduled_cloud_function()
    self.assertEqual(response, "Ingestion Completed")
    mock_blob_instance.open.return_value.__enter__.return_value.write.assert_called_once()
    mock_blob_instance.open.return_value.__enter__.return_value.write.assert_called_with(
        '{"time": "2023-12-12T15:30:10Z"}'
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents.fetch_data_and_checkpoint"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch("google.cloud.storage.Blob")
  def test_scheduled_cloud_function_blob_not_exists(
      self,
      mock_blob,
      mock_storage_client,
      mock_fetch_data_and_checkpoint,
      mock_get_and_ingest_events,
      mocked_get_env_var,
  ):
    """Test case to verify log_type file blob does not exists."""
    mocked_get_env_var.side_effect = [
        "test-bucket",
        "test-bucket/temp/log_types.txt",
    ]
    mock_file_content = "{'time': '2022-10-11T15:10:14Z'}"

    # Set up the mock blob and its open method
    mock_blob_instance = mock_blob.return_value
    mock_blob_instance.open.return_value.__enter__.return_value.read.return_value = (
        mock_file_content
    )
    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.exists.return_value = (
        False
    )
    mock_fetch_data_and_checkpoint.return_value = (
        ["test.com"],
        mock_blob_instance,
        {"time": "2023-11-12T15:30:10Z"},
    )
    mock_get_and_ingest_events.return_value = True

    response = main.scheduled_cloud_function()
    self.assertEqual(response, "Ingestion Completed")
    mock_blob_instance.open.return_value.__enter__.return_value.write.assert_called_once()
    mock_blob_instance.open.return_value.__enter__.return_value.write.assert_called_with(
        '{"time": "2023-11-12T15:30:10Z"}'
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents.fetch_data_and_checkpoint"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_scheduled_cloud_function_exception_in_blob(
      self,
      mock_cloud_logging,
      mock_storage_client,
      unused_mock_fetch_data_and_checkpoint,
      unused_mock_get_and_ingest_events,
      mocked_get_env_var,
  ):
    """Test case to verify exception in getting log_type blob."""
    mocked_get_env_var.side_effect = [
        "test-bucket",
        "test-bucket/temp/log_types.txt",
    ]
    mock_storage_client.return_value.get_bucket.return_value.blob.side_effect = Exception(
        "Bucket not found"
    )
    response = main.scheduled_cloud_function()
    mock_cloud_logging.assert_called_with(
        "An error occurred: Bucket not found", severity="ERROR"
    )
    self.assertEqual(response, "Ingestion not Completed")

  def test_scheduled_cloud_function_exception_in_bucket(
      self,
      mocked_get_env_var,
  ):
    """Test case to verify exception in getting log_type blob."""
    mocked_get_env_var.side_effect = [""]
    response = main.scheduled_cloud_function()
    self.assertEqual(response, "Ingestion not Completed")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents.fetch_data_and_checkpoint"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  def test_scheduled_cloud_function_fetch_data_and_checkpoint_value_error(
      self,
      mock_storage_client,
      mock_fetch_data_and_checkpoint,
      unused_mock_get_and_ingest_events,
      mocked_get_env_var,
  ):
    """Test case to verify ValuError in fetch_data_and_checkpoint method."""
    mocked_get_env_var.side_effect = [
        "test-bucket",
        "test-bucket/temp/log_types.txt",
    ]
    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.exists.return_value = (
        True
    )
    mock_fetch_data_and_checkpoint.return_value = (
        ["test.com"],
        mock.MagicMock(),
    )

    response = main.scheduled_cloud_function()

    self.assertRaises(ValueError)
    self.assertEqual(response, "Ingestion not Completed")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents.fetch_data_and_checkpoint"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_scheduled_cloud_function_fetch_data_and_checkpoint_exception(
      self,
      mock_cloud_logging,
      mock_storage_client,
      mock_fetch_data_and_checkpoint,
      unused_mock_get_and_ingest_events,
      mocked_get_env_var,
  ):
    """Test case to verify Exception in fetch_data_and_checkpoint method."""
    mocked_get_env_var.side_effect = [
        "test-bucket",
        "test-bucket/temp/log_types.txt",
    ]
    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.exists.return_value = (
        True
    )
    mock_fetch_data_and_checkpoint.side_effect = Exception(
        "Error in fetching Data"
    )

    response = main.scheduled_cloud_function()

    mock_cloud_logging.assert_called_with(
        "Error in fetching events: Error in fetching Data", severity="ERROR"
    )
    self.assertEqual(response, "Ingestion not Completed")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents.fetch_data_and_checkpoint"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch("google.cloud.storage.Blob")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_scheduled_cloud_function_no_data(
      self,
      mock_cloud_logging,
      mock_blob,
      mock_storage_client,
      mock_fetch_data_and_checkpoint,
      mock_get_and_ingest_events,
      mocked_get_env_var,
  ):
    """Test case to verify when no domains returned from mock_fetch_data_and_checkpoint method."""
    mocked_get_env_var.side_effect = [
        "test-bucket",
        "test-bucket/temp/log_types.txt",
    ]
    mock_file_content = "{'time': '2022-10-11T15:10:14Z'}"

    # Set up the mock blob and its open method
    mock_blob_instance = mock_blob.return_value
    mock_blob_instance.open.return_value.__enter__.return_value.read.return_value = (
        mock_file_content
    )

    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.exists.return_value = (
        True
    )
    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.download_as_text.return_value = (
        "Test_log_type"
    )
    mock_fetch_data_and_checkpoint.return_value = (
        [],
        mock_blob_instance,
        {"time": "2023-06-12T15:30:10Z"},
    )
    mock_get_and_ingest_events.return_value = True

    response = main.scheduled_cloud_function()

    mock_cloud_logging.assert_called_with(
        "The start time for next execution is updated to 2023-06-12T15:30:10Z."
    )
    self.assertEqual(response, "Ingestion not Completed")
    mock_blob_instance.open.return_value.__enter__.return_value.write.assert_called_once()
    mock_blob_instance.open.return_value.__enter__.return_value.write.assert_called_with(
        '{"time": "2023-06-12T15:30:10Z"}'
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.fetch_logs.FetchEvents.fetch_data_and_checkpoint"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_scheduled_cloud_function_get_and_ingest_events_exception(
      self,
      mock_cloud_logging,
      mock_storage_client,
      mock_fetch_data_and_checkpoint,
      mock_get_and_ingest_events,
      mocked_get_env_var,
  ):
    """Test case when Exception in get_and_ingest_events method."""
    mocked_get_env_var.side_effect = [
        "test-bucket",
        "test-bucket/temp/log_types.txt",
    ]
    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.exists.return_value = (
        True
    )
    mock_storage_client.return_value.get_bucket.return_value.blob.return_value.download_as_text.return_value = (
        "Test_log_type"
    )
    mock_fetch_data_and_checkpoint.return_value = (
        ["test.com"],
        mock.MagicMock(),
        {"time": "2023-12-12T15:30:10Z"},
    )
    mock_get_and_ingest_events.side_effect = Exception(
        "Exception in ingesting data"
    )

    response = main.scheduled_cloud_function()

    mock_cloud_logging.assert_called_with(
        "Error: Exception in ingesting data", severity="ERROR"
    )
    self.assertEqual(response, "Ingestion not Completed")

  # get_and_ingest_events method
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.domaintool_client.domaintools.API")
  def test_get_and_ingest_events_failure_redis(
      self,
      mock_domain_tool_client,
      mock_client_hget,
      mocked_get_env_var,
  ):
    """Test case when get_and_ingest_event method is failed due to error in redis."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "",
        "allow_list_name",
    ]
    mock_domain_tool_client.return_value = mock.MagicMock()
    mock_client_hget.side_effect = Exception
    with self.assertRaises(Exception):
      main.get_and_ingest_events("Test_log_type", ["test"], "scheduler")
    self.assertEqual(mock_client_hget.call_count, 1)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.domaintool_client.domaintools.API")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_enriched_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_subdomains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_domains_to_redis")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.utils.get_value_from_secret_manager"
  )
  def test_get_and_ingest_events_success_without_dnsdb(
      self,
      mock_get_value_from_secret_manager,
      mock_add_domains_to_redis,
      mock_get_subdomains,
      mock_get_enriched_domains,
      mock_domain_tool_client,
      mock_client_hget,
      mock_ingest,
      mocked_get_env_var,
  ):
    """Test case when get_and_ingest_event method passes without dnsdb api call."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "",
        "allow_list_name",
        "50",
    ]
    mock_domain_tool_client.return_value = mock.MagicMock()
    mock_client_hget.return_value = True
    mock_get_enriched_domains.return_value = {
        "results": [
            {"domain": "test_domain.com"},
            {"domain": "test_domain2.com"},
        ]
    }
    mock_get_subdomains.return_value = [{"domain": "*.com", "count": 10}]
    mock_ingest.get_reference_list.return_value = ["test_domain.com"]
    mock_ingest.ingest.return_value = True
    mock_add_domains_to_redis.return_value = True
    mock_get_value_from_secret_manager.return_value = "API_KEY"
    main.get_and_ingest_events("Test_log_type", [], "scheduler")
    self.assertEqual(
        mocked_get_env_var.mock_calls[0],
        mock.call("DOMAINTOOLS_API_USERNAME", is_secret=True),
    )
    self.assertEqual(
        mocked_get_env_var.mock_calls[1],
        mock.call("DOMAINTOOLS_API_KEY", is_secret=True),
    )
    self.assertEqual(
        mocked_get_env_var.mock_calls[2],
        mock.call("DNSDB_API_KEY", required=False, default=""),
    )
    self.assertEqual(
        mocked_get_env_var.mock_calls[3],
        mock.call("ALLOW_LIST", required=False, default=""),
    )
    self.assertEqual(
        mocked_get_env_var.mock_calls[4],
        mock.call(
            "FETCH_SUBDOMAINS_FOR_MAX_DOMAINS", required=False, default="2000"
        ),
    )
    self.assertEqual(mock_get_subdomains.call_count, 0)
    self.assertEqual(mock_get_enriched_domains.call_count, 1)
    self.assertEqual(mock_get_value_from_secret_manager.call_count, 0)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}domaintool_client.DomainToolClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_enriched_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_subdomains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_domains_to_redis")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.utils.get_value_from_secret_manager"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_get_and_ingest_events_success_with_dnsdb(
      self,
      mock_cloud_logging,
      mock_get_value_from_secret_manager,
      mock_add_domains_to_redis,
      mock_get_subdomains,
      mock_get_enriched_domains,
      mock_domain_tool_client,
      mock_client_hget,
      mock_ingest,
      mocked_get_env_var,
  ):
    """Test when get_and_ingest_event method passess with dnsdb api call."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "test-secret/dnsdb-api-key/version/1",
        "",
        "5000",
    ]
    mock_domain_tool_client.return_value = None
    mock_client_hget.side_effect = [True, False]
    mock_get_enriched_domains.return_value = {
        "results": [
            {"domain": "test_domain.com"},
            {"domain": "test_domain2.com"},
        ]
    }
    mock_get_subdomains.return_value = [{"domain": "*.com", "count": 10}]
    mock_ingest.get_reference_list.return_value = ["test_domain.com"]
    mock_ingest.ingest.return_value = True
    mock_add_domains_to_redis.return_value = True
    mock_get_value_from_secret_manager.return_value = "API_KEY"
    main.get_and_ingest_events(
        "Test_log_type", ["test_domain.com", "test_domain2.com"], "scheduler"
    )
    self.assertEqual(mock_cloud_logging.call_count, 11)
    self.assertEqual(mock_get_subdomains.call_count, 2)
    self.assertEqual(mock_get_enriched_domains.call_count, 1)
    self.assertEqual(mock_add_domains_to_redis.call_count, 1)
    self.assertEqual(mock_get_value_from_secret_manager.call_count, 1)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}domaintool_client.DomainToolClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_enriched_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_subdomains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_domains_to_redis")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.utils.get_value_from_secret_manager"
  )
  def test_get_and_ingest_events_large_domain_list(
      self,
      mock_get_value_from_secret_manager,
      mock_add_domains_to_redis,
      mock_get_subdomains,
      mock_get_enriched_domains,
      mock_domain_tool_client,
      mock_client_hget,
      mock_ingest,
      mocked_get_env_var,
  ):
    """Test case when more domains supplied for enrichment."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "test-secret/dnsdb-api-key/version/1",
        "",
        "500",
    ]
    mock_domain_tool_client.return_value = None
    mock_client_hget.return_value = False
    mock_get_enriched_domains.side_effect = [
        {
            "results": [
                {"domain": "test_domain.com"},
                {"domain": "test_domain_2.com"},
            ]
        },
        {
            "results": [
                {"domain": "test_domain_3.com"},
                {"domain": "test_domain_5.com"},
            ]
        },
        {
            "results": [
                {"domain": "test_domain_6.com"},
                {"domain": "test_domain_6.com"},
            ]
        },
        {
            "results": [
                {"domain": "test_domain_7.com"},
                {"domain": "test_domain_8.com"},
            ]
        },
    ]
    mock_get_subdomains.return_value = [{"domain": "*.com", "count": 10}]
    mock_ingest.get_reference_list.return_value = ["test_domain.com"]
    mock_ingest.ingest.return_value = True
    mock_add_domains_to_redis.return_value = True
    mock_get_value_from_secret_manager.return_value = "API_KEY"
    main.get_and_ingest_events(
        "Test_log_type", generate_domains(300), "scheduler"
    )
    self.assertEqual(mock_get_subdomains.call_count, 6)
    self.assertEqual(mock_get_enriched_domains.call_count, 3)
    self.assertEqual(mock_get_value_from_secret_manager.call_count, 1)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}domaintool_client.DomainToolClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_enriched_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_subdomains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_domains_to_redis")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.utils.get_value_from_secret_manager"
  )
  def test_get_and_ingest_events_runtime_error(
      self,
      mock_get_value_from_secret_manager,
      mock_add_domains_to_redis,
      mock_get_subdomains,
      mock_get_enriched_domains,
      mock_domain_tool_client,
      mock_client_hget,
      mock_ingest,
      mocked_get_env_var,
  ):
    """Test case when RunTimeError occurres."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "test-secret/dnsdb-api-key/version/1",
        "allow_list",
        "500",
    ]
    mock_domain_tool_client.return_value = None
    mock_client_hget.return_value = False
    mock_get_enriched_domains.side_effect = [
        {
            "results": [
                {
                    "domain": "test_domain.com",
                    "domain_risk": {
                        "risk_score": 35,
                        "components": [{"evidence": ["provisional"]}],
                    },
                },
                {"domain": "test_domain_2.com"},
            ]
        },
        {
            "results": [
                {"domain": "test_domain_3.com"},
                {"domain": "test_domain_5.com"},
            ]
        },
        {
            "results": [
                {"domain": "test_domain_6.com"},
                {"domain": "test_domain_6.com"},
            ]
        },
    ]
    mock_get_subdomains.return_value = [{"domain": "*.com", "count": 10}]
    mock_ingest.get_reference_list.side_effect = Exception(
        "Error in getting reference list"
    )
    mock_ingest.ingest.side_effect = Exception("Error in ingesting logs")
    mock_add_domains_to_redis.return_value = True
    mock_get_value_from_secret_manager.return_value = "API_KEY"

    with self.assertRaises(RuntimeError):
      main.get_and_ingest_events(
          "Test_label", generate_domains(201), "scheduler"
      )
    self.assertEqual(mock_get_subdomains.call_count, 6)
    self.assertEqual(mock_get_enriched_domains.call_count, 3)
    self.assertEqual(mock_get_value_from_secret_manager.call_count, 1)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}domaintool_client.DomainToolClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_enriched_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_subdomains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_domains_to_redis")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.utils.get_value_from_secret_manager"
  )
  def test_get_and_ingest_events_get_reference_list_exception(
      self,
      mock_get_value_from_secret_manager,
      mock_add_domains_to_redis,
      mock_get_subdomains,
      mock_get_enriched_domains,
      mock_domain_tool_client,
      mock_client_hget,
      mock_ingest,
      mocked_get_env_var,
  ):
    """Test case when exception occurres in get_reference_list method."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "test-secret/dnsdb-api-key/version/1",
        "",
        "500",
    ]
    mock_domain_tool_client.return_value = None
    mock_client_hget.return_value = False
    mock_get_enriched_domains.side_effect = [
        {
            "results": [
                {
                    "domain": "test_domain.com",
                    "domain_risk": {
                        "risk_score": 35,
                        "components": [{"evidence": ["provisional"]}],
                    },
                },
                {"domain": "test_domain_2.com"},
            ]
        },
        {
            "results": [
                {"domain": "test_domain_3.com"},
                {"domain": "test_domain_5.com"},
            ]
        },
        {
            "results": [
                {"domain": "test_domain_6.com"},
                {"domain": "test_domain_6.com"},
            ]
        },
    ]
    mock_get_subdomains.return_value = [{"domain": "*.com", "count": 10}]
    mock_ingest.get_reference_list.side_effect = Exception(
        "Error in getting reference list"
    )
    mock_ingest.ingest.return_value = True
    mock_add_domains_to_redis.return_value = True
    mock_get_value_from_secret_manager.return_value = "API_KEY"

    main.get_and_ingest_events("Test_label", ["test_domain_1"], "scheduler")
    self.assertEqual(mock_get_subdomains.call_count, 2)
    self.assertEqual(mock_get_enriched_domains.call_count, 1)
    self.assertEqual(mock_get_value_from_secret_manager.call_count, 1)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}domaintool_client.DomainToolClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_enriched_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_subdomains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_domains_to_redis")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.utils.get_value_from_secret_manager"
  )
  def test_get_and_ingest_events_bulk_enrichment(
      self,
      mock_get_value_from_secret_manager,
      mock_add_domains_to_redis,
      mock_get_subdomains,
      mock_get_enriched_domains,
      mock_domain_tool_client,
      mock_client_hget,
      mock_ingest,
      mocked_get_env_var,
  ):
    """Test case when method get_and_ingest_event called with bulk_enrichment argument."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "test-secret/dnsdb-api-key/version/1",
        "500",
    ]
    mock_domain_tool_client.return_value = None
    mock_client_hget.side_effect = [True, False]
    mock_get_enriched_domains.return_value = {
        "results": [
            {"domain": "test_domain.com"},
            {"domain": "test_domain2.com"},
        ]
    }
    mock_get_subdomains.return_value = [{"domain": "*.com", "count": 10}]
    mock_ingest.get_reference_list.return_value = ["test_domain.com"]
    mock_ingest.ingest.return_value = True
    mock_add_domains_to_redis.return_value = True
    mock_get_value_from_secret_manager.return_value = "API_KEY"
    main.get_and_ingest_events(
        "Test_log_type",
        ["test_domain.com", "test_domain2.com"],
        "bulk_enrichment",
    )
    self.assertEqual(mock_get_subdomains.call_count, 0)
    self.assertEqual(mock_get_enriched_domains.call_count, 1)
    self.assertEqual(mock_get_value_from_secret_manager.call_count, 1)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}domaintool_client.DomainToolClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_enriched_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_subdomains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_domains_to_redis")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.utils.get_value_from_secret_manager"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_get_and_ingest_events_monitoring_domain(
      self,
      mock_cloud_logging,
      mock_get_value_from_secret_manager,
      mock_add_domains_to_redis,
      mock_get_subdomains,
      mock_get_enriched_domains,
      mock_domain_tool_client,
      mock_client_hget,
      mock_ingest,
      mocked_get_env_var,
  ):
    """Test case when method get_and_ingest_event called with monitoring_domain argument."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "test-secret/dnsdb-api-key/version/1",
        "500",
    ]
    mock_domain_tool_client.return_value = None
    mock_client_hget.side_effect = [True, False]
    mock_get_enriched_domains.return_value = {
        "results": [
            {"domain": "test_domain.com"},
            {"domain": "test_domain2.com"},
        ]
    }
    mock_get_subdomains.side_effect = [{"domain": "*.com", "count": 10}]
    mock_ingest.get_reference_list.return_value = ["test_domain.com"]
    mock_ingest.ingest.return_value = True
    mock_add_domains_to_redis.return_value = True
    mock_get_value_from_secret_manager.return_value = "API_KEY"
    main.get_and_ingest_events(
        "Test_log_type",
        ["test_domain.com", "test_domain2.com"],
        "monitoring_domain",
        "monitor_list",
    )
    self.assertEqual(mock_cloud_logging.call_count, 6)
    self.assertEqual(mock_get_subdomains.call_count, 0)
    self.assertEqual(mock_get_enriched_domains.call_count, 1)
    self.assertEqual(mock_get_value_from_secret_manager.call_count, 1)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hget")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}domaintool_client.DomainToolClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_enriched_domains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_subdomains")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.add_domains_to_redis")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.utils.get_value_from_secret_manager"
  )
  def test_get_and_ingest_events_subdomain_exception(
      self,
      mock_get_value_from_secret_manager,
      mock_add_domains_to_redis,
      mock_get_subdomains,
      mock_get_enriched_domains,
      mock_domain_tool_client,
      mock_client_hget,
      mock_ingest,
      mocked_get_env_var,
  ):
    """Test case when Exception occurres in get_subdomains method."""
    mocked_get_env_var.side_effect = [
        "test-user",
        "test-password",
        "test-secret/dnsdb-api-key/version/1",
        "allow_list",
        "500",
    ]
    mock_domain_tool_client.return_value = None
    mock_client_hget.return_value = False
    mock_get_enriched_domains.return_value = {
        "results": [
            {"domain": "test_domain_6.com"},
            {"domain": "test_domain_6.com"},
        ]
    }
    mock_get_subdomains.side_effect = Exception("Error in ingesting logs")
    mock_ingest.get_reference_list.return_value = ["domain.com"]
    mock_ingest.ingest.return_value = True
    mock_add_domains_to_redis.return_value = True
    mock_get_value_from_secret_manager.return_value = "API_KEY"

    with self.assertRaises(Exception):
      main.get_and_ingest_events(
          "Test_label", ["domain.com", "domain_1.com"], "scheduler"
      )
    self.assertEqual(mock_get_subdomains.call_count, 1)
    self.assertEqual(mock_get_enriched_domains.call_count, 1)
    self.assertEqual(mock_get_value_from_secret_manager.call_count, 1)
    self.assertEqual(mock_add_domains_to_redis.call_count, 0)

  # get_enriched_domains method
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.domaintool_client.DomainToolClient.generate_api"
  )
  def test_get_enriched_domains_success(
      self, mock_generate_api, unused_mocked_get_env_var
  ):
    """Test case when API returns NotAuthorizedException Exception."""
    mock_resp = mock.Mock(spec=main.domaintool_client.domaintools.API)
    mock_resp.iris_enrich.return_value.response.return_value = [
        "test1",
        "test2",
    ]
    mock_generate_api.return_value = mock_resp

    domaintools_client = main.domaintool_client.DomainToolClient(
        "test_user", "test_key"
    )
    response = main.get_enriched_domains(
        domaintools_client, generate_domains(5)
    )
    self.assertEqual(response, ["test1", "test2"])

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.domaintool_client.DomainToolClient.generate_api"
  )
  def test_get_enriched_domains_notauthorized_exception(
      self, mock_generate_api, unused_mocked_get_env_var
  ):
    """Test case when API returns NotAuthorizedException Exception."""
    mock_resp = mock.Mock(spec=main.domaintool_client.domaintools.API)
    mock_resp.iris_enrich.side_effect = NotAuthorizedException(
        401, "Invalid API key"
    )
    mock_generate_api.return_value = mock_resp

    domaintools_client = main.domaintool_client.DomainToolClient(
        "test_user", "test_key"
    )
    with self.assertRaises(NotAuthorizedException):
      main.get_enriched_domains(domaintools_client, generate_domains(5))

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.domaintool_client.DomainToolClient.generate_api"
  )
  def test_get_enriched_domains_exception(
      self, mock_generate_api, unused_mocked_get_env_var
  ):
    """Test case when API returns general Exception."""
    mock_resp = mock.Mock(spec=main.domaintool_client.domaintools.API)
    mock_resp.iris_enrich.side_effect = Exception("Error in api call")
    mock_generate_api.return_value = mock_resp

    domaintools_client = main.domaintool_client.DomainToolClient(
        "test_user", "test_key"
    )
    with self.assertRaises(Exception):
      main.get_enriched_domains(domaintools_client, generate_domains(5))

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.domaintool_client.DomainToolClient.generate_api"
  )
  @mock.patch("time.sleep")
  def test_get_enriched_domains_service_unavailable_exception(
      self,
      mock_time,
      mock_generate_api,
      unused_mocked_get_env_var,
  ):
    """Test case when API returns ServiceUnavailableException Exception."""
    mock_resp = mock.Mock(spec=main.domaintool_client.domaintools.API)
    mock_resp.iris_enrich.side_effect = ServiceUnavailableException(
        503, "Error in api call"
    )
    mock_generate_api.return_value = mock_resp

    domaintools_client = main.domaintool_client.DomainToolClient(
        "test_user", "test_key"
    )
    with self.assertRaises(ServiceUnavailableException):
      main.get_enriched_domains(domaintools_client, generate_domains(5))
    self.assertEqual(mock_time.call_count, 2)

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.domaintool_client.DomainToolClient.generate_api"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_get_enriched_domains_proxy_error_exception(
      self,
      mock_cloud_logging,
      mock_generate_api,
      unused_mocked_get_env_var,
  ):
    """Test case when API returns requests.exceptions.ProxyError Exception."""
    mock_resp = mock.Mock(spec=main.domaintool_client.domaintools.API)
    mock_resp.iris_enrich.side_effect = requests.exceptions.ProxyError(
        "Error in api call"
    )
    mock_generate_api.return_value = mock_resp

    domaintools_client = main.domaintool_client.DomainToolClient(
        "test_user", "test_key"
    )
    main.get_enriched_domains(domaintools_client, generate_domains(5))
    self.assertEqual(mock_cloud_logging.call_count, 1)

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}main.domaintool_client.DomainToolClient.generate_api"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_get_enriched_domains_ssl_error_exception(
      self,
      mock_cloud_logging,
      mock_generate_api,
      unused_mocked_get_env_var,
  ):
    """Test case when API returns requests.exceptions.SSLError Exception."""
    mock_resp = mock.Mock(spec=main.domaintool_client.domaintools.API)
    mock_resp.iris_enrich.side_effect = requests.exceptions.SSLError(
        "Error in api call"
    )
    mock_generate_api.return_value = mock_resp

    domaintools_client = main.domaintool_client.DomainToolClient(
        "test_user", "test_key"
    )
    main.get_enriched_domains(domaintools_client, generate_domains(5))
    self.assertEqual(mock_cloud_logging.call_count, 1)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}domaintool_client.DomainToolClient")
  def test_get_enriched_domains_no_data(
      self, mock_domain_tool_client, unused_mocked_get_env_var
  ):
    """Test when get_enriched_domains method called with empty data."""
    response = main.get_enriched_domains(mock_domain_tool_client, [])
    self.assertIs(response, None)

  # add_domains_to_redis method
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hmset")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.expire")
  def test_add_domains_to_redis_success(
      self, mock_client_expire, mock_client_hmset, mocked_get_env_var
  ):
    """Test case when add_domains_to_redis passess successfully."""
    redis_data = [{
        "value": "test.com",
        "created_timestamp": "2023-12-12T10:50:10Z",
        "evidence": "",
    }]
    mock_client_hmset.return_value = True
    mock_client_expire.return_value = True
    mocked_get_env_var.side_effect = ["10", "5"]
    main.add_domains_to_redis(redis_data)
    self.assertEqual(
        mocked_get_env_var.mock_calls[0],
        mock.call("PROVISIONAL_TTL", required=False, default="1"),
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hmset")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.expire")
  def test_add_domains_to_redis_evidence_provisional(
      self, mock_client_expire, mock_client_hmset, mocked_get_env_var
  ):
    """Test case when value of evidence key is provisional then set ttl value to non_provisional_ttl."""
    redis_data = [{
        "value": "test.com",
        "created_timestamp": "2023-12-12T10:50:10Z",
        "evidence": "provisional",
    }]
    mock_client_hmset.return_value = True
    mock_client_expire.return_value = True
    mocked_get_env_var.side_effect = ["10", "5"]
    main.add_domains_to_redis(redis_data)
    self.assertEqual(
        mocked_get_env_var.mock_calls[1],
        mock.call("NON_PROVISIONAL_TTL", required=False, default="30"),
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.hmset")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.client.expire")
  def test_add_domains_to_redis_exception(
      self, mock_client_expire, mock_client_hmset, mocked_get_env_var
  ):
    """Test case when Exception occurres in adding data into redis."""
    redis_data = [{
        "value": "test.com",
        "created_timestamp": "2023-12-12T10:50:10Z",
        "evidence": "provisional",
    }]
    mock_client_hmset.side_effect = Exception("Error in adding data to redis")
    mock_client_expire.return_value = True
    mocked_get_env_var.side_effect = ["10", "5"]
    with self.assertRaises(Exception):
      main.add_domains_to_redis(redis_data)

  # get_subdomains method
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.requests.get")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_get_subdomains_success(
      self, mock_cloud_logging, mock_request, unused_mocked_get_env_var
  ):
    """Test case when get_subdomains passess successfully."""
    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.iter_lines.return_value = DNSDB_TEST_DATA
    mock_request.return_value = mock_response
    response = main.get_subdomains("API_KEY", "test.com")
    expected_result = [
        {
            "subdomain": "screenshots.ar.test.com",
            "first_seen": 1614295495,
            "last_seen": 1701905071,
            "count": 357,
        },
        {
            "subdomain": "screenshots.ar.test2.com",
            "first_seen": 1614295497,
            "last_seen": 1701905071,
            "count": 3495,
        },
        {
            "subdomain": "marketing.test2.com",
            "first_seen": 1311185207,
            "last_seen": 1701910597,
            "count": 104,
        },
        {
            "subdomain": "marketing.test.com",
            "first_seen": 1393454260,
            "last_seen": 1701910597,
            "count": 588,
        },
        {
            "subdomain": "covid-19.test.com",
            "first_seen": 1585079396,
            "last_seen": 1701906724,
            "count": 296,
        },
        {
            "subdomain": "covid-20.test.com",
            "first_seen": 1585079396,
            "last_seen": 1701906724,
            "count": 300,
        },
        {
            "subdomain": "covid-21.test.com",
            "first_seen": 1585079396,
            "last_seen": 1701906728,
            "count": 482,
        },
        {
            "subdomain": "covid-22.test.com",
            "first_seen": 1585079396,
            "last_seen": 1701906724,
            "count": 374,
        },
        {
            "subdomain": "covid-23.test.com",
            "first_seen": 1585079396,
            "last_seen": 1701906723,
            "count": 98,
        },
        {
            "subdomain": "covid-24.test.com",
            "first_seen": 1585079396,
            "last_seen": 1701906724,
            "count": 15,
        },
    ]
    self.assertEqual(len(response), 10)
    self.assertEqual(response, expected_result)
    self.assertEqual(mock_cloud_logging.call_count, 0)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.requests.get")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_get_subdomains_error(
      self, mock_cloud_logging, mock_request, unused_mocked_get_env_var
  ):
    """Test when get_subdomains fails with API error."""
    mock_response = mock.Mock()
    mock_response.status_code = 401
    mock_response.iter_lines.return_value = DNSDB_TEST_DATA
    mock_request.return_value = mock_response
    with self.assertRaises(Exception):
      main.get_subdomains("API_KEY", "test.com")
    self.assertEqual(mock_cloud_logging.call_count, 1)

  def test_invalid_json(self, mocked_get_env_var):
    """Test Invalid json provided to cloud function."""
    mocked_get_env_var.side_effect = [
        "5",
        "10",
        "100",
        "1.2.3.4",
        "1234",
        "test_user",
        "test_key",
    ]
    request_object = requests.Request(data="test")
    response = main.main(request_object)
    self.assertEqual(
        response,
        "Ingestion not completed due to error in parameter.\n",
    )

  def test_a_invalid_argument(self, mocked_get_env_var):
    """Test a Invalid argument in cloud function."""
    mocked_get_env_var.side_effect = [
        "5",
        "10",
        "100",
        "1.2.3.4",
        "1234",
        "test_user",
        "test_key",
    ]
    request_object = requests.Request(data='{"allow": true}')
    response = main.main(request_object)
    self.assertEqual(
        response,
        "Provide valid parameters for adhoc.\n",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.allow_tags_dummy_ingest")
  def test_valid_allow_list_argument(
      self, mocked_allow_tags_dummy_ingest, mocked_get_env_var
  ):
    """Test valid allow_list argument for adhoc."""
    mocked_allow_tags_dummy_ingest.return_value = None
    mocked_get_env_var.side_effect = [
        "5",
        "10",
        "100",
        "test",
        "1.2.3.4",
        "1234",
        "test_user",
        "test_key",
    ]
    request_object = requests.Request(data='{"allow_list": true}')
    response = main.main(request_object)
    self.assertEqual(
        response,
        "Ingestion Completed",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.allow_tags_dummy_ingest")
  def test_valid_monitoring_tags_argument(
      self, mocked_allow_tags_dummy_ingest, mocked_get_env_var
  ):
    """Test valid monitoring_tags argument for adhoc."""
    mocked_allow_tags_dummy_ingest.return_value = None
    mocked_get_env_var.side_effect = [
        "5",
        "10",
        "100",
        "test",
        "1.2.3.4",
        "1234",
        "test_user",
        "test_key",
    ]
    request_object = requests.Request(data='{"monitoring_tags": true}')
    response = main.main(request_object)
    self.assertEqual(
        response,
        "Ingestion Completed",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.monitoring_bulk_ingest")
  def test_valid_monitoring_list_argument(
      self, mocked_monitoring_bulk_ingest, mocked_get_env_var
  ):
    """Test valid monitoring_list argument for adhoc."""
    mocked_monitoring_bulk_ingest.return_value = None
    mocked_get_env_var.side_effect = [
        "5",
        "10",
        "100",
        "test",
        "1.2.3.4",
        "1234",
        "test_user",
        "test_key",
    ]
    request_object = requests.Request(data='{"monitoring_list": true}')
    response = main.main(request_object)
    self.assertEqual(
        response,
        "Ingestion Completed",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.monitoring_bulk_ingest")
  def test_valid_bulk_enrichment_argument(
      self, mocked_monitoring_bulk_ingest, mocked_get_env_var
  ):
    """Test valid bulk_enrichment argument for adhoc."""
    mocked_monitoring_bulk_ingest.return_value = None
    mocked_get_env_var.side_effect = [
        "5",
        "10",
        "100",
        "test",
        "1.2.3.4",
        "1234",
        "test_user",
        "test_key",
    ]
    request_object = requests.Request(data='{"bulk_enrichment": true}')
    response = main.main(request_object)
    self.assertEqual(
        response,
        "Ingestion Completed",
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  def test_dummy_ingest_success_allow_list(
      self, mocked_ingest, mocked_get_reference_list, unused_mocked_get_env_var
  ):
    """Test success for allow_tags_dummy_ingest function for allow_list."""
    mocked_get_reference_list.return_value = ["test.com"]
    mocked_ingest.return_value = None
    response = main.allow_tags_dummy_ingest("test", "allow_list")
    self.assertIsNone(response)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  def test_dummy_ingest_success_tags(
      self, mocked_ingest, mocked_get_reference_list, unused_mocked_get_env_var
  ):
    """Test success for allow_tags_dummy_ingest function for monitoring_tags."""
    mocked_get_reference_list.return_value = ["test"]
    mocked_ingest.return_value = None
    response = main.allow_tags_dummy_ingest("test", "monitoring_tags")
    self.assertIsNone(response)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  def test_dummy_ingest_no_domains(
      self, mocked_get_reference_list, unused_mocked_get_env_var
  ):
    """Test for allow_tags_dummy_ingest function for no domains."""
    mocked_get_reference_list.return_value = []
    response = main.allow_tags_dummy_ingest("test", "allow_list")
    self.assertIsNone(response)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
  def test_dummy_ingest_failure_ingest(
      self, mocked_ingest, mocked_get_reference_list, unused_mocked_get_env_var
  ):
    """Test Exception for allow_tags_dummy_ingest function in ingestion."""
    mocked_get_reference_list.return_value = ["test"]
    mocked_ingest.side_effect = Exception()
    response = main.allow_tags_dummy_ingest("test", "allow_list")
    self.assertEqual(response, "Ingestion not completed")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  def test_dummy_ingest_failure_get_reference(
      self, mocked_get_reference_list, unused_mocked_get_env_var
  ):
    """Test Exception for allow_tags_dummy_ingest function in reference list."""
    mocked_get_reference_list.side_effect = Exception()
    response = main.allow_tags_dummy_ingest("test", "allow_list")
    self.assertIsNone(response)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  def test_monitor_bulk_enrich_failure_get_reference(
      self, mocked_get_reference_list, unused_mocked_get_env_var
  ):
    """Test Exception for monitoring_bulk_ingest function in reference list."""
    mocked_get_reference_list.side_effect = Exception()
    response = main.monitoring_bulk_ingest("test", "monitoring_domain")
    self.assertIsNone(response)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_events")
  def test_monitor_bulk_enrich_failure_ingest(
      self,
      mocked_get_and_ingest_events,
      mocked_get_reference_list,
      unused_mocked_get_env_var,
  ):
    """Test Exception for monitoring_bulk_ingest function in ingesting events."""
    mocked_get_reference_list.return_value = ["test.com"]
    mocked_get_and_ingest_events.side_effect = RuntimeError()
    response = main.monitoring_bulk_ingest("test", "monitoring_domain")
    self.assertEqual(response, "Ingestion not completed.")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.get_reference_list")
  def test_monitor_bulk_enrich_no_domains(
      self, mocked_get_reference_list, unused_mocked_get_env_var
  ):
    """Test monitoring_bulk_ingest function for no domains."""
    mocked_get_reference_list.return_value = []
    response = main.monitoring_bulk_ingest("test", "monitoring_domain")
    self.assertIsNone(response)

  def test_check_valid_arguments_invalid(self, unused_mocked_get_env_var):
    """Test check_valid_arguments function for invalid argument."""
    response = main.check_valid_arguments("test", "test")
    self.assertEqual(response, False)

  def test_check_valid_arguments_false(self, unused_mocked_get_env_var):
    """Test check_valid_arguments function for false argument."""
    response = main.check_valid_arguments("test", "false")
    self.assertEqual(response, False)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.allow_tags_dummy_ingest")
  def test_adhoc_function_failure_allow_list(
      self, mocked_allow_tags_dummy_ingest, mocked_get_env_var
  ):
    """Test adhoc_function function for failure in allow_list."""
    mocked_get_env_var.side_effect = ["test"]
    mocked_allow_tags_dummy_ingest.return_value = "Ingestion not completed"
    response = main.adhoc_function(allow_list=True)
    self.assertEqual(response, "Ingestion not completed")

  def test_adhoc_function_undefined_allow_list(self, mocked_get_env_var):
    """Test adhoc_function function for not providing allow_list reference name in environment variable."""
    mocked_get_env_var.side_effect = [""]
    response = main.adhoc_function(allow_list=True)
    self.assertEqual(response, "Ingestion Completed")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.allow_tags_dummy_ingest")
  def test_adhoc_function_failure_monitoring_tags(
      self, mocked_allow_tags_dummy_ingest, mocked_get_env_var
  ):
    """Test adhoc_function function for failure in monitoring_tags."""
    mocked_get_env_var.side_effect = ["test"]
    mocked_allow_tags_dummy_ingest.return_value = "Ingestion not completed"
    response = main.adhoc_function(monitoring_tags=True)
    self.assertEqual(response, "Ingestion not completed")

  def test_adhoc_function_undefined_monitoring_tags(self, mocked_get_env_var):
    """Test adhoc_function function for not providing monitoring_tags reference name in environment variable."""
    mocked_get_env_var.side_effect = [""]
    response = main.adhoc_function(monitoring_tags=True)
    self.assertEqual(response, "Ingestion Completed")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.monitoring_bulk_ingest")
  def test_adhoc_function_failure_monitoring_list(
      self, mocked_monitoring_bulk_ingest, mocked_get_env_var
  ):
    """Test adhoc_function function for failure in monitoring_list."""
    mocked_get_env_var.side_effect = ["test"]
    mocked_monitoring_bulk_ingest.return_value = "Ingestion not completed"
    response = main.adhoc_function(monitoring_list=True)
    self.assertEqual(response, "Ingestion not completed")

  def test_adhoc_function_undefined_monitoring_list(self, mocked_get_env_var):
    """Test adhoc_function function for not providing monitoring_tags reference name in environment variable."""
    mocked_get_env_var.side_effect = [""]
    response = main.adhoc_function(monitoring_list=True)
    self.assertEqual(response, "Ingestion Completed")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.monitoring_bulk_ingest")
  def test_adhoc_function_failure_bulk_enrichment(
      self, mocked_monitoring_bulk_ingest, mocked_get_env_var
  ):
    """Test adhoc_function function for failure in bulk_enrichment."""
    mocked_get_env_var.side_effect = ["test"]
    mocked_monitoring_bulk_ingest.return_value = "Ingestion not completed"
    response = main.adhoc_function(bulk_enrichment=True)
    self.assertEqual(response, "Ingestion not completed")

  def test_adhoc_function_undefined_bulk_enrichment(self, mocked_get_env_var):
    """Test adhoc_function function for not providing bulk_enrichment reference name in environment variable."""
    mocked_get_env_var.side_effect = [""]
    response = main.adhoc_function(bulk_enrichment=True)
    self.assertEqual(response, "Ingestion Completed")

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.scheduled_cloud_function")
  def test_main_success(
      self, mock_scheduled_cloud_function, mocked_get_env_var
  ):
    """Test case to verify main method passess successfully for scheduled environment."""
    mocked_get_env_var.side_effect = [
        "5",
        "10",
        "50",
        "1.2.3.4",
        "1234",
        "test_user",
        "test_key",
    ]
    mock_scheduled_cloud_function.return_value = "Ingestion Completed"
    response = main.main(request=requests.Request(data=None))
    self.assertEqual(
        response,
        "Ingestion Completed",
    )
