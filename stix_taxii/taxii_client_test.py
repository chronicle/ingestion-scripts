# Copyright 2022 Google LLC
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
"""Unit test case file to test the taxii_client module of STIX/TAXII ingestion script."""

import io
import sys

# copybara:insert(imports) import unittest
from unittest import mock

import requests_mock

# copybara:strip_begin(imports)
from google3.testing.pybase import googletest
# copybara:strip_end

INGESTION_SCRIPTS_PATH = "google3.third_party.chronicle.ingestion_scripts"
sys.modules[f"{INGESTION_SCRIPTS_PATH}.common.ingest"] = mock.Mock()

# copybara:strip_begin(imports)
from stix_taxii import taxii_client  # pylint: disable=g-import-not-at-top
# copybara:strip_end

# Headers constants.
TAXII_V21_HEADERS = {"Content-Type": "application/taxii+json;version=2.1"}
TAXII_V20_HEADERS = {
    "Content-Type": "application/vnd.oasis.taxii+json;version=2.0"
}
TAXII_V11_HEADERS = {
    "Content-Type": "application/xml",
    "X-Taxii-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
    "X-Taxii-Protocol": "urn:taxii.mitre.org:protocol:http:1.0",
    "X-Taxii-Services": "urn:taxii.mitre.org:services:1.1"
}

# File path constants.
TEST_DATA_DIR = "test_data"
TEST_TAXII_V11_DISCOVERY_RESP = f"{TEST_DATA_DIR}/taxii_v11_discovery_response.xml"
TEST_TAXII_V11_COLLECTIONS_RESP = f"{TEST_DATA_DIR}/taxii_v11_collections_response.xml"
TEST_TAXII_v11_INDICATOR_EMPTY_RESP = f"{TEST_DATA_DIR}/taxii_v11_indicators_response_empty.xml"
TEST_TAXII_V11_INDICATOR_PAGE_1_RESP = f"{TEST_DATA_DIR}/taxii_v11_indicators_response_page_1.xml"
TEST_TAXII_V11_DISCOVERY_RESP_WITHOUT_CMS = f"{TEST_DATA_DIR}/taxii_v11_discovery_response_without_collection_management.xml"

# Test taxii hostname.
TEST_HOSTNAME = "https://dummy.com/"

# Test discovery url.
TEST_DISCOVERY_URL = f"{TEST_HOSTNAME}taxii/"

# Dummy username and password.
TEST_USERNAME = "test_username"
TEST_PASSWORD = "test_password"


# copybara:insert(imports) class TestTaxiiClientVersion11(unittest.TestCase):
class TestTaxiiClientVersion11(googletest.TestCase):
  """Test cases for TAXII Client version 1.1."""

  def setUp(self):
    """Set up method to be called before every test case."""
    super().setUp()
    self.requests_mock = requests_mock.Mocker()
    with open(
        TEST_TAXII_V11_DISCOVERY_RESP, "r", encoding="utf-8") as file:
      mock_xml_discovery = "".join(file.readlines())

    with open(
        TEST_TAXII_V11_COLLECTIONS_RESP, "r",
        encoding="utf-8") as file:
      mock_xml_collections = "".join(file.readlines())

    self.requests_mock.post(
        TEST_DISCOVERY_URL,
        body=io.BytesIO(mock_xml_discovery.encode("utf-8")),
        headers=TAXII_V11_HEADERS)

    self.requests_mock.post(
        f"{TEST_DISCOVERY_URL}collection/",
        body=io.BytesIO(mock_xml_collections.encode("utf-8")),
        headers=TAXII_V11_HEADERS)

    self.requests_mock.start()
    self.mock_client = taxii_client.TAXIIClient(
        discovery_url=TEST_DISCOVERY_URL,
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        taxii_version=taxii_client.TAXII_VERSION_11,
        collection_names="test")

  def tearDown(self):
    """Tear down method to be called after every test case."""
    super().tearDown()
    self.requests_mock.stop()

  def test_create_client_with_valid_configuration_params(self):
    """Test case to verify the client should not raise error when valid configuration parameter provided.
    """
    self.assertEqual(self.mock_client.collection_names, ["test"])
    self.assertEqual(self.mock_client.taxii_version,
                     taxii_client.TAXII_VERSION_11)
    self.assertEqual(self.mock_client.discovery_url, TEST_DISCOVERY_URL)

  def test_pull_indicators_when_no_data_returned(self):
    """Test case to verify that pull_indicators method should return empty list when no data is returned from the TAXII Server.
    """
    with open(
        TEST_TAXII_v11_INDICATOR_EMPTY_RESP, "r",
        encoding="utf-8") as file:
      mock_xml_indicators = "".join(file.readlines())

    self.requests_mock.post(
        f"{TEST_DISCOVERY_URL}poll/",
        body=io.BytesIO(mock_xml_indicators.encode("utf-8")),
        headers=TAXII_V11_HEADERS)

    self.assertEqual(
        self.mock_client.pull_indicators(start_time="2022-11-14T00:00:00.000Z"),
        [])

  def test_pull_indicators_when_valid_data_returned(self):
    """Test case to verify that pull_indicators method should return valid list of indicators when data is received from the TAXII Server.
    """
    with open(
        TEST_TAXII_V11_INDICATOR_PAGE_1_RESP, "r",
        encoding="utf-8") as file:
      mock_xml_indicators_page_1 = "".join(file.readlines())

    self.requests_mock.post(
        f"{TEST_DISCOVERY_URL}poll/",
        body=io.BytesIO(mock_xml_indicators_page_1.encode("utf-8")),
        headers=TAXII_V11_HEADERS)

    indicators = self.mock_client.pull_indicators(
        start_time="2022-11-14T00:00:00.000Z")

    self.assertEqual([i.get("id") for i in indicators], ["id1", "id2"])

  def test_validate_collections_when_no_cms_found(self):
    """Test case to verify that an InvalidValueError should be raised if no collection management service found from discovery response.
    """
    with open(
        TEST_TAXII_V11_DISCOVERY_RESP_WITHOUT_CMS, "r",
        encoding="utf-8") as file:
      mock_xml_discovery = "".join(file.readlines())

    self.requests_mock.post(
        TEST_DISCOVERY_URL,
        body=io.BytesIO(mock_xml_discovery.encode("utf-8")),
        headers=TAXII_V11_HEADERS)

    self.assertRaises(taxii_client.InvalidValueError, taxii_client.TAXIIClient,
                      TEST_DISCOVERY_URL, TEST_USERNAME, TEST_PASSWORD,
                      taxii_client.TAXII_VERSION_11, "test")


# copybara:insert(imports) class TestTaxiiClientVersion20(unittest.TestCase):
class TestTaxiiClientVersion20(googletest.TestCase):
  """Test cases for TAXII Client version 2.0."""

  def setUp(self):
    """Set up method to be called before every test case."""
    super().setUp()
    self.requests_mock = requests_mock.Mocker()

    mock_json_discovery = {
        "title": "Mock taxii server",
        "default": TEST_HOSTNAME,
        "api_roots": [TEST_HOSTNAME]
    }
    mock_json_collections = {
        "collections": [{
            "id": "test-id",
            "title": "test",
            "can_read": True,
            "can_write": False
        }, {
            "id": "test-id2",
            "title": "test2",
            "can_read": True,
            "can_write": False
        }]
    }

    self.requests_mock.get(
        TEST_DISCOVERY_URL,
        json=mock_json_discovery,
        headers=TAXII_V20_HEADERS)

    self.requests_mock.get(
        f"{TEST_HOSTNAME}collections/",
        json=mock_json_collections,
        headers=TAXII_V20_HEADERS)

    self.requests_mock.start()
    self.mock_client = taxii_client.TAXIIClient(
        discovery_url=f"{TEST_HOSTNAME}taxii/",
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        taxii_version=taxii_client.TAXII_VERSION_20,
        collection_names="test")

  def tearDown(self):
    """Tear down method to be called after every test case."""
    super().tearDown()
    self.requests_mock.stop()

  def test_create_client_with_valid_configuration_params(self):
    """Test case to verify the client should not raise error when valid configuration parameter provided.
    """
    self.assertEqual(self.mock_client.collection_names, ["test"])
    self.assertEqual(self.mock_client.discovery_url, TEST_DISCOVERY_URL)
    self.assertEqual(self.mock_client.taxii_version,
                     taxii_client.TAXII_VERSION_20)

  def test_create_client_when_invalid_collection_name_provided(self):
    """Test case to verify that an InvalidValueError should be raised if the provided collection name does not exist on server.
    """
    self.assertRaises(taxii_client.InvalidValueError, taxii_client.TAXIIClient,
                      TEST_DISCOVERY_URL, TEST_USERNAME, TEST_PASSWORD,
                      taxii_client.TAXII_VERSION_20, "dummy")

  def test_pull_indicators_when_no_data_returned(self):
    """Test case to verify that pull_indicators method should return empty list when no data is returned from the TAXII Server.
    """
    mock_url = (f"{TEST_HOSTNAME}collections/test-id/objects/" +
                "?added_after=2022-11-14T00:00:00.000Z&match[type]=indicator")
    mock_json_indicators = {
        "type": "bundle",
        "id": "bundle--id",
        "spec_version": "2.0",
        "objects": []
    }

    self.requests_mock.get(mock_url, json=mock_json_indicators)

    self.assertEqual(
        self.mock_client.pull_indicators(start_time="2022-11-14T00:00:00.000Z"),
        [])


# copybara:insert(imports) class TestTaxiiClientVersion21(unittest.TestCase):
class TestTaxiiClientVersion21(googletest.TestCase):
  """Test cases for TAXII Client version 2.1."""

  def setUp(self):
    """Set up method to be called before every test case."""
    super().setUp()
    self.requests_mock = requests_mock.Mocker()

    mock_json_discovery = {
        "title": "Mock taxii server",
        "default": TEST_HOSTNAME,
        "api_roots": [TEST_HOSTNAME]
    }
    mock_json_collections = {
        "collections": [{
            "id": "test-id",
            "title": "test",
            "can_read": True,
            "can_write": False
        }, {
            "id": "test-id2",
            "title": "test2",
            "can_read": True,
            "can_write": False
        }]
    }

    self.requests_mock.get(
        f"{TEST_HOSTNAME}taxii2/",
        json=mock_json_discovery,
        headers=TAXII_V21_HEADERS)
    self.requests_mock.get(
        f"{TEST_HOSTNAME}collections/",
        json=mock_json_collections,
        headers=TAXII_V21_HEADERS)

    self.requests_mock.start()
    self.mock_client = taxii_client.TAXIIClient(
        discovery_url=f"{TEST_HOSTNAME}taxii2/",
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        taxii_version=taxii_client.TAXII_VERSION_21,
        collection_names="test")

  def tearDown(self):
    """Tear down method to be called after every test case."""
    super().tearDown()
    self.requests_mock.stop()

  def test_create_client_with_invalid_configuration_params(self):
    """Test case to verify the client should raise InvalidValueError when invalid configuration parameter provided.
    """
    self.assertRaises(taxii_client.InvalidValueError, taxii_client.TAXIIClient,
                      " ", TEST_USERNAME, TEST_PASSWORD,
                      taxii_client.TAXII_VERSION_21, "")
    self.assertRaises(taxii_client.InvalidValueError, taxii_client.TAXIIClient,
                      TEST_HOSTNAME, TEST_USERNAME, TEST_PASSWORD, "2.6", "")

  def test_create_client_with_valid_configuration_params(self):
    """Test case to verify the client should not raise error when valid configuration parameter provided.
    """
    self.assertEqual(self.mock_client.collection_names, ["test"])
    self.assertEqual(self.mock_client.discovery_url, f"{TEST_HOSTNAME}taxii2/")
    self.assertEqual(self.mock_client.taxii_version,
                     taxii_client.TAXII_VERSION_21)

  def test_create_client_when_invalid_collection_name_provided(self):
    """Test case to verify that an InvalidValueError should be raised if the provided collection name does not exist on server.
    """
    self.assertRaises(taxii_client.InvalidValueError, taxii_client.TAXIIClient,
                      f"{TEST_HOSTNAME}taxii2/", TEST_USERNAME,
                      TEST_PASSWORD, taxii_client.TAXII_VERSION_21,
                      "dummy")

  def test_pull_indicators_when_no_data_returned(self):
    """Test case to verify that pull_indicators method should return empty list when no data is returned from the TAXII Server.
    """
    mock_url = (
        f"{TEST_HOSTNAME}collections/test-id/objects/" +
        "?limit=1000&added_after=2022-11-14T00:00:00.000Z&match[type]=indicator"
    )
    mock_json_indicators = {"objects": [], "more": False}

    self.requests_mock.get(
        mock_url, json=mock_json_indicators, headers=TAXII_V21_HEADERS)

    self.assertEqual(
        self.mock_client.pull_indicators(start_time="2022-11-14T00:00:00.000Z"),
        [])

  def test_pull_indicators_when_valid_data_returned(self):
    """Test case to verify that pull_indicators method should return valid list of indicators when data is received from the TAXII Server.
    """
    mock_json_indicators_1 = {
        "objects": [{
            "id": "id1",
            "type": "indicator"
        }, {
            "id": "id2",
            "type": "indicator"
        }],
        "more": True,
        "next": 2
    }
    mock_json_indicators_2 = {
        "objects": [{
            "id": "id3",
            "type": "indicator"
        }, {
            "id": "id4",
            "type": "indicator"
        }],
        "more": False
    }

    mock_url_1 = (
        f"{TEST_HOSTNAME}collections/test-id/objects/" +
        "?limit=1000&added_after=2022-11-14T00:00:00.000Z&match[type]=indicator"
    )
    mock_url_2 = (
        f"{TEST_HOSTNAME}collections/test-id/objects/?limit=2" +
        "&next=2&added_after=2022-11-14T00:00:00.000Z&match[type]=indicator")

    self.requests_mock.get(
        mock_url_1, json=mock_json_indicators_1, headers=TAXII_V21_HEADERS)

    self.requests_mock.get(
        mock_url_2, json=mock_json_indicators_2, headers=TAXII_V21_HEADERS)

    indicators = self.mock_client.pull_indicators(
        start_time="2022-11-14T00:00:00.000Z")

    self.assertEqual([i.get("id") for i in indicators],
                     ["id1", "id2", "id3", "id4"])
