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
"""Unittest cases for fetch logs."""

import datetime
import json
import os
import unittest
from unittest import mock

import google_auth_httplib2
import httplib2

import fetch_logs

os.environ["CHRONICLE_CUSTOMER_ID"] = "test_id"
os.environ["CHRONICLE_SERVICE_ACCOUNT"] = """{
    "project_id": "1234"
}"""
INGESTION_SCRIPTS_PATH = ""
SAMPLE_RESPONSE = {
    "events": [{
        "udm": {
            "principal": {
                "hostname": "principal_host_1",
                "network": {"dns": {"questions": [{"name": "name_1"}]}},
            },
            "src": {
                "hostname": "test.com",
                "network": {"dns": {"questions": [{"name": "name_1"}]}},
            },
            "target": {
                "hostname": "target_host_1",
                "network": {"dns": {"questions": [{"name": "name_1"}]}},
            },
            "intermediary": [{
                "hostname": "intermediary_host_1",
                "administrativeDomain": "administrativeDomain_1",
                "domain": {"name": "domain_1"},
                "network": {
                    "dns": {"questions": [{"name": "name_1"}]},
                    "dnsDomain": "dnsDomain_1",
                },
                "asset": {
                    "hostname": "hostname_1",
                    "networkDomain": "networkDomain_1",
                },
                "url": "url_1",
            }],
            "observer": {
                "hostname": "observer_host_1",
                "network": {"dns": {"questions": [{"name": "name_1"}]}},
            },
            "about": [{
                "administrativeDomain": "about_admin_domain_1",
                "hostname": "about_host_1",
                "asset": {
                    "networkDomain": "networkDomain_1",
                    "hostname": "hostname_1",
                },
                "domain": {"name": "name_1"},
                "network": {
                    "dns": {"questions": [{"name": "name_1"}]},
                    "dnsDomain": "dnsDomain_1",
                },
                "url": "url_1",
            }],
            "network": {"dns": {"questions": [{"name": "name_1"}]}},
            "securityResult": [{"urlBackToProduct": "urlBackToProduct_1"}],
        }
    }],
    "moreDataAvailable": True,
}
fetch_object = fetch_logs.FetchEvents("test1")


@mock.patch(
    f"{INGESTION_SCRIPTS_PATH}fetch_logs.utils.get_env_var",
)
class TestFetchLogs(unittest.TestCase):
  """Test cases for Fetching logs from chronicle."""

  def test_divide_labels_empty(self, unused_mocked_get_env_var):
    """Test divide_labels function for empty data."""
    response = fetch_logs.FetchEvents("").divide_lable()
    self.assertEqual(response, [])

  def test_divide_labels_success(self, unused_mocked_get_env_var):
    """Test divide_labels function."""
    response = fetch_object.divide_lable()
    self.assertEqual(response, ["test1"])

  def test_get_parse_query(self, unused_mocked_get_env_var):
    """Test get_parse_query function which returns a query for Chronicle."""
    response = fetch_object.get_parse_query(["test1", "test2"], True)
    self.assertEqual(
        response,
        (
            '(metadata.log_type+%3D+"test1"+or+metadata.log_type+%3D+"test2")%20AND%20'
            "(about.hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www"
            "%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F"
            "(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20domain%20%3D"
            "%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%"
            "2F%3F%5Cn%5D%2B)%2F%20or%20about.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E"
            "@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20about.asset.hostname%20"
            "%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%"
            "5C%2F%3F%5Cn%5D%2B)%2F%20or%20about.network.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C"
            "%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20about"
            ".network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3"
            "F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.administrative_domain%20%3D%20%2F%5"
            "E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5C"
            "n%5D%2B)%2F%20or%20intermediary.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@"
            "%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.network.dns"
            ".questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:ww"
            "w%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.network.dns_domain%20%3D%20%2F%5E(%3F:h"
            "ttps%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B"
            ")%2F%20or%20intermediary.asset.hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%"
            "2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.asset.network_d"
            "omain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F("
            "%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.administrative_domain%20%3D%20%2F%5E(%3F:https%3F:%5C"
            "%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%2"
            "0observer.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F("
            "%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.network.dns.questions.name%20%3D%20%2"
            "F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F"
            "%5Cn%5D%2B)%2F%20or%20observer.network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%"
            "5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.asset.hos"
            "tname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F("
            "%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.asset.network_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%"
            "2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20"
            "principal.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F("
            "%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20principal.network.dns.questions.name%20%3D%20%"
            "2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3"
            "F%5Cn%5D%2B)%2F%20or%20principal.network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F"
            ":%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.administrati"
            "ve_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)"
            "%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%"
            "3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.networ"
            "k.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%"
            "3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.network.dns_domain%20%3D%20%2F%5E(%3F:https"
            "%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F"
            "%20or%20src.asset.network_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%"
            "5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20target.domain.name%20%3D%20%2F%5E(%"
            "3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5"
            "D%2B)%2F%20or%20target.network.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%"
            "5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20target.network.dns"
            "_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3"
            "F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F"
            "%20or%20principal.url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F("
            "%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20about.url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5"
            "C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src."
            "url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5"
            "B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20target.url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%"
            "5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.url%20%3"
            "D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C"
            "%2F%3F%5Cn%5D%2B)%2F%20or%20observer.url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C"
            "%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20metadata.url_back_to_produc"
            "t%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%"
            "5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20security_result.url_back_to_product%20%3D%20%2F%5E(%3F:https%3F:%5"
            "C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F)"
        ),
    )

  def test_get_parse_query_no_label(self, unused_mocked_get_env_var):
    """Test get_parse_query function with no label which returns a query for Chronicle."""
    response = fetch_object.get_parse_query([], False)
    self.assertEqual(
        response,
        (
            "about.hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www"
            "%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F"
            "(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20domain%20%3D"
            "%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%"
            "2F%3F%5Cn%5D%2B)%2F%20or%20about.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E"
            "@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20about.asset.hostname%20"
            "%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%"
            "5C%2F%3F%5Cn%5D%2B)%2F%20or%20about.network.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C"
            "%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20about"
            ".network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3"
            "F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.administrative_domain%20%3D%20%2F%5"
            "E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5C"
            "n%5D%2B)%2F%20or%20intermediary.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@"
            "%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.network.dns"
            ".questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:ww"
            "w%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.network.dns_domain%20%3D%20%2F%5E(%3F:h"
            "ttps%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B"
            ")%2F%20or%20intermediary.asset.hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%"
            "2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.asset.network_d"
            "omain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F("
            "%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.administrative_domain%20%3D%20%2F%5E(%3F:https%3F:%5C"
            "%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%2"
            "0observer.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F("
            "%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.network.dns.questions.name%20%3D%20%2"
            "F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F"
            "%5Cn%5D%2B)%2F%20or%20observer.network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%"
            "5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.asset.hos"
            "tname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F("
            "%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.asset.network_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%"
            "2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20"
            "principal.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F("
            "%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20principal.network.dns.questions.name%20%3D%20%"
            "2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3"
            "F%5Cn%5D%2B)%2F%20or%20principal.network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F"
            ":%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.administrati"
            "ve_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)"
            "%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%"
            "3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.networ"
            "k.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%"
            "3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.network.dns_domain%20%3D%20%2F%5E(%3F:https"
            "%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F"
            "%20or%20src.asset.network_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%"
            "5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20target.domain.name%20%3D%20%2F%5E(%"
            "3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5"
            "D%2B)%2F%20or%20target.network.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%"
            "5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20target.network.dns"
            "_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3"
            "F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F"
        ),
    )

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}fetch_logs.service_account.Credentials.from_service_account_info"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs._auth.authorized_http")
  @mock.patch("google_auth_httplib2.AuthorizedHttp.request")
  def test_fetch_events_success(
      self,
      mock_request,
      mock_authorized_http,
      mock_credentials,
      mocked_get_env_var,
  ):
    """Test successful execution of fetch_events function."""
    mocked_get_env_var.return_value = '{"your": "service_account_json"}'
    mock_request.return_value = ()
    mock_authorized_http.return_value = google_auth_httplib2.AuthorizedHttp
    mock_credentials.return_value = None

    parse_query = "test"
    start_time = datetime.datetime(2023, 1, 1, 0, 0, 0)
    end_time = datetime.datetime(2023, 1, 2, 0, 0, 0)

    result = fetch_object.fetch_events(parse_query, start_time, end_time)
    self.assertEqual(
        mocked_get_env_var.mock_calls[0],
        mock.call("CHRONICLE_SERVICE_ACCOUNT", is_secret=True)
    )
    self.assertEqual(result, ())

  def test_fetch_events_failure_json(self, mocked_get_env_var):
    """Test fetch_events function due to invalid service account json."""
    mocked_get_env_var.return_value = '{"your: "service_account_json"}'
    parse_query = "test"
    start_time = datetime.datetime(2023, 1, 1, 0, 0, 0)
    end_time = datetime.datetime(2023, 1, 2, 0, 0, 0)
    with self.assertRaises(RuntimeError):
      fetch_object.fetch_events(parse_query, start_time, end_time)

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}fetch_logs.service_account.Credentials.from_service_account_info"
  )
  def test_fetch_events_failure_credentials(
      self, mock_credentials, mocked_get_env_var
  ):
    """Test fetch_events function due to failure in credentials."""
    mocked_get_env_var.return_value = '{"your": "service_account_json"}'
    mock_credentials.side_effect = ValueError
    parse_query = "test"
    start_time = datetime.datetime(2023, 1, 1, 0, 0, 0)
    end_time = datetime.datetime(2023, 1, 2, 0, 0, 0)
    with self.assertRaises(ValueError):
      fetch_object.fetch_events(parse_query, start_time, end_time)

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}fetch_logs.service_account.Credentials.from_service_account_info"
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs._auth.authorized_http")
  @mock.patch("google_auth_httplib2.AuthorizedHttp.request")
  def test_fetch_events_failure_http_request(
      self,
      mock_request,
      mock_authorized_http,
      mock_credentials,
      mocked_get_env_var,
  ):
    """Test fetch_events function for failure in http request to Chronicle."""
    mocked_get_env_var.return_value = '{"your": "service_account_json"}'
    mock_request.side_effect = Exception
    mock_authorized_http.return_value = google_auth_httplib2.AuthorizedHttp
    mock_credentials.return_value = None

    parse_query = "test"
    start_time = datetime.datetime(2023, 1, 1, 0, 0, 0)
    end_time = datetime.datetime(2023, 1, 2, 0, 0, 0)

    with self.assertRaises(Exception):
      fetch_object.fetch_events(parse_query, start_time, end_time)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.FetchEvents.fetch_data")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Blob")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.json.load")
  def test_fetch_data_and_checkpoint_success(
      self,
      mock_json,
      mock_blob,
      unused_mock_bucket,
      mock_fetch_data,
      mocked_get_env_var,
  ):
    """Test successful execution of fetch_data_and_checkpoint function."""
    mocked_get_env_var.side_effect = [
        "10",
        "true",
        "test_bucket",
        "checkpoint.json",
    ]
    mock_blob_instance = mock.Mock()
    mock_blob_instance.exists.return_value = True
    mock_blob.return_value = mock_blob_instance
    mock_json.return_value = {"time": "2023-09-05 13:37:00"}
    mock_fetch_data.return_value = [], mock_blob_instance, {}
    # mock_blob.return_value = storage.Bucket().blob()
    response = fetch_object.fetch_data_and_checkpoint()
    self.assertTupleEqual(response, ([], mock_blob_instance, {}))

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.FetchEvents.fetch_data")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Blob")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.json.load")
  def test_fetch_data_and_checkpoint_without_checkpoint_time(
      self,
      mock_json,
      mock_blob,
      unused_mock_bucket,
      mock_fetch_data,
      mocked_get_env_var,
  ):
    """Test successful execution of fetch_data_and_checkpoint function without time specified in checkpoint file."""
    mocked_get_env_var.side_effect = ["10", "true", "test_bucket", ""]
    mock_blob_instance = mock.Mock()
    mock_blob_instance.exists.return_value = True
    mock_blob.return_value = mock_blob_instance
    mock_json.return_value = {"time": ""}
    mock_fetch_data.return_value = [], mock_blob_instance, {}
    # mock_blob.return_value = storage.Bucket().blob()
    response = fetch_object.fetch_data_and_checkpoint()
    self.assertEqual(
        mocked_get_env_var.mock_calls[1],
        mock.call("FETCH_URL_EVENTS", required=False, default="")
    )
    self.assertEqual(
        mocked_get_env_var.mock_calls[3],
        mock.call("CHECKPOINT_FILE_PATH", required=False,
                  default="checkpoint.json")
    )
    self.assertTupleEqual(response, ([], mock_blob_instance, {}))

  def test_fetch_data_and_checkpoint_invalid_endtime(self, mocked_get_env_var):
    """Test fetch_data_and_checkpoint function for invalid end_time_duration argument."""
    mocked_get_env_var.side_effect = ["test"]
    with self.assertRaises(ValueError):
      fetch_object.fetch_data_and_checkpoint()

  def test_fetch_data_and_checkpoint_invalid_bucket(
      self, mocked_get_env_var
  ):
    """Test fetch_data_and_checkpoint function for exception in blob object."""
    mocked_get_env_var.side_effect = [
        "10",
        "true",
        "",
    ]
    with self.assertRaises(ValueError):
      fetch_object.fetch_data_and_checkpoint()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Blob")
  def test_fetch_data_and_checkpoint_invalid_blob(
      self, mock_blob, unused_mock_bucket, mocked_get_env_var
  ):
    """Test fetch_data_and_checkpoint function for exception in blob object."""
    mocked_get_env_var.side_effect = [
        "10",
        "true",
        "test_bucket",
        "checkpoint.json",
    ]
    mock_blob_instance = mock.Mock()
    mock_blob_instance.open.side_effect = Exception
    mock_blob.return_value = mock_blob_instance
    # mock_blob.return_value = storage.Bucket().blob()
    with self.assertRaises(Exception):
      fetch_object.fetch_data_and_checkpoint()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Blob")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.json.load")
  def test_fetch_data_and_checkpoint_invalid_json(
      self, mock_json, mock_blob, unused_mock_bucket, mocked_get_env_var
  ):
    """Test fetch_data_and_checkpoint function for invalid checkpoint json."""
    mocked_get_env_var.side_effect = [
        "10",
        "true",
        "test_bucket",
        "checkpoint.json",
    ]
    mock_blob_instance = mock.Mock()
    mock_blob_instance.exists.return_value = True
    mock_blob.return_value = mock_blob_instance
    mock_json.side_effect = ValueError
    # mock_blob.return_value = storage.Bucket().blob()
    with self.assertRaises(ValueError):
      fetch_object.fetch_data_and_checkpoint()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Blob")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.json.load")
  def test_fetch_data_and_checkpoint_invalid_timestamp(
      self, mock_json, mock_blob, unused_mock_bucket, mocked_get_env_var
  ):
    """Test fetch_data_and_checkpoint function for invalid timestamp in checkpoint file."""
    mocked_get_env_var.side_effect = [
        "10",
        "true",
        "test_bucket",
        "checkpoint.json",
    ]
    mock_blob_instance = mock.Mock()
    mock_blob_instance.exists.return_value = True
    mock_blob.return_value = mock_blob_instance
    mock_json.return_value = {"time": "2023-09-05"}
    # mock_blob.return_value = storage.Bucket().blob()
    with self.assertRaises(ValueError):
      fetch_object.fetch_data_and_checkpoint()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.FetchEvents.fetch_data")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Blob")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.json.load")
  def test_fetch_data_and_checkpoint_runtime_fetch_data(
      self,
      mock_json,
      mock_blob,
      unused_mock_bucket,
      mock_fetch_data,
      mocked_get_env_var,
  ):
    """Test fetch_data_and_checkpoint function which raises RuntimeError for fetch_data."""
    mocked_get_env_var.side_effect = [
        "10",
        "true",
        "test_bucket",
        "checkpoint.json",
    ]
    mock_blob_instance = mock.Mock()
    mock_blob_instance.exists.return_value = True
    mock_blob.return_value = mock_blob_instance
    mock_json.return_value = {"time": "2023-09-05 13:37:00"}
    mock_fetch_data.side_effect = RuntimeError
    with self.assertRaises(RuntimeError):
      fetch_object.fetch_data_and_checkpoint()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.FetchEvents.fetch_data")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Blob")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.json.load")
  def test_fetch_data_and_checkpoint_exception_fetch_data(
      self,
      mock_json,
      mock_blob,
      unused_mock_bucket,
      mock_fetch_data,
      mocked_get_env_var,
  ):
    """Test fetch_data_and_checkpoint function which raises Exception for fetch_data."""
    mocked_get_env_var.side_effect = [
        "10",
        "true",
        "test_bucket",
        "checkpoint.json",
    ]
    mock_blob_instance = mock.Mock()
    mock_blob_instance.exists.return_value = True
    mock_blob.return_value = mock_blob_instance
    mock_json.return_value = {"time": "2023-09-05 13:37:00"}
    mock_fetch_data.side_effect = Exception
    with self.assertRaises(Exception):
      fetch_object.fetch_data_and_checkpoint()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.FetchEvents.fetch_events")
  def test_fetch_data_success(
      self, mock_fetch_events, unused_mocked_get_env_var
  ):
    """Test successful execution of fetch_data function."""
    mock_fetch_events.return_value = (
        httplib2.Response({"status": 200}),
        json.dumps(SAMPLE_RESPONSE).encode("utf-8"),
    )
    start_time = datetime.datetime(2023, 1, 1, 0, 0, 0)
    end_time = datetime.datetime(2023, 1, 1, 0, 2, 0)

    response = fetch_object.fetch_data(
        "test", start_time, end_time, 120, None, True
    )
    self.assertEqual(
        response, (["test.com"], None, {"time": "2023-01-01 00:01:00"})
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.FetchEvents.fetch_events")
  def test_fetch_data_status_404(
      self, mock_fetch_events, unused_mocked_get_env_var
  ):
    """Test execution of fetch_data function for status code 404."""
    mock_fetch_events.return_value = (httplib2.Response({"status": 404}), "")
    start_time = datetime.datetime(2023, 1, 1, 0, 0, 0)
    end_time = datetime.datetime(2023, 1, 1, 0, 2, 0)
    with self.assertRaises(RuntimeError):
      fetch_object.fetch_data("test", start_time, end_time, 120, None, True)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.utils.cloud_logging")
  def test_convert_str_to_bool_empty_string(self, mocked_cloud_logging,
                                            unused_mocked_get_env_var):
    """Test convert_str_to_bool providing empty string in argument."""
    response = fetch_object.convert_str_to_bool("")
    self.assertEqual(response, False)
    mocked_cloud_logging.assert_not_called()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.utils.cloud_logging")
  def test_convert_str_to_bool_invalid_argument(
      self, mocked_cloud_logging, unused_mocked_get_env_var
  ):
    """Test convert_str_to_bool providing invalid argument."""
    response = fetch_object.convert_str_to_bool("test")
    self.assertEqual(response, False)
    mocked_cloud_logging.assert_called()

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.utils.cloud_logging")
  def test_convert_str_to_bool_false_argument(
      self, mocked_cloud_logging, unused_mocked_get_env_var
  ):
    """Test convert_str_to_bool providing false argument."""
    response = fetch_object.convert_str_to_bool("false")
    self.assertEqual(response, False)
    mocked_cloud_logging.assert_not_called()

  def test_convert_str_to_bool_true_argument(
      self, unused_mocked_get_env_var
  ):
    """Test convert_str_to_bool providing true argument."""
    response = fetch_object.convert_str_to_bool("true")
    self.assertEqual(response, True)

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.FetchEvents.fetch_data")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}fetch_logs.storage.Client")
  def test_checkpoint_blob_does_not_exist(
      self, mock_storage_client, mock_fetch_data, unused_mocked_get_env_var
  ):
    """Test fetch_data_and_checkpoint function when checkpoint blob does not exist."""
    mock_bucket = mock.MagicMock()
    mock_storage_client().get_bucket.return_value = mock_bucket
    mock_blob = mock.MagicMock()
    mock_blob.exists.return_value = False
    mock_bucket.blob.return_value = mock_blob
    mock_fetch_data.return_value = [], mock_bucket, {}

    response = fetch_object.fetch_data_and_checkpoint()
    self.assertTupleEqual(response, ([], mock_bucket, {}))
