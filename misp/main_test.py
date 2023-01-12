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
"""Unit tests for the 'main' module."""

import sys

import unittest
from unittest import mock

import requests

INGESTION_SCRIPTS_PATH = ""
SCRIPT_PATH = ""

sys.modules["{}common.ingest".format(INGESTION_SCRIPTS_PATH)] = mock.Mock()

import main


def get_mock_response():
  """Return a mock response."""
  response = mock.Mock()
  response.raise_for_status = mock.Mock()
  response.status_code = 200
  return response


# Mock data
_test_key_to_remove_entity = {
    "response": [{
        "Event": {
            "id": "1",
            "info": "logged source ip",
            "uuid": "c99506a6-1255-4b71-afa5-7b8ba48c3b1b",
            "date": "2022-01-01",
            "Event": {
                "id": "12345"
            },
            "EventReport": [{}],
            "Tag": [{
                "id": "12345",
                "name": "tlp:white",
                "colour": "#ffffff"
            }],
            "Object": [{
                "id": "12345",
                "name": "ail-leak",
                "meta-category": "string",
                "description": "string"
            }],
            "Galaxy": [{
                "id": "12345",
                "name": "Ransomware",
                "type": "ransomware",
                "description": "Ransomware galaxy based on ..."
            }],
            "RelatedEvent": [{}],
            "ShadowAttribute": [{
                "id": "12345",
                "event_id": "12345",
                "object_id": "12345",
                "object_relation": "sensor",
                "category": "Internal reference",
                "type": "md5"
            }],
            "Org": {
                "id": "12345",
                "name": "ORGNAME"
            },
            "Orgc": {
                "id": "12345",
                "name": "ORGNAME"
            },
            "Feed": {
                "id": "101",
                "name": "CIRCL OSINT Feed",
                "provider": "CIRCL"
            }
        }
    }]
}


@mock.patch("{}main.utils.get_env_var".format(SCRIPT_PATH), return_value="test")
@mock.patch("{}main.ingest.ingest".format(SCRIPT_PATH))
@mock.patch("{}main.requests.post".format(SCRIPT_PATH))
class TestMISPIngestion(unittest.TestCase):
  """Test cases to verify MISP ingestion script."""

  @mock.patch("builtins.print")
  def test_http_error(self, mocked_print, mocked_post, unused_mocked_ingest,
                      unused_mocked_get_env_var):
    """Test case to ensure that we raise errors when status code other than 2XX is encountered.
    """
    response = get_mock_response()
    response.raise_for_status.side_effect = requests.HTTPError()
    response.status_code = 400
    response.json.return_value = {
        "message": "Bad request",
        "url": "/events/restSearch"
    }
    mocked_post.return_value = response

    with self.assertRaises(requests.HTTPError):
      main.main(req="")

    expected_calls = [
        mock.call(
            "HTTP Error: 400, Reason: {'message': 'Bad request', 'url': '/events/restSearch'}"
        ),
        mock.call(
            "ERROR: Unexpected error occured while fetching events from the MISP API."
        )
    ]
    self.assertEqual(mocked_print.mock_calls[-2:], expected_calls)

  def test_no_logs_to_ingest(self, mocked_post, mocked_ingest,
                             unused_mocked_get_env_var):
    """Test case to verify we call ingest with empty list of data, when we have no logs to consume.
    """
    response = get_mock_response()
    response.json.return_value = {"response": []}
    mocked_post.return_value = response

    main.main(req="")

    self.assertEqual(mocked_ingest.call_count, 1)
    mocked_ingest.assert_called_with([], "MISP_IOC")

  def test_ingest_logs(self, mocked_post, mocked_ingest,
                       unused_mocked_get_env_var):
    """Test case to verify we call ingest with expcted args when we have logs to consume.
    """
    response = get_mock_response()
    response.json.return_value = {
        "response": [{
            "Event": {
                "id": "1"
            }
        }, {
            "Event": {
                "id": "2"
            }
        }]
    }
    mocked_post.return_value = response

    main.main(req="")

    self.assertEqual(mocked_ingest.call_count, 1)
    mocked_ingest.assert_called_with([{"id": "1"}, {"id": "2"}], "MISP_IOC")

  def test_log_retrieve_time(self, mocked_post, unused_mocked_ingest,
                             unused_mocked_get_env_var):
    """Test case to verify the log retrieve time is as expected."""
    response = get_mock_response()
    response.json.return_value = {"response": []}
    mocked_post.return_value = response

    main.get_and_ingest_events(
        api_key="test",
        target_server="test_server",
        start_time="15",
        org_name="testOrg")

    _, kwargs = mocked_post.call_args
    expected_log_retrieve_time = "15m"  # Get logs of last 15 minutes
    self.assertEqual(
        kwargs.get("json").get("timestamp"), expected_log_retrieve_time)

  def test_key_to_remove(self, mocked_post, mocked_ingest,
                         unused_mocked_get_env_var):
    """Test case to verify we remove the keys in "key_to_remove" form the logs data.
    """
    response = get_mock_response()
    response.json.return_value = _test_key_to_remove_entity
    mocked_post.return_value = response

    main.get_and_ingest_events(
        api_key="test",
        target_server="test_server",
        start_time="100",
        org_name="testOrg")

    mocked_ingest.assert_called_with([{
        "id": "1",
        "info": "logged source ip",
        "uuid": "c99506a6-1255-4b71-afa5-7b8ba48c3b1b",
        "date": "2022-01-01"
    }], "MISP_IOC")
