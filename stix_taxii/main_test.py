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
"""Unit test case file for main module of STIX/TAXII ingestion script."""

import datetime
import sys

# copybara:insert(imports) import unittest
from unittest import mock

# copybara:strip_begin(imports)
from google3.testing.pybase import googletest
# copybara:strip_end

INGESTION_SCRIPTS_PATH = "google3.third_party.chronicle.ingestion_scripts"
sys.modules[f"{INGESTION_SCRIPTS_PATH}.common.ingest"] = mock.Mock()

# copybara:strip_begin(imports)
from stix_taxii import main  # pylint: disable=g-import-not-at-top
from stix_taxii import taxii_client
# copybara:strip_end

# Test value for poll interval.
TEST_POLL_INTERVAL = 15


def get_mock_response() -> mock.Mock:
  """Return a mock response.

  Returns:
    mock.Mock: Mock response.
  """
  response = mock.Mock()
  response.raise_for_status = mock.Mock()
  response.status_code = 200
  return response


# copybara:insert(imports) class TestTaxiiClientVersion11(unittest.TestCase):
class TestStixTaxiiIngestion(googletest.TestCase):
  """Test cases for the main function."""

  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}.stix_taxii.main.taxii_client."
      "convert_date_to_stix_format")
  @mock.patch(
      f"{INGESTION_SCRIPTS_PATH}.stix_taxii.main.taxii_client.TAXIIClient")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.stix_taxii.main.utils.get_env_var")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.common.auth.requests.Session.send")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}.stix_taxii.main.ingest.ingest")
  def test_main_success(self, mocked_ingest, mocked_send, *unused_args):
    """Test case to verify that the ingest function should be called once when the TAXII Server returns valid response.
    """
    mock_response_1 = get_mock_response()
    mock_response_1.json.return_value = {"access_token": "test_access_token"}

    mock_response_2 = get_mock_response()
    mock_response_2.json.return_value = {"entries": [], "chunk_size": 0}

    mocked_send.side_effect = [mock_response_1, mock_response_2]

    main.main(req="")

    self.assertEqual(mocked_ingest.call_count, 1)

  def test_convert_date_to_stix_format(self):
    """Test case to verify that the convert_date_to_stix format returns the valid date string when provided a valid datetime object.
    """
    dt_object = datetime.datetime(2022, 1, 1, 5, 45, 58, 564783)
    dt_object = dt_object.replace(tzinfo=datetime.timezone.utc)

    self.assertEqual(
        taxii_client.convert_date_to_stix_format(dt_object),
        "2022-01-01T05:45:58.564783Z")
