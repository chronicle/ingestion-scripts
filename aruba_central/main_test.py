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
"""Unit test cases for Aruba Central script."""

import sys

import unittest
from unittest import mock

import requests

INGESTION_SCRIPTS_PATH = ""
SCRIPT_PATH = ""

sys.modules[f"{INGESTION_SCRIPTS_PATH}common.ingest"] = mock.MagicMock()

import main


@mock.patch(f"{SCRIPT_PATH}main.utils.get_env_var")
@mock.patch(f"{SCRIPT_PATH}main.utils.get_last_run_at")
@mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
@mock.patch.object(
    main.pycentral.audit_logs.Audit, "__init__", return_value=None)
@mock.patch.object(
    main.pycentral.base.ArubaCentralBase, "__init__", return_value=None)
class TestArubaCentralIngestion(unittest.TestCase):
  """Test cases for Aruba Central script."""

  def test_no_logs_to_ingest(
      self,
      unused_mocked_client,
      unused_mocked_audit_object,
      mocked_ingest,
      unused_mocked_get_last_run_at,
      unused_mocked_get_env_var,
  ):
    """Test case to verify that we do not call ingest function when there are no logs to ingest."""
    mock_response = {
        "code": 200,
        "msg": {
            "audit_logs": [],
            "remaining_records": False,
            "total": 0
        },
    }

    with mock.patch(
        f"{SCRIPT_PATH}main.pycentral.audit_logs.Audit.get_traillogs",
        return_value=mock_response):
      main.main(request="")
    self.assertEqual(mocked_ingest.call_count, 0)

  @mock.patch(
      f"{SCRIPT_PATH}main.pycentral.audit_logs.Audit.get_traillogs"
  )
  def test_pagination(
      self,
      mock_get_logs,
      unused_mocked_client,
      unused_mocked_audit_object,
      mocked_ingest,
      unused_mocked_get_last_run_at,
      unused_mocked_get_env_var,
  ):
    """Test case to verify the pagination mechanism."""

    mock_response_1 = {
        "code": 200,
        "msg": {
            "audit_logs": [{
                "id": 1
            }],
            "remaining_records": True,
            "total": 1
        },
    }
    mock_response_2 = {
        "code": 200,
        "msg": {
            "audit_logs": [{
                "id": 2
            }],
            "remaining_records": False,
            "total": 1
        },
    }

    mock_get_logs.side_effect = [mock_response_1, mock_response_2]

    main.main(request="")

    self.assertEqual(mocked_ingest.call_count, 2)

  @mock.patch(
      f"{SCRIPT_PATH}main.pycentral.audit_logs.Audit.get_traillogs"
  )
  def test_http_error(
      self,
      mock_get_logs,
      unused_mocked_client,
      unused_mocked_audit_object,
      unused_mocked_ingest,
      unused_mocked_get_last_run_at,
      mocked_get_env_var,
  ):
    """Test case to verify http error from Aruba Central API."""
    mocked_get_env_var.side_effect = [
        "test", "test", "test", "test", "test", "test", 10
    ]
    mock_get_logs.return_value = {
        "code": 429,
        "msg": "Rate limit exceeded.",
    }

    with self.assertRaises(requests.HTTPError) as error:
      main.main(request="")

    self.assertEqual(
        str(error.exception),
        "Exception occurred while making API call. Rate limit exceeded.")

  @mock.patch(
      f"{SCRIPT_PATH}main.pycentral.audit_logs.Audit.get_traillogs"
  )
  def test_chronicle_ingestion_error(
      self,
      mock_get_logs,
      unused_mocked_client,
      unused_mocked_audit_object,
      mocked_ingest,
      unused_mocked_get_last_run_at,
      unused_mocked_get_env_var,
  ):
    """Test case scenario when error obtained from chronicle ingestion."""
    mock_get_logs.return_value = {
        "code": 200,
        "msg": {
            "audit_logs": [{
                "id": 1
            }],
            "remaining_records": True,
            "total": 1
        },
    }

    mocked_ingest.side_effect = Exception("Error in API call.")

    with self.assertRaises(Exception) as error:
      main.main(request="")

    self.assertEqual(
        str(error.exception),
        (
            "Unable to push the data to the Chronicle. Please check the"
            " Chronicle configuration parameters."
        ),
    )

  def test_system_error_while_creating_client(
      self,
      mocked_client,
      unused_mocked_audit_object,
      unused_mocked_ingest,
      unused_mocked_get_last_run_at,
      mocked_get_env_var,
  ):
    """Test case scenario when system error occurred."""
    mocked_get_env_var.side_effect = [
        "test", "test", "test", "test", "test", "test", 10
    ]
    mocked_client.side_effect = SystemExit("exiting...")

    with self.assertRaises(requests.HTTPError) as error:
      main.main(request="")

    self.assertEqual(
        str(error.exception),
        "Exception occurred while making API call.\nexiting...",
    )

  @mock.patch(
      f"{SCRIPT_PATH}main.pycentral.audit_logs.Audit.get_traillogs"
  )
  def test_get_env_variable_for_secret(
      self,
      mock_get_logs,
      unused_mocked_client,
      unused_mocked_audit_object,
      unused_mocked_ingest,
      unused_mocked_get_last_run_at,
      mocked_get_env_var,
  ):
    """Test case to verify is_secret in get_env_vars."""
    mock_get_logs.return_value = {
        "code": 200,
        "msg": {
            "audit_logs": [{
                "id": 1
            }],
            "remaining_records": False,
            "total": 1
        },
    }

    main.main("")

    self.assertEqual(
        mocked_get_env_var.mock_calls[1],
        mock.call("ARUBA_CLIENT_SECRET_SECRET_PATH", is_secret=True))

    self.assertEqual(
        mocked_get_env_var.mock_calls[4],
        mock.call("ARUBA_PASSWORD_SECRET_PATH", is_secret=True))
