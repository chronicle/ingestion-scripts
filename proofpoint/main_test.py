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
"""Unit test case file for main module of Proofpoint ingestion script."""
import sys
import unittest
from unittest import mock

# Constants.
ENV_VARS = [
    "proofpoint_server_url", "proofpoint_service_principle",
    "proofpoint_secret", "30", "chronicle_data_type"
]
INGESTION_COMPLETE_MSG = "Ingestion completed."

INGESTION_SCRIPTS_PATH = ""
SCRIPT_PATH = ""

sys.modules[f"{INGESTION_SCRIPTS_PATH}common.ingest"] = mock.MagicMock()
sys.modules[f"{INGESTION_SCRIPTS_PATH}common.utils"] = mock.MagicMock()

import main


def get_mock_response(json_response="", status_code=200):
  """Return a mock response."""
  response = mock.Mock()
  response.raise_for_status = mock.Mock()
  response.status_code = status_code
  response.json.return_value = json_response
  return response


def get_mock_response_error(exception, status_code=200):
  """Return a mock response."""
  response = mock.Mock()
  response.raise_for_status = mock.Mock()
  response.status_code = status_code
  response.json.side_effect = exception
  return response


class TestProofpointPeople(unittest.TestCase):
  """Test cases for proofpoint script."""

  def test_validate_params_for_invalid_value_error(self):
    """Test case to verify that the validate_params raises InvalidValueError when invalid data provided."""
    with self.assertRaises(main.InvalidValueError) as error:
      main.validate_params("20")
    self.assertEqual(
        str(error.exception),
        "Invalid value provided for retrieval range. Supported values are: 14, "
        "30, 90")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_error_code_400(self, mock_auth_user, mock_utils):
    """Test case to verify exception is raised with appropriate message for http error code 400."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        status_code=400)

    mock_request = mock.MagicMock()
    with self.assertRaises(RuntimeError) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "Status code 400. Bad Request. Possible reason could be, the Proofpoint"
        " retrieval range provided is having a value other than 14, 30 or 90.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_error_code_401(self, mock_auth_user, mock_utils):
    """Test case to verify exception is raised with appropriate message for http error code 401."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        status_code=401)

    mock_request = mock.MagicMock()
    with self.assertRaises(RuntimeError) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "Status code 401. Authentication failed. Possible reason could be, "
        "Proofpoint service principle or Proofpoint secret is invalid.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_error_code_429(self, mock_auth_user, mock_utils):
    """Test case to verify exception is raised with appropriate message for http error code 429."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        status_code=429)

    mock_request = mock.MagicMock()
    with self.assertRaises(RuntimeError) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "Status code 429. API rate limit exceeded. The API rate limit for the "
        "Proofpoint People API is 50 per day.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_error_code_500(self, mock_auth_user, mock_utils):
    """Test case to verify exception is raised with appropriate message for http error code 500."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        status_code=500)

    mock_request = mock.MagicMock()
    with self.assertRaises(RuntimeError) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "Status code 500. Internal server error occurred.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_error_code_501(self, mock_auth_user, mock_utils):
    """Test case to verify exception is raised with appropriate message for http error code 501."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        status_code=501)

    mock_request = mock.MagicMock()
    with self.assertRaises(RuntimeError) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception), "Error occurred while making the API request.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_api_call_exception(self, mock_auth_user, mock_utils):
    """Test case to verify exception is raised for failure in API call."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.side_effect = Exception()

    mock_request = mock.MagicMock()
    with self.assertRaises(Exception) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception), "Error occurred while making the API request.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_api_call_http_error(self, mock_auth_user, mock_utils):
    """Test case to verify exception is raised for http error in API call."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.side_effect = main.exceptions.HTTPError(
        response=get_mock_response(status_code=429))

    mock_request = mock.MagicMock()
    with self.assertRaises(Exception) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        "Status code 429. API rate limit exceeded. The API rate "
        "limit for the Proofpoint People API is 50 per day.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_response_json_serializable_value_error(self, mock_auth_user,
                                                  mock_utils):
    """Test case to verify ValueError is raised when response is not json serializable."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response_error(
        exception=ValueError())

    mock_request = mock.MagicMock()
    with self.assertRaises(Exception) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        (
            "Unexpected data format received while collecting users from"
            " Proofpoint."
        ),
    )

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  def test_response_json_serializable_type_error(
      self, mock_auth_user, mock_utils
  ):
    """Test case to verify TypeError is raised when response is not json serializable."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response_error(
        exception=TypeError())

    mock_request = mock.MagicMock()
    with self.assertRaises(Exception) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception),
        (
            "Unexpected data format received while collecting users from"
            " Proofpoint."
        ),
    )

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  def test_ingestion_failure(self, mock_ingest, mock_auth_user, mock_utils):
    """Test case to verify exception is raised from ingest."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        json_response={
            "users": [{
                "name": "name_1",
                "title": "student"
            }],
            "totalVapUsers": 1
        })
    mock_ingest.side_effect = Exception()

    mock_request = mock.MagicMock()
    with self.assertRaises(Exception) as error:
      main.main(mock_request)

    self.assertEqual(
        str(error.exception), "Unable to push the data to the Chronicle.")

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  def test_successful_ingestion(self, mock_ingest, mock_auth_user, mock_utils):
    """Test case for successful ingestion in chronicle."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        json_response={
            "users": [{
                "name": "name_1",
                "title": "student"
            }],
            "totalVapUsers": 1
        })
    mock_request = mock.MagicMock()
    assert main.main(mock_request) == INGESTION_COMPLETE_MSG
    self.assertEqual(mock_ingest.call_count, 1)

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  def test_pagination(self, mock_ingest, mock_auth_user, mock_utils):
    """Test case to verify pagination."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        json_response={
            "users": [{
                "name": "name_1",
                "title": "student"
            }],
            "totalVapUsers": 2
        })
    mock_request = mock.MagicMock()
    assert main.main(mock_request) == INGESTION_COMPLETE_MSG
    self.assertEqual(mock_ingest.call_count, 2)
    self.assertEqual(mock_auth_user.return_value.get.mock_calls[2],
                     mock.call(
                         "proofpoint_server_url/v2/people/vap?window=30&page=2")
                     )

  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  def test_ingestion_when_no_data_received(self, mock_ingest, mock_auth_user,
                                           mock_utils):
    """Test case to verify ingest is not called when no logs are received."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        json_response={})
    mock_request = mock.MagicMock()
    assert main.main(mock_request) == INGESTION_COMPLETE_MSG
    self.assertEqual(mock_ingest.call_count, 0)

  @mock.patch(f"{SCRIPT_PATH}main.utils.get_env_var")
  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  def test_is_secret_mutant(self, unused_mock_ingest, mock_auth_user,
                            mock_utils, mock_get_env_var):
    """Test case to verify is_secret in get_env_vars."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        json_response={
            "users": [{
                "name": "name_1",
                "title": "student"
            }],
            "totalVapUsers": 1
        })
    mock_request = mock.MagicMock()

    main.main(mock_request)
    self.assertEqual(mock_get_env_var.mock_calls[2],
                     mock.call("PROOFPOINT_SECRET", is_secret=True))

  @mock.patch(f"{SCRIPT_PATH}main.utils.get_env_var")
  @mock.patch(f"{SCRIPT_PATH}main.utils")
  @mock.patch(f"{SCRIPT_PATH}main.auth.UsernamePasswordAuth")
  @mock.patch(f"{SCRIPT_PATH}main.ingest.ingest")
  @mock.patch(f"{SCRIPT_PATH}main.validate_params")
  def test_is_required_mutant(self, mock_validate_params, unused_mock_ingest,
                              mock_auth_user,
                              mock_utils, mock_get_env_var):
    """Test case to verify is_secret in get_env_vars."""
    mock_utils.get_env_var.side_effect = ENV_VARS
    mock_auth_user.return_value = mock.MagicMock()
    mock_auth_user.return_value.get.return_value = get_mock_response(
        json_response={
            "users": [{
                "name": "name_1",
                "title": "student"
            }],
            "totalVapUsers": 1
        })
    mock_request = mock.MagicMock()

    main.main(mock_request)
    self.assertEqual(
        mock_get_env_var.mock_calls[3],
        mock.call("PROOFPOINT_RETRIEVAL_RANGE", required=False, default="30"))
    self.assertEqual(mock_validate_params.call_count, 1)
