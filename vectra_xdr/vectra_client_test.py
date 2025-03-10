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
#
# pylint: disable=line-too-long
# pylint: disable=g-importing-member
# pylint: disable=invalid-name
# pylint: disable=g-multiple-import
# pylint: disable=unused-argument
# pylint: disable=g-import-not-at-top

import datetime
import json
import sys
import unittest
from unittest import mock

import requests

INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest"] = mock.Mock()

from common import status
import constant
import exception
from vectra_client import VectraClient

patch = mock.patch
MagicMock = mock.MagicMock


class TestVectraClientCheckpoint(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_secret_manager_client = MagicMock()
    self.client = VectraClient(
        "dummy_id",
        "dummy_secret",
        "https://dummy.com",
        "dummy_bucket",
        self.mock_secret_manager_client,
    )
    self.client.session = MagicMock()  # Mock the session object

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._generate_initial_access_and_refresh_token"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_initial_access_and_refresh_token_call(
      self, mock_logging, mock_method
  ):
    new_client = VectraClient(
        "dummy_id",
        "dummy_secret",
        "https://dummy.com",
        "dummy_bucket",
        self.mock_secret_manager_client,
    )
    self.assertEqual(mock_method.call_count, 1)
    self.assertEqual(
        new_client.session.headers.get("User-Agent"), "vectra-rux-csiem-1.0.0"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_initial_access_and_refresh_token_exists(
      self, mock_logging
  ):
    self.mock_secret_manager_client.get_secrets.return_value = {
        "access_token": "test_token",
        "refresh_token": "test_refresh",
    }
    self.client._generate_initial_access_and_refresh_token()
    self.assertEqual(self.client.access_token, "test_token")
    self.assertEqual(self.client.refresh_token, "test_refresh")
    self.client.session.headers.update.assert_called_with(
        {"Authorization": "Bearer test_token"}
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_initial_access_and_refresh_token_not_exists(
      self, mock_logging
  ):
    self.mock_secret_manager_client.get_secrets.side_effect = Exception(
        "Secret not found"
    )
    with patch.object(
        self.client, "_generate_access_and_refresh_token"
    ) as mock_generate:
      self.client._generate_initial_access_and_refresh_token()
      mock_generate.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient.validate_response"
  )
  def test__make_rest_call_for_token_generation_refresh_token_exception(
      self, mock_validate, mock_logging
  ):
    mock_validate.side_effect = exception.RefreshTokenException(
        "Invalid refresh token"
    )
    with self.assertRaises(exception.RefreshTokenException) as re:
      self.client._make_rest_call_for_token_generation()
    self.assertEqual(
        str(re.exception),
        "Failed to generate new access token using refresh token.",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient.validate_response"
  )
  def test__make_rest_call_for_token_generation_unauthorize_exception(
      self, mock_validate, mock_logging
  ):
    mock_validate.side_effect = exception.UnauthorizeException(
        "Invalid credentials"
    )
    with self.assertRaises(exception.UnauthorizeException) as ue:
      self.client._make_rest_call_for_token_generation()
    self.assertEqual(
        str(ue.exception),
        "Provided Credentials are not valid!. Please verify provided"
        " credentials.",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient.validate_response"
  )
  def test__make_rest_call_for_token_generation_vectra_exception(
      self, mock_validate, mock_logging
  ):
    mock_validate.side_effect = exception.VectraException(
        "Vectra API error"
    )
    with self.assertRaises(exception.VectraException) as ve:
      self.client._make_rest_call_for_token_generation()
    self.assertEqual(str(ve.exception), "Vectra API error")

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._generate_access_and_refresh_token"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_rest_call_for_token_generation"
  )
  def test__generate_access_token_refresh_token_expired(
      self, mock_token_call, mock_logging, mock_gen_token
  ):
    mock_token_call.side_effect = exception.RefreshTokenException(
        "Refresh token expired"
    )
    self.client._generate_access_token()
    mock_gen_token.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_rest_call_for_token_generation",
      side_effect=exception.RateLimitException("Rate limit exceeded"),
  )
  def test__generate_access_token_rate_limit(
      self, mock_token_call, mock_logging
  ):
    with self.assertRaises(exception.RateLimitException):
      self.client._generate_access_token()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_rest_call_for_token_generation",
      side_effect=Exception("API Error"),
  )
  def test__generate_access_token_api_error(
      self, mock_token_call, mock_logging
  ):
    with self.assertRaises(exception.VectraException):
      self.client._generate_access_token()

  @patch("google.cloud.storage.Client")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value="test_bucket",
  )
  def test__get_last_checkpoint_exists(self, mock_env_var, MockStorageClient):
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = json.dumps(
        {"test_endpoint": "test_checkpoint"}
    )

    checkpoint = self.client._get_last_checkpoint(
        "test_endpoint"
    )
    self.assertEqual(checkpoint, "test_checkpoint")

  @patch("google.cloud.storage.Client")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value="test_bucket",
  )
  def test__get_last_checkpoint_not_exists(
      self, mock_env_var, MockStorageClient
  ):
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = False

    checkpoint = self.client._get_last_checkpoint(
        "test_endpoint"
    )
    self.assertIsNone(checkpoint)

  @patch("google.cloud.storage.Client")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value="test_bucket",
  )
  def test__set_last_checkpoint(self, mock_env_var, MockStorageClient):
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value

    mock_open = MagicMock()
    mock_blob.open.return_value.__enter__.return_value = (
        mock_open
    )
    mock_blob.exists.return_value = False

    self.client._set_last_checkpoint(
        "new_endpoint", "new_checkpoint"
    )

    mock_blob.open.assert_called_once_with(mode="w", encoding="utf-8")
    mock_open.write.assert_called_once_with(
        json.dumps({"new_endpoint": "new_checkpoint"})
    )

  @patch("google.cloud.storage.Client")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value="test_bucket",
  )
  def test__set_last_checkpoint_existing(self, mock_env_var, MockStorageClient):
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value

    mock_open = MagicMock()
    mock_blob.open.return_value.__enter__.return_value = mock_open
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = (
        '{"existing_endpoint": "existing_checkpoint"}'
    )

    self.client._set_last_checkpoint(
        "new_endpoint", "new_checkpoint"
    )

    expected_data = {
        "existing_endpoint": "existing_checkpoint",
        "new_endpoint": "new_checkpoint",
    }
    mock_open.write.assert_called_once_with(json.dumps(expected_data))

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.ingest.ingest"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging"
  )
  def test__ingest_events_with_events(self, mock_logging, mock_ingest):
    events = [{"key": "value1"}, {"key": "value2"}]
    client = VectraClient(
        "dummy_id",
        "dummy_secret",
        "https://dummy.com",
        "dummy_bucket",
        MagicMock(),
    )
    client._ingest_events(events)
    mock_ingest.assert_called_once_with(
        events, constant.CHRONICLE_DATA_TYPE
    )
    mock_logging.assert_called_with(
        "Ingesting events into Chronicle."
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging"
  )
  def test__ingest_events_no_events(self, mock_logging):

    client = VectraClient(
        "dummy_id",
        "dummy_secret",
        "https://dummy.com",
        "dummy_bucket",
        MagicMock(),
    )
    client._ingest_events([])  # Empty list
    mock_logging.assert_called_with(
        "No events to push data to ingest into Chronicle."
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.ingest.ingest",
      side_effect=Exception("Ingest Error"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__ingest_events_exception(self, mock_logging, mock_ingest):
    events = [{"key": "value"}]
    client = VectraClient(
        "dummy_id",
        "dummy_secret",
        "https://dummy.com",
        "dummy_bucket",
        MagicMock(),
    )

    with self.assertRaises(Exception) as e:
      client._ingest_events(events)

    self.assertIn(
        "Ingest Error", str(e.exception)
    )

    mock_logging.assert_any_call("Ingesting events into Chronicle.")
    mock_logging.assert_called_with(
        "Error occurred while ingesting data: Ingest Error", severity="ERROR"
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value=False,
  )
  def test__handle_checkpoint_with_last_checkpoint(
      self, mock_env_var, mock_logging
  ):
    last_checkpoint = "2024-07-20T12:00:00Z"
    checkpoint_field, checkpoint_value = self.client._handle_checkpoint(
        last_checkpoint
    )
    self.assertEqual(checkpoint_field, "from")
    self.assertEqual(checkpoint_value, last_checkpoint)

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value=False,
  )
  def test__handle_checkpoint_no_last_checkpoint(
      self, mock_env_var, mock_logging
  ):
    checkpoint_field, checkpoint_value = self.client._handle_checkpoint(None)
    self.assertEqual(checkpoint_field, "event_timestamp_gte")
    self.assertTrue(  # pylint: disable=g-generic-assert
        isinstance(checkpoint_value, str)
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value="true",
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.datetime.datetime"
  )
  def test__handle_checkpoint_historical_true(
      self, mock_datetime, mock_env_var, mock_logging
  ):
    mock_now = datetime.datetime(2025, 1, 4, 9, 53, 54, 883808)
    mock_datetime.now.return_value = mock_now

    checkpoint_field, checkpoint_value = self.client._handle_checkpoint(None)
    self.assertEqual(checkpoint_field, "event_timestamp_gte")

    time_24_hours_ago = mock_now - datetime.timedelta(hours=24)
    expected_checkpoint = time_24_hours_ago.isoformat()

    self.assertEqual(checkpoint_value, expected_checkpoint)

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__extract_response_valid(self, mock_logging):
    response = {
        "events": [1, 2, 3],
        constant.REMAINING_COUNT: 10,
        constant.NEXT_CHECKPOINT: "next_checkpoint_value",
    }
    events, remaining_count, next_checkpoint = self.client._extract_response(
        response
    )
    self.assertEqual(events, [1, 2, 3])
    self.assertEqual(remaining_count, 10)
    self.assertEqual(next_checkpoint, "next_checkpoint_value")

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__extract_response_none(self, mock_logging):
    with self.assertRaises(TypeError) as e:
      self.client._extract_response(None)
    self.assertIn("Response is None", str(e.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__extract_response_no_next_checkpoint(self, mock_logging):
    response = {"events": [1, 2, 3], constant.REMAINING_COUNT: 10}
    with self.assertRaises(ValueError) as e:
      self.client._extract_response(response)
    self.assertIn("Next Checkpoint is None", str(e.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__extract_response_no_events(self, mock_logging):
    response = {
        constant.REMAINING_COUNT: 10,
        constant.NEXT_CHECKPOINT: "next_checkpoint_value",
    }
    with self.assertRaises(TypeError) as e:
      self.client._extract_response(response)
    self.assertIn("Events is None", str(e.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__extract_response_no_remaining_count(self, mock_logging):

    response = {
        "events": [1, 2, 3],
        constant.NEXT_CHECKPOINT: "next_checkpoint_value",
    }
    with self.assertRaises(TypeError) as e:
      self.client._extract_response(response)
    self.assertIn("Remaining count is None", str(e.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__extract_response_invalid_events_type(self, mock_logging):
    response = {
        "events": "invalid",
        constant.REMAINING_COUNT: 10,
        constant.NEXT_CHECKPOINT: "next_checkpoint_value",
    }
    with self.assertRaises(TypeError) as e:
      self.client._extract_response(response)
    self.assertIn("Events is not of type list", str(e.exception))

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_detection_events_by_type"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._extract_response"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._set_last_checkpoint"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_detection_events_success(
      self,
      mock_logging,
      mock_set_checkpoint,
      mock_ingest,
      mock_extract_response,
      mock_get_events,
  ):
    mock_get_events.side_effect = [
        {
            "events": [1, 2, 3],
            constant.REMAINING_COUNT: 3,
            constant.NEXT_CHECKPOINT: "checkpoint1",
        },
        {
            "events": [4, 5],
            constant.REMAINING_COUNT: 2,
            constant.NEXT_CHECKPOINT: "checkpoint2",
        },
        {
            "events": [],
            constant.REMAINING_COUNT: 0,
            constant.NEXT_CHECKPOINT: "checkpoint3",
        },
        {
            "events": [6, 7, 8],
            constant.REMAINING_COUNT: 3,
            constant.NEXT_CHECKPOINT: "checkpoint4",
        },
        {
            "events": [9, 10],
            constant.REMAINING_COUNT: 2,
            constant.NEXT_CHECKPOINT: "checkpoint5",
        },
        {
            "events": [],
            constant.REMAINING_COUNT: 0,
            constant.NEXT_CHECKPOINT: "checkpoint6",
        },
    ]
    mock_extract_response.side_effect = lambda x: (
        x["events"],
        x[constant.REMAINING_COUNT],
        x[constant.NEXT_CHECKPOINT],
    )

    self.client.get_and_ingest_detection_events()

    self.assertEqual(mock_get_events.call_count, 6)
    self.assertEqual(mock_ingest.call_count, 6)
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_DETECTION_ENDPOINT + "_" + constant.ACCOUNT_TYPE,
        "checkpoint1",
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_DETECTION_ENDPOINT + "_" + constant.ACCOUNT_TYPE,
        "checkpoint2",
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_DETECTION_ENDPOINT + "_" + constant.HOST_TYPE,
        "checkpoint4",
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_DETECTION_ENDPOINT + "_" + constant.HOST_TYPE,
        "checkpoint5",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_detection_events_by_type"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._extract_response"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._set_last_checkpoint"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_detection_events_exception(
      self,
      mock_logging,
      mock_set_checkpoint,
      mock_ingest,
      mock_extract_response,
      mock_get_events,
  ):

    mock_get_events.side_effect = Exception("API Error")

    self.client.get_and_ingest_detection_events()
    mock_logging.assert_called_with(
        "Execution of Detection host stops due to exception occurred while"
        " making API call. Error message: API Error",
        severity="ERROR",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      side_effect=["true", "false"],
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_last_checkpoint"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._handle_checkpoint",
      return_value=("event_timestamp_gte", "test_checkpoint"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__get_detection_events_by_type(
      self,
      mock_logging,
      mock_handle_checkpoint,
      mock_get_last_checkpoint,
      mock_make_api_call,
      mock_env_var,
  ):
    expected_query_params = {
        "event_timestamp_gte": "test_checkpoint",
        "type": "test_type",
        "include_info_category": "true",
        "include_triaged": "false",
        "limit": constant.MAX_EVENT_LIMIT,
    }
    self.client._get_detection_events_by_type("test_type")
    mock_make_api_call.assert_called_once_with(
        constant.VECTRA_DETECTION_ENDPOINT, expected_query_params
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      side_effect=["true", "false"],
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call",
      side_effect=Exception("API Error"),
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_last_checkpoint"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._handle_checkpoint",
      return_value=("event_timestamp_gte", "test_checkpoint"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__get_detection_events_by_type_api_exception(
      self,
      mock_logging,
      mock_handle_checkpoint,
      mock_get_last_checkpoint,
      mock_make_api_call,
      mock_env_var,
  ):

    with self.assertRaisesRegex(Exception, "API Error"):
      self.client._get_detection_events_by_type("test_type")

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_audit_events"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._extract_response"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._set_last_checkpoint"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_audit_events_success(
      self,
      mock_logging,
      mock_set_checkpoint,
      mock_ingest,
      mock_extract_response,
      mock_get_events,
  ):
    mock_get_events.side_effect = [
        {
            "events": [1, 2, 3],
            constant.REMAINING_COUNT: 3,
            constant.NEXT_CHECKPOINT: "checkpoint1",
        },
        {
            "events": [4, 5],
            constant.REMAINING_COUNT: 2,
            constant.NEXT_CHECKPOINT: "checkpoint2",
        },
        {
            "events": [],
            constant.REMAINING_COUNT: 0,
            constant.NEXT_CHECKPOINT: "checkpoint3",
        },
    ]
    mock_extract_response.side_effect = lambda x: (
        x["events"],
        x[constant.REMAINING_COUNT],
        x[constant.NEXT_CHECKPOINT],
    )

    self.client.get_and_ingest_audit_events()

    self.assertEqual(mock_get_events.call_count, 3)
    self.assertEqual(
        mock_ingest.call_count, 3
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_AUDIT_ENDPOINT, "checkpoint1"
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_AUDIT_ENDPOINT, "checkpoint2"
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_audit_events"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._extract_response"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._set_last_checkpoint"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_audit_events_exception(
      self,
      mock_logging,
      mock_set_checkpoint,
      mock_ingest,
      mock_extract_response,
      mock_get_events,
  ):
    mock_get_events.side_effect = Exception("API Error")

    self.client.get_and_ingest_audit_events()

    mock_logging.assert_called_with(
        "Execution of Audit stops due to exception occurred while making API"
        " call. Error message: API Error",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_last_checkpoint"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._handle_checkpoint",
      return_value=("event_timestamp_gte", "test_checkpoint"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__get_audit_events(
      self,
      mock_logging,
      mock_handle_checkpoint,
      mock_get_last_checkpoint,
      mock_make_api_call,
  ):

    expected_query_params = {
        "event_timestamp_gte": (
            "test_checkpoint"
        ),
        "limit": constant.MAX_EVENT_LIMIT,
    }

    self.client._get_audit_events()

    mock_make_api_call.assert_called_once_with(
        constant.VECTRA_AUDIT_ENDPOINT, expected_query_params
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call",
      side_effect=Exception("API Error"),
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_last_checkpoint"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._handle_checkpoint",
      return_value=("event_timestamp_gte", "test_checkpoint"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__get_audit_events_exception(
      self,
      mock_logging,
      mock_handle_checkpoint,
      mock_get_last_checkpoint,
      mock_make_api_call,
  ):

    with self.assertRaisesRegex(Exception, "API Error"):
      self.client._get_audit_events()

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_entity_scoring_by_type"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._extract_response"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._set_last_checkpoint"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_entity_scoring_events_success(
      self,
      mock_logging,
      mock_set_checkpoint,
      mock_ingest,
      mock_extract_response,
      mock_get_events,
  ):
    mock_get_events.side_effect = [
        {
            "events": [1, 2, 3],
            constant.REMAINING_COUNT: 3,
            constant.NEXT_CHECKPOINT: "checkpoint1",
        },
        {
            "events": [4, 5],
            constant.REMAINING_COUNT: 2,
            constant.NEXT_CHECKPOINT: "checkpoint2",
        },
        {
            "events": [],
            constant.REMAINING_COUNT: 0,
            constant.NEXT_CHECKPOINT: "checkpoint3",
        },
        {
            "events": [6, 7, 8],
            constant.REMAINING_COUNT: 3,
            constant.NEXT_CHECKPOINT: "checkpoint4",
        },
        {
            "events": [9, 10],
            constant.REMAINING_COUNT: 2,
            constant.NEXT_CHECKPOINT: "checkpoint5",
        },
        {
            "events": [],
            constant.REMAINING_COUNT: 0,
            constant.NEXT_CHECKPOINT: "checkpoint6",
        },
    ]

    mock_extract_response.side_effect = lambda x: (
        x["events"],
        x[constant.REMAINING_COUNT],
        x[constant.NEXT_CHECKPOINT],
    )

    self.client.get_and_ingest_entity_scoring_events()

    self.assertEqual(
        mock_get_events.call_count, 6
    )
    self.assertEqual(
        mock_ingest.call_count, 6
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_SCORING_ENDPOINT + "_" + constant.ACCOUNT_TYPE,
        "checkpoint1",
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_SCORING_ENDPOINT + "_" + constant.ACCOUNT_TYPE,
        "checkpoint2",
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_SCORING_ENDPOINT + "_" + constant.HOST_TYPE,
        "checkpoint4",
    )
    mock_set_checkpoint.assert_any_call(
        constant.VECTRA_SCORING_ENDPOINT + "_" + constant.HOST_TYPE,
        "checkpoint5",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_entity_scoring_by_type"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._extract_response"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._set_last_checkpoint"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_entity_scoring_events_exception(
      self,
      mock_logging,
      mock_set_checkpoint,
      mock_ingest,
      mock_extract_response,
      mock_get_events,
  ):
    mock_get_events.side_effect = Exception("API Error")
    self.client.get_and_ingest_entity_scoring_events()
    mock_logging.assert_called_with(
        "Execution of Scoring host stops due to exception occurred while making"
        " API call. Error message: API Error",
        severity="ERROR",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value=True,
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_last_checkpoint"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._handle_checkpoint",
      return_value=("event_timestamp_gte", "test_checkpoint"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__get_entity_scoring_by_type(
      self,
      mock_logging,
      mock_handle_checkpoint,
      mock_get_last_checkpoint,
      mock_make_api_call,
      mock_env_var,
  ):

    expected_query_params = {
        "event_timestamp_gte": "test_checkpoint",
        "type": "test_type",
        "include_score_decreases": True,
        "limit": constant.MAX_EVENT_LIMIT,
    }

    self.client._get_entity_scoring_by_type("test_type")
    mock_make_api_call.assert_called_once_with(
        constant.VECTRA_SCORING_ENDPOINT, expected_query_params
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value=True,
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call",
      side_effect=Exception("API Error"),
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_last_checkpoint"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._handle_checkpoint",
      return_value=("event_timestamp_gte", "test_checkpoint"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__get_entity_scoring_by_type_exception(
      self,
      mock_logging,
      mock_handle_checkpoint,
      mock_get_last_checkpoint,
      mock_make_api_call,
      mock_env_var,
  ):

    with self.assertRaisesRegex(Exception, "API Error"):
      self.client._get_entity_scoring_by_type("test_type")

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value="test_vlans",
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call",
      return_value=None,
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_health_events_no_data(
      self, mock_logging, mock_ingest_events, mock_make_api_call, mock_env_var
  ):
    self.client.get_and_ingest_health_events()
    mock_logging.assert_called_with(
        "No data health received from the API response."
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value="test_vlans",
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call",
      return_value={"health": "good"},
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_health_events_success(
      self, mock_logging, mock_ingest_events, mock_make_api_call, mock_env_var
  ):
    self.client.get_and_ingest_health_events()

    mock_make_api_call.assert_called_once_with(
        constant.VECTRA_HEALTH_ENDPOINT, {"v_lans": "test_vlans"}
    )
    mock_ingest_events.assert_called_once_with([{"health": "good"}])
    mock_logging.assert_called_with("Health events ingested into Chronicle.")

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
      return_value="test_vlans",
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call",
      side_effect=Exception("API Error"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_health_events_exception(
      self, mock_logging, mock_ingest_events, mock_make_api_call, mock_env_var
  ):
    self.client.get_and_ingest_health_events()

    mock_logging.assert_called_with(
        "Execution of Health stops due to exception occurred while making API"
        " call. Error message: API Error",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.HandleExceptions")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_validate_response_success(
      self, mock_logging, mock_handle_exceptions
  ):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.raise_for_status.return_value = (
        None
    )
    VectraClient.validate_response("/test_url", mock_response)
    mock_logging.assert_not_called()
    mock_handle_exceptions.assert_not_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.HandleExceptions")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_validate_response_http_error(
      self, mock_logging, mock_handle_exceptions
  ):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        "HTTP Error"
    )
    mock_response.status_code = 400
    VectraClient.validate_response("/test_url", mock_response)

    mock_handle_exceptions.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_validate_response_rate_limit_error(self, mock_logging):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        "Rate Limited"
    )
    mock_response.status_code = status.STATUS_TOO_MANY_REQUESTS

    with self.assertRaisesRegex(
        exception.RateLimitException, "API rate limit exceeded."
    ):
      VectraClient.validate_response("/test_url", mock_response)

    mock_logging.assert_any_call(
        "RateLimitException occurred. API rate limit exceeded. Error message:"
        " Rate Limited",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.HandleExceptions")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_validate_response_other_exception(
      self, mock_logging, mock_handle_exceptions
  ):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.raise_for_status.side_effect = Exception(
        "Generic Error"
    )

    with self.assertRaisesRegex(Exception, "Generic Error"):
      VectraClient.validate_response("test_url", mock_response)

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.time.sleep")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__make_api_call_rate_limit_max_retry(self, mock_logging, mock_sleep):
    mock_response = MagicMock(status_code=429, headers={"Retry-After": "1"})
    self.client.session.request.return_value = mock_response
    with patch.object(
        self.client,
        "validate_response",
        side_effect=exception.RateLimitException("Rate Limit Exceeded"),
    ):
      with self.assertRaises(exception.RateLimitException) as context:
        self.client._make_api_call("/test", retry_count=1)
      self.assertIn(
          constant.ERRORS["RATE_LIMIT_EXCEEDED"], str(context.exception)
      )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_make_api_call_unauthorize_max_retry(self, mock_logging):
    self.client.session.request.return_value = MagicMock()
    with patch.object(
        self.client,
        "validate_response",
        side_effect=exception.UnauthorizeException("Unauthorized"),
    ):
      with patch.object(
          self.client, "_generate_access_token"
      ) as mock_generate_token:
        with self.assertRaisesRegex(
            exception.UnauthorizeException, "Unauthorized"
        ):
          self.client._make_api_call(
              "/test", retry_count_token=1
          )
        mock_generate_token.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__make_api_call_json_decode_error(self, mock_logging):
    mock_response = MagicMock()
    mock_response.json.side_effect = json.JSONDecodeError(
        "Invalid JSON", "", 0
    )
    self.client.session.request.return_value = mock_response
    with patch.object(
        self.client, "validate_response"
    ) as mock_validate:
      mock_validate.return_value = None

      result = self.client._make_api_call("/test")
      self.assertEqual(result, {})  # pylint: disable=g-generic-assert
      mock_logging.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__make_api_call_generic_exception(self, mock_logging):
    self.client.session.request.side_effect = Exception("Generic API error")

    with patch.object(
        self.client, "validate_response"
    ) as mock_validate:
      mock_validate.return_value = None

      result = self.client._make_api_call("/test")
      self.assertEqual(result, {})  # pylint: disable=g-generic-assert
      mock_logging.assert_called()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_make_api_call_success(self, mock_logging):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "key": "value"
    }
    self.client.session.request.return_value = mock_response

    with patch.object(
        self.client, "validate_response"
    ) as mock_validate:
      mock_validate.return_value = None

      result = self.client._make_api_call(
          "/test_endpoint", params={"param1": "value1"}, method="GET"
      )
      self.assertEqual(
          result, {"key": "value"}
      )
      self.client.session.request.assert_called_once_with(
          "GET",
          "https://dummy.com/test_endpoint",
          params={"param1": "value1"},
          data=None,
          timeout=constant.DEFAULT_REQUEST_TIMEOUT,
      )

      mock_validate.assert_called_once_with(
          "/test_endpoint", mock_response
      )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_make_api_call_success_with_data(self, mock_logging):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": [{"id": 1}, {"id": 2}]
    }
    self.client.session.request.return_value = mock_response
    with patch.object(self.client, "validate_response") as mock_validate:
      mock_validate.return_value = None

      result = self.client._make_api_call("/test")
      self.assertEqual(result, {"data": [{"id": 1}, {"id": 2}]})

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.time.sleep")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_make_api_call_rate_limit_retry_success(
      self, mock_logging, mock_sleep
  ):
    mock_response_retry = MagicMock()
    mock_response_retry.status_code = 200
    mock_response_retry.json.return_value = {"key": "value"}

    mock_response_rate_limit = MagicMock(
        status_code=429, headers={"Retry-After": "0"}
    )

    self.client.session.request.side_effect = [
        mock_response_rate_limit,
        mock_response_retry,
    ]

    with patch.object(
        self.client,
        "validate_response",
        side_effect=[exception.RateLimitException("Rate limit exceeded"), None],
    ):
      result = self.client._make_api_call("/test")
      self.assertEqual(
          result, {"key": "value"}
      )
      mock_sleep.assert_called_once_with(0)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_rest_call_for_token_generation",
      side_effect=exception.RateLimitException("Rate limit exceeded"),
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_access_and_refresh_token_rate_limit(
      self, mock_logging, mock_make_rest_call
  ):
    with self.assertRaises(exception.RateLimitException) as e:
      self.client._generate_access_and_refresh_token()
    self.assertIn("Rate limit exceeded", str(e.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_initial_access_and_refresh_token_both_missing(
      self, mock_logging
  ):
    self.mock_secret_manager_client.get_secrets.return_value = (
        {}
    )
    with patch.object(
        self.client, "_generate_access_and_refresh_token"
    ) as mock_generate:
      self.client._generate_initial_access_and_refresh_token()
      mock_generate.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_initial_access_and_refresh_token_only_access_token_missing(
      self, mock_logging
  ):
    self.mock_secret_manager_client.get_secrets.return_value = {
        "refresh_token": "test_refresh_token"
    }
    with patch.object(
        self.client, "_generate_access_and_refresh_token"
    ) as mock_generate:
      self.client._generate_initial_access_and_refresh_token()
      mock_generate.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_initial_access_and_refresh_token_only_refresh_token_missing(
      self, mock_logging
  ):
    self.mock_secret_manager_client.get_secrets.return_value = {
        "access_token": "test_access_token"
    }
    with patch.object(
        self.client, "_generate_access_and_refresh_token"
    ) as mock_generate:
      self.client._generate_initial_access_and_refresh_token()
      mock_generate.assert_called_once()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient.validate_response"
  )
  def test__make_rest_call_for_token_generation_exception(
      self, mock_validate, mock_logging
  ):
    mock_validate.side_effect = Exception("Generic API Error")
    with self.assertRaisesRegex(
        exception.VectraException, "Generic API Error"
    ):
      self.client._make_rest_call_for_token_generation()

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_rest_call_for_token_generation",
      side_effect=exception.UnauthorizeException("Unauthorized"),
  )
  def test__generate_access_and_refresh_token_unauthorized(
      self, mock_make_rest_call, mock_logging
  ):
    with self.assertRaisesRegex(
        exception.UnauthorizeException, "Unauthorized"
    ):
      self.client._generate_access_and_refresh_token()

  @patch("google.cloud.storage.Client")
  def test__get_last_checkpoint_invalid_input(self, MockStorageClient):
    checkpoint = self.client._get_last_checkpoint("")
    self.assertIsNone(
        checkpoint
    )

    checkpoint = self.client._get_last_checkpoint(None)
    self.assertIsNone(checkpoint)

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_entity_scoring_by_type"
  )
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._extract_response"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._set_last_checkpoint"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_entity_scoring_events_empty(
      self,
      mock_logging,
      mock_set_checkpoint,
      mock_ingest,
      mock_extract_response,
      mock_get_events,
  ):
    mock_get_events.side_effect = [{
        "result": [],
        constant.REMAINING_COUNT: 1,
        constant.NEXT_CHECKPOINT: "checkpoint1",
    }]

    mock_extract_response.side_effect = lambda x: (
        x["events"],
        x[constant.REMAINING_COUNT],
        x[constant.NEXT_CHECKPOINT],
    )

    self.client.get_and_ingest_entity_scoring_events()

    self.assertEqual(
        mock_get_events.call_count, 2
    )
    self.assertEqual(mock_ingest.call_count, 0)

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient.validate_response"
  )
  def test__make_rest_call_for_token_generation_rate_limit_exception_retry_success(
      self, mock_validate, mock_logging
  ):
    mock_response = MagicMock(
        headers={"Retry-After": 1}, status_code=429
    )
    mock_response_success = MagicMock(
        status_code=200,
        json=lambda: {
            "access_token": "new_token",
            "refresh_token": "new_refresh_token",
        },
    )
    self.client.session.request.side_effect = [
        mock_response,
        mock_response_success,
    ]

    mock_validate.side_effect = [
        exception.RateLimitException("Rate Limit Exceeded"),
        None,
    ]
    self.client._make_rest_call_for_token_generation(
        retry_count=1
    )
    self.assertEqual(self.client.access_token, "new_token")
    self.assertEqual(self.client.refresh_token, "new_refresh_token")

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_access_and_refresh_token_vectra_exception(
      self, mock_logging
  ):

    with patch.object(
        self.client,
        "_make_rest_call_for_token_generation",
        side_effect=exception.VectraException("Vectra Error"),
    ):
      with self.assertRaises(
          exception.VectraException
      ):
        self.client._generate_access_and_refresh_token()

  @patch("google.cloud.storage.Client")
  def test__get_last_checkpoint_invalid_json(self, MockStorageClient):
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = (
        "invalid_json"
    )

    client = VectraClient(
        "dummy_id",
        "dummy_secret",
        "https://dummy.com",
        "dummy_bucket",
        MagicMock(),
    )
    checkpoint = client._get_last_checkpoint("test_endpoint")
    self.assertIsNone(
        checkpoint
    )

  @patch("google.cloud.storage.Client")
  def test__set_last_checkpoint_invalid_json(self, MockStorageClient):
    mock_client = MockStorageClient.return_value
    mock_bucket = mock_client.get_bucket.return_value
    mock_blob = mock_bucket.blob.return_value
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = "invalid_json"

    mock_open = MagicMock()
    mock_blob.open.return_value.__enter__.return_value = mock_open

    client = VectraClient(
        "dummy_id",
        "dummy_secret",
        "https://dummy.com",
        "dummy_bucket",
        MagicMock(),
    )

    client._set_last_checkpoint("new_endpoint", "new_checkpoint")

    mock_open.write.assert_called_once_with(
        json.dumps({"new_endpoint": "new_checkpoint"})
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__set_last_checkpoint_exception(self, mock_logging):
    mock_client = MagicMock()
    mock_client.get_bucket.side_effect = Exception(
        "Bucket Error"
    )
    with patch("google.cloud.storage.Client", return_value=mock_client):
      with patch(
          f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
          return_value="test_bucket",
      ):
        self.client._set_last_checkpoint("endpoint", "checkpoint")
        mock_logging.assert_called_with(
            "Unknown exception occurred while setting checkpoint. Error"
            " message: Bucket Error",
            severity="ERROR",
        )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__get_detection_events_by_type_success(self, mock_logging):
    with patch.object(self.client, "_make_api_call") as mock_api_call:
      with patch.object(
          self.client, "_get_last_checkpoint"
      ) as mock_get_checkpoint:
        with patch.object(
            self.client, "_handle_checkpoint"
        ) as mock_handle_checkpoint:
          with patch(
              f"{INGESTION_SCRIPTS_PATH}vectra_client.vectra_utils.get_environment_variable",
              side_effect=["test_info_category", "test_triaged"],
          ):
            mock_get_checkpoint.return_value = "test_checkpoint"
            mock_handle_checkpoint.return_value = ("test_field", "test_value")
            mock_api_call.return_value = {"key": "value"}
            response = self.client._get_detection_events_by_type("test_type")
            self.assertEqual(response, {"key": "value"})
            mock_api_call.assert_called_with(
                constant.VECTRA_DETECTION_ENDPOINT,
                {
                    "test_field": "test_value",
                    "type": "test_type",
                    "include_info_category": "test_info_category",
                    "include_triaged": "test_triaged",
                    "limit": constant.MAX_EVENT_LIMIT,
                },
            )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test__generate_initial_access_and_refresh_token_token_generation_exception(
      self, mock_logging
  ):
    self.mock_secret_manager_client.get_secrets.side_effect = Exception(
        "Secret not found"
    )
    with patch.object(
        self.client, "_generate_access_and_refresh_token"
    ) as mock_generate:
      mock_generate.side_effect = exception.RefreshTokenException(
          "Invalid refresh token"
      )
      with self.assertRaises(
          Exception
      ) as e:
        self.client._generate_initial_access_and_refresh_token()
      self.assertIn(
          "Invalid refresh token", str(e.exception)
      )

      mock_logging.assert_called_with(
          "Failed to generate tokens: Invalid refresh token", severity="ERROR"
      )
      self.assertIsNone(
          self.client.access_token
      )
      self.assertIsNone(self.client.refresh_token)

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient.validate_response"
  )
  def test__make_rest_call_for_token_generation_rate_limit_exceeded(
      self, mock_validate, mock_logging
  ):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.headers = {"Retry-After": 1}
    mock_response.status_code = 429
    mock_validate.side_effect = exception.RateLimitException(
        "Rate limit exceeded"
    )

    with self.assertRaises(exception.RateLimitException) as context:
      self.client._make_rest_call_for_token_generation(
          retry_count=0
      )

    self.assertIn(
        "Rate limit exceeded. Please wait and try again.",
        str(context.exception),
    )

    mock_logging.assert_called_with(
        "Maximum retry count reached. Failed to generate new access token"
        f" using refresh token. {constant.ERRORS['RATE_LIMIT_EXCEEDED']}",
        severity="ERROR",
    )

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_entity_lockdown_by_type"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_lockdown_events_success(
      self, mock_logging, mock_ingest, mock_get_lockdown
  ):
    mock_get_lockdown.side_effect = [
        [
            {"id": 1, "type": constant.ACCOUNT_TYPE}
        ],
        [{"id": 2, "type": constant.HOST_TYPE}],
    ]

    self.client.get_and_ingest_lockdown_events()

    mock_get_lockdown.assert_any_call(constant.ACCOUNT_TYPE)
    mock_ingest.assert_any_call([{"id": 1, "type": constant.ACCOUNT_TYPE}])
    mock_get_lockdown.assert_any_call(constant.HOST_TYPE)
    mock_ingest.assert_any_call([{"id": 2, "type": constant.HOST_TYPE}])

  @patch(
      f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_entity_lockdown_by_type"
  )
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._ingest_events")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  def test_get_and_ingest_lockdown_events_exception(
      self, mock_logging, mock_ingest, mock_get_lockdown
  ):
    mock_get_lockdown.side_effect = Exception("API Error")

    self.client.get_and_ingest_lockdown_events()

    mock_logging.assert_called_with(
        f"Execution of Lockdown {constant.HOST_TYPE} stops due to exception"
        " occurred while making API call. Error message: API Error",
        severity="ERROR",
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call")
  def test__get_entity_lockdown_by_type_success(
      self, mock_api_call, mock_logging
  ):
    mock_api_call.return_value = [
        {"id": 1, "type": "account"}
    ]
    lockdown_type = "account"
    response = self.client._get_entity_lockdown_by_type(lockdown_type)
    mock_logging.assert_called_with(
        f"Entity lockdown events for {lockdown_type} type."
    )
    mock_api_call.assert_called_with(
        constant.VECTRA_LOCKDOWN_ENDPOINT, {"type": lockdown_type}
    )
    self.assertEqual(response, [{"id": 1, "type": "account"}])

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._make_api_call")
  def test__get_entity_lockdown_by_type_exception(
      self, mock_api_call, mock_logging
  ):
    mock_api_call.side_effect = Exception("API Error")
    lockdown_type = "host"
    with self.assertRaises(Exception) as e:
      self.client._get_entity_lockdown_by_type(lockdown_type)
    self.assertIn("API Error", str(e.exception))

  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.utils.cloud_logging")
  @patch(f"{INGESTION_SCRIPTS_PATH}vectra_client.VectraClient._get_entity_lockdown_by_type")
  def test__get_entity_lockdown_by_type_none(
      self, mock_get_entity_lockdown_by_type, mock_logging
  ):
    mock_get_entity_lockdown_by_type.side_effect = None
    self.client.get_and_ingest_lockdown_events()
    mock_logging.assert_called_with(
        "No data lockdown received from the API response for host type."
    )
