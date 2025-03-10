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
# pylint: disable=invalid-name
# pylint: disable=unused-argument
# pylint: disable=g-import-not-at-top

import sys
import unittest
from unittest import mock

INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest"] = mock.Mock()

import constant
import main

MagicMock = mock.MagicMock
patch = mock.patch


class TestMainFunction(unittest.TestCase):

  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.SecretManagerClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_client.VectraClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.run_methods_with_intervals")
  def test_successful_execution(
      self,
      mock_run_methods,
      MockVectraClient,
      MockSecretManagerClient,
      mock_get_env_var,
  ):
    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_CLIENT_ID_SECRECT_NAME: "client_id_secret",
        constant.ENV_CLIENT_SECRET_SECRET_NAME: "client_secret_secret",
        constant.ENV_VECTRA_BASE_URL: "https://vectra.example.com",
        constant.ENV_GCP_BUCKET_NAME: "test_bucket",
        constant.ENV_VAR_DETECTION: "true",
        constant.ENV_VAR_SCORING: "true",
        constant.ENV_VAR_LOCKDOWN: "true",
        constant.ENV_VAR_AUDIT: "true",
        constant.ENV_VAR_HEALTH: "true",
    }.get(
        key
    )

    mock_secret_manager_instance = MockSecretManagerClient.return_value
    mock_secret_manager_instance.get_secrets.return_value = "test_secret"
    mock_vectra_client_instance = MockVectraClient.return_value

    mock_vectra_client_instance.get_and_ingest_detection_events.__name__ = (
        "get_and_ingest_detection_events"
    )
    mock_vectra_client_instance.get_and_ingest_entity_scoring_events.__name__ = (
        "get_and_ingest_entity_scoring_events"
    )
    mock_vectra_client_instance.get_and_ingest_lockdown_events.__name__ = (
        "get_and_ingest_lockdown_events"
    )
    mock_vectra_client_instance.get_and_ingest_audit_events.__name__ = (
        "get_and_ingest_audit_events"
    )
    mock_vectra_client_instance.get_and_ingest_health_events.__name__ = (
        "get_and_ingest_health_events"
    )

    result = main.main(MagicMock())

    MockVectraClient.assert_called_once_with(
        client_id="test_secret",
        client_secret="test_secret",
        base_url="https://vectra.example.com",
        bucket_name="test_bucket",
        secret_manager_client=mock_secret_manager_instance,
    )

    mock_get_env_var.asset_called_once_with(
        constant.ENV_CLIENT_SECRET_SECRET_NAME, is_required=True, is_secret=True
    )

    mock_get_env_var.asset_called_once_with(
        constant.ENV_GCP_PROJECT_NUMBER, is_required=True
    )

    expected_enabled_methods = [
        mock_vectra_client_instance.get_and_ingest_detection_events,
        mock_vectra_client_instance.get_and_ingest_entity_scoring_events,
        mock_vectra_client_instance.get_and_ingest_lockdown_events,
        mock_vectra_client_instance.get_and_ingest_audit_events,
        mock_vectra_client_instance.get_and_ingest_health_events,
    ]
    mock_run_methods.assert_called_once_with(expected_enabled_methods)
    self.assertEqual(result, "data ingestion completed")

  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.SecretManagerClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_client.VectraClient")
  def test_no_methods_enabled(
      self,
      MockVectraClient,
      MockSecretManagerClient,
      mock_get_env_var,
  ):
    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_CLIENT_ID_SECRECT_NAME: "client_id_secret",
        constant.ENV_CLIENT_SECRET_SECRET_NAME: "client_secret_secret",
        constant.VECTRA_API_TOKEN_SECRET_NAME: "vectra_api_token",
        constant.ENV_VECTRA_BASE_URL: "https://vectra.example.com",
        constant.ENV_GCP_BUCKET_NAME: "test_bucket",
        constant.ENV_VAR_DETECTION: "false",
        constant.ENV_VAR_SCORING: "false",
        constant.ENV_VAR_LOCKDOWN: "false",
        constant.ENV_VAR_AUDIT: "false",
        constant.ENV_VAR_HEALTH: "false",
    }.get(
        key
    )
    mock_secret_manager_instance = MockSecretManagerClient.return_value
    mock_secret_manager_instance.get_secrets.return_value = "test_secret"
    request = MagicMock()
    response = main.main(request)
    self.assertEqual(
        response,
        ("No methods enabled. Please set proper environment variables.", 400),
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.SecretManagerClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_error_in_secret_retrieval(
      self,
      mock_cloud_logging,
      MockSecretManagerClient,
      mock_get_environment_variable,
  ):
    mock_get_environment_variable.side_effect = lambda key, is_required=False, is_secret=False: {
        "ENV_CLIENT_ID_SECRECT_NAME": "client_id_secret",
        "ENV_CLIENT_SECRET_SECRET_NAME": "client_secret_secret",
        "ENV_VECTRA_BASE_URL": "https://vectra.example.com",
        "ENV_GCP_BUCKET_NAME": "test_bucket",
    }.get(
        key
    )

    mock_secret_manager_instance = MockSecretManagerClient.return_value
    mock_secret_manager_instance.get_secrets.side_effect = Exception(
        "Secret retrieval error"
    )

    request = MagicMock()
    response = main.main(request)

    mock_cloud_logging.assert_any_call(
        "Unknown exception occurred while retrieving the environment"
        " credentials. Error message: Secret retrieval error",
        severity="ERROR",
    )
    self.assertEqual(
        response, ("Error initializing: Secret retrieval error", 500)
    )

  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.get_environment_variable")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.SecretManagerClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_client.VectraClient")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.vectra_utils.run_methods_with_intervals")
  @patch(f"{INGESTION_SCRIPTS_PATH}main.utils.cloud_logging")
  def test_run_methods_error(
      self,
      mock_logging,
      mock_run_methods,
      MockVectraClient,
      MockSecretManagerClient,
      mock_get_env_var,
  ):

    mock_get_env_var.side_effect = lambda key, is_required=False, is_secret=False: {
        constant.ENV_CLIENT_ID_SECRECT_NAME: "client_id_secret",
        constant.ENV_CLIENT_SECRET_SECRET_NAME: "client_secret_secret",
        constant.ENV_VECTRA_BASE_URL: "https://vectra.example.com",
        constant.ENV_GCP_BUCKET_NAME: "test_bucket",
        constant.ENV_VAR_DETECTION: "true",
    }.get(
        key
    )

    mock_secret_manager_instance = MockSecretManagerClient.return_value
    mock_secret_manager_instance.get_secrets.return_value = "test_secret"
    mock_run_methods.side_effect = Exception("Error running methods")

    mock_vectra_client_instance = MockVectraClient.return_value
    mock_vectra_client_instance.get_and_ingest_detection_events.__name__ = (
        "get_and_ingest_detection_events"
    )
    mock_vectra_client_instance.get_and_ingest_entity_scoring_events.__name__ = (
        "get_and_ingest_entity_scoring_events"
    )
    mock_vectra_client_instance.get_and_ingest_lockdown_events.__name__ = (
        "get_and_ingest_lockdown_events"
    )
    mock_vectra_client_instance.get_and_ingest_audit_events.__name__ = (
        "get_and_ingest_audit_events"
    )
    mock_vectra_client_instance.get_and_ingest_health_events.__name__ = (
        "get_and_ingest_health_events"
    )

    request = MagicMock()
    main.main(request)

    mock_logging.assert_called_with(
        "Unknown exception occurred while executing methods parallelly. Error"
        " message: Error running methods",
        severity="ERROR",
    )
