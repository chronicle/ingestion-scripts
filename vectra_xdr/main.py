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
"""Main script for Vectra XDR ingestion."""

from common import utils
import constant
import utils as vectra_utils
import vectra_client


def main(request):  # pylint: disable=unused-argument
  try:
    secret_manager_client = vectra_utils.SecretManagerClient()
    client_id = secret_manager_client.get_secrets(
        secret_name=vectra_utils.get_environment_variable(
            constant.ENV_CLIENT_ID_SECRECT_NAME,
            is_required=True,
            is_secret=True,
        ),
        secret_format_is_json_type=False,
    )
    client_secrets = secret_manager_client.get_secrets(
        secret_name=vectra_utils.get_environment_variable(
            constant.ENV_CLIENT_SECRET_SECRET_NAME,
            is_required=True,
            is_secret=True,
        ),
        secret_format_is_json_type=False,
    )
    base_url = vectra_utils.get_environment_variable(
        constant.ENV_VECTRA_BASE_URL, is_required=True
    )
    bucket_name = vectra_utils.get_environment_variable(
        constant.ENV_GCP_BUCKET_NAME, is_required=True
    )

    vectra_client_instance = vectra_client.VectraClient(
        client_id=client_id,
        client_secret=client_secrets,
        base_url=base_url,
        bucket_name=bucket_name,
        secret_manager_client=secret_manager_client,
    )

    methods_map = {
        constant.ENV_VAR_DETECTION: (
            vectra_client_instance.get_and_ingest_detection_events
        ),
        constant.ENV_VAR_SCORING: (
            vectra_client_instance.get_and_ingest_entity_scoring_events
        ),
        constant.ENV_VAR_LOCKDOWN: (
            vectra_client_instance.get_and_ingest_lockdown_events
        ),
        constant.ENV_VAR_AUDIT: (
            vectra_client_instance.get_and_ingest_audit_events
        ),
        constant.ENV_VAR_HEALTH: (
            vectra_client_instance.get_and_ingest_health_events
        ),
    }

    # Get enabled methods from environment variables
    enabled_methods = []
    for method_name, method_func in methods_map.items():
      if vectra_utils.get_environment_variable(method_name) == "true":
        enabled_methods.append(method_func)

    # Check if there are no methods to run
    if not enabled_methods:
      utils.cloud_logging(
          "No methods enabled. Please set proper environment variables.",
          severity="ERROR",
      )
      return "No methods enabled. Please set proper environment variables.", 400

    utils.cloud_logging(
        "Enabled methods:"
        f" {', '.join([method.__name__ for method in enabled_methods])}",
    )
    # Run enabled methods with intervals
    try:
      vectra_utils.run_methods_with_intervals(enabled_methods)
      utils.cloud_logging("Methods executed successfully.")
      return "data ingestion completed"
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Unknown exception occurred while executing methods parallelly."
          f" Error message: {str(e)}",
          severity="ERROR",
      )
      return f"Error executing methods: {str(e)}"

  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        "Unknown exception occurred while retrieving the environment"
        f" credentials. Error message: {e}",
        severity="ERROR",
    )
    return f"Error initializing: {str(e)}", 500
