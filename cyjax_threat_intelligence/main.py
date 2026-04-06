# Copyright 2026 Google LLC
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
"""Main script for Cyjax to Google SecOps SIEM ingestion."""

from typing import Tuple

from common import utils
import constant as con
import cyjax_client
import exception_handler
import utility


def main(request) -> Tuple[str, int]:  # pylint: disable=unused-argument
  """Entry point for Cyjax IOC ingestion into Google SecOps.

  Args:
      request: Flask request object (required for Cloud Functions).

  Returns:
      Tuple[str, int]: Status message and HTTP status code.
  """
  bucket_name = None

  try:
    utility.check_sufficient_permissions_on_service_account()

    utils.cloud_logging("Starting Cyjax ingestion process.")

    bucket_name = utility.get_environment_variable(
        con.ENV_GCP_BUCKET_NAME, is_required=True
    )

    if not utility.acquire_process_lock(bucket_name):
      return (
          "Another process is already running. Skipping execution.",
          409,
      )

    api_token = utility.get_environment_variable(
        con.ENV_CYJAX_API_TOKEN, is_required=True, is_secret=True
    )
    historical_ioc_duration_str = utility.get_environment_variable(
        con.ENV_HISTORICAL_IOC_DURATION
    )
    historical_ioc_duration = utility.validate_integer_env(
        historical_ioc_duration_str, con.ENV_HISTORICAL_IOC_DURATION
    )
    if (
        historical_ioc_duration
        and historical_ioc_duration > con.MAX_HISTORICAL_IOC_DURATION
    ):
      raise exception_handler.CyjaxException(
          "HISTORICAL_IOC_DURATION cannot exceed "
          f"{con.MAX_HISTORICAL_IOC_DURATION} days. "
          f"Provided value: {historical_ioc_duration}."
      )
    query = utility.get_environment_variable(con.ENV_QUERY)
    enable_enrichment_str = utility.get_environment_variable(
        con.ENV_ENABLE_ENRICHMENT
    )
    enable_enrichment = utility.parse_boolean_env(enable_enrichment_str)
    indicator_types = utility.get_environment_variable(con.ENV_INDICATOR_TYPES)

    if indicator_types:
      types_list = [t.strip() for t in indicator_types.split("|")]
      indicator_types = ",".join(types_list)

    utils.cloud_logging(
        "Configuration loaded - "
        f"Historical IOC Duration: {historical_ioc_duration} days, "
        f"Query: {query if query else 'None'}, "
        f"Enrichment Enabled: {enable_enrichment}, "
        f"Indicator Type: {indicator_types if indicator_types else 'All'}."
    )

    cyjax_client_instance = cyjax_client.CyjaxClient(
        api_token=api_token,
        bucket_name=bucket_name,
        historical_ioc_duration=historical_ioc_duration,
        enable_enrichment=enable_enrichment,
        query=query,
        indicator_type=indicator_types,
    )

    try:
      cyjax_client_instance.fetch_and_ingest_indicators()
      utility.release_process_lock(bucket_name)
      return "Data ingestion completed successfully.", 200

    except exception_handler.RunTimeExceeded as e:
      utils.cloud_logging(
          "Execution time limit exceeded during Cyjax data collection &"
          f" ingestion. Error message: {str(e)}.",
          severity="WARNING",
      )
      utility.release_process_lock(bucket_name)
      return f"Execution time limit exceeded: {repr(e)}", 200

    except exception_handler.CyjaxException as e:
      utils.cloud_logging(
          "Error occurred while Cyjax data collection & ingestion."
          f" Error message: {str(e)}.",
          severity="ERROR",
      )
      utility.release_process_lock(bucket_name)
      return f"Error during Cyjax data ingestion: {repr(e)}", 400

    except Exception as e:  # pylint: disable=broad-exception-caught
      utils.cloud_logging(
          "Unknown exception occurred while Cyjax data collection "
          f"& ingestion. Error message: {str(e)}.",
          severity="ERROR",
      )
      utility.release_process_lock(bucket_name)
      return (
          f"An unknown error occurred during Cyjax data ingestion: {repr(e)}",
          400,
      )

  except exception_handler.GCPPermissionDeniedError as e:
    utils.cloud_logging(
        "The service account does not have sufficient permissions for Cyjax"
        f" ingestion. Error message: {str(e)}.",
        severity="ERROR",
    )
    if bucket_name:
      utility.release_process_lock(bucket_name)
    return (
        "The service account does not have sufficient permissions "  # pylint: disable=implicit-str-concat
        "for Cyjax ingestion.",
        403,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    utils.cloud_logging(
        f"Unknown exception occurred during initialization: {repr(e)}.",
        severity="ERROR",
    )
    if bucket_name:
      utility.release_process_lock(bucket_name)
    return f"Error initializing: {repr(e)}", 500
