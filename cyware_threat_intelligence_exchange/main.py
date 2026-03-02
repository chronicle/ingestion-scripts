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
"""Main script for Cyware CTIX to Google SecOps SIEM ingestion."""

import traceback
import urllib.parse

from common import utils
import constant
import cyware_client
import exception_handler
import utility


def main(request):  # pylint: disable=unused-argument
  """Driver function for Cyware CTIX data ingestion into Google SecOps.

  This function:
  1. Loads and validates required environment variables
  2. Acquires process lock to prevent overlapping executions
  3. Initializes the CTIX client
  4. Fetches saved result set data (sequential pagination)
  5. Optionally fetches enrichment data via bulk IOC lookup (if enabled)
  6. Ingests data into Google SecOps Chronicle
  7. Releases process lock on completion or error

  Args:
      request: The request object from the cloud function.

  Returns:
      A tuple of (message, status_code) where message is a string
      indicating success or failure, and status_code is an HTTP status
      code.
  """
  tenant_name = None
  bucket_name = None

  try:
    utility.check_sufficient_permissions_on_service_account()

    utils.cloud_logging("Starting Cyware CTIX ingestion process.")

    tenant_name = utility.get_environment_variable(constant.ENV_TENANT_NAME)
    base_url = utility.get_environment_variable(
        constant.ENV_BASE_URL, is_required=True
    )
    if not tenant_name:
      parsed_url = urllib.parse.urlparse(base_url)
      tenant_name = parsed_url.netloc
      utils.cloud_logging(
          "Tenant name not provided, extracted tenant name "
          f"from base url is: {tenant_name}"
      )
    bucket_name = utility.get_environment_variable(
        constant.ENV_GCP_BUCKET_NAME, is_required=True
    )

    if not utility.acquire_process_lock(tenant_name, bucket_name):
      return (
          "Another process is already running. Skipping execution.",
          409,
      )
    access_id = utility.get_environment_variable(
        constant.ENV_ACCESS_ID, is_required=True, is_secret=True
    )
    secret_key = utility.get_environment_variable(
        constant.ENV_SECRET_KEY, is_required=True, is_secret=True
    )
    enrichment_enabled_str = utility.get_environment_variable(
        constant.ENV_ENRICHMENT_ENABLED
    )
    enrichment_enabled = utility.parse_boolean_env(enrichment_enabled_str)
    lookback_days = utility.get_environment_variable(
        constant.ENV_INDICATOR_LOOKBACK_DAYS
    )
    lookback_days = utility.validate_integer_env(
        lookback_days, constant.ENV_INDICATOR_LOOKBACK_DAYS
    )
    label_name = utility.get_environment_variable(
        constant.ENV_LABEL_NAME, is_required=True
    )

    utils.cloud_logging(
        f"Configuration loaded - Tenant: {tenant_name}, "
        f"Base URL: {base_url}, "
        f"Enrichment: {'enabled' if enrichment_enabled else 'disabled'}, "
        f"Lookback Days: {lookback_days}"
    )

    ctix_client = cyware_client.CTIXClient(
        base_url=base_url,
        access_id=access_id,
        secret_key=secret_key,
        tenant_name=tenant_name,
        enrichment_enabled=enrichment_enabled,
        label_name=label_name,
        bucket_name=bucket_name,
        lookback_days=lookback_days,
    )

    try:
      ctix_client.fetch_indicators_by_labels()
      utility.release_process_lock(tenant_name, bucket_name)
      return "Data ingestion completed successfully.", 200

    except exception_handler.RunTimeExceeded as e:
      utils.cloud_logging(
          "Execution time limit exceeded during CTIX data collection &"
          f" ingestion. Error message: {str(e)}\n"
          f"Traceback: {traceback.format_exc()}",
          severity="WARNING",
      )
      utility.release_process_lock(tenant_name, bucket_name)
      return f"Execution time limit exceeded: {repr(e)}", 200

    except exception_handler.CywareCTIXException as e:
      utils.cloud_logging(
          "Error occurred while CTIX data collection & ingestion."
          f" Error message: {str(e)}\n"
          f"Traceback: {traceback.format_exc()}",
          severity="ERROR",
      )
      utility.release_process_lock(tenant_name, bucket_name)
      return f"Error during CTIX data ingestion: {repr(e)}", 400

    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Unknown exception occurred while CTIX data collection "
          f"& ingestion. Error message: {str(e)}\n"
          f"Traceback: {traceback.format_exc()}",
          severity="ERROR",
      )
      utility.release_process_lock(tenant_name, bucket_name)
      return (
          f"An unknown error occurred during CTIX data ingestion: {repr(e)}",
          400,
      )

  except exception_handler.GCPPermissionDeniedError as e:
    utils.cloud_logging(
        "The service account does not have sufficient permissions for CTIX"
        f" ingestion. Error message: {str(e)}\n"
        f"Traceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    if tenant_name and bucket_name:
      utility.release_process_lock(tenant_name, bucket_name)
    return (
        "The service account does not have sufficient permissions "
        + "for CTIX ingestion.",
        403,
    )
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        f"Unknown exception occurred during initialization: {repr(e)}\n"
        f"Traceback: {traceback.format_exc()}",
        severity="ERROR",
    )
    if tenant_name and bucket_name:
      utility.release_process_lock(tenant_name, bucket_name)
    return f"Error initializing: {repr(e)}", 500
