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
"""Fetch the Audit Trail logs from the Aruba Central platform and ingest into Chronicle."""

import datetime
from typing import Any, Dict

import pycentral.audit_logs
import pycentral.base
import requests

from common import ingest
from common import status
from common import utils


# Environment variable constants.
ENV_ARUBA_CLIENT_ID = "ARUBA_CLIENT_ID"
ENV_ARUBA_CLIENT_SECRET_SECRET_PATH = "ARUBA_CLIENT_SECRET_SECRET_PATH"
ENV_ARUBA_USERNAME = "ARUBA_USERNAME"
ENV_ARUBA_PASSWORD_SECRET_PATH = "ARUBA_PASSWORD_SECRET_PATH"
ENV_ARUBA_BASE_URL = "ARUBA_BASE_URL"
ENV_ARUBA_CUSTOMER_ID = "ARUBA_CUSTOMER_ID"

# Log type to push data into the Chronicle.
CHRONICLE_DATA_TYPE = "ARUBA_CENTRAL"

# Date format to be used to parse the date string to the datetime object.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def get_and_ingest_audit_logs(central_info: Dict[str, Any]) -> None:
  """Fetch logs from Aruba Central platform and ingest it into Chronicle.

  Args:
    central_info (Dict[str, Any]): Parameter dictionary containing
      information related Aruba Central and API Gateway for HTTPS
      connection.

  Raises:
    Exception: When data could not pushed to Chronicle or Error from API
      while requesting audit trails.
  """
  # Create client object for ArubaCentralBase class.
  try:
    client = pycentral.base.ArubaCentralBase(central_info=central_info)
  # The SDK is logging the error message and exiting the function whenever an
  # error occurs in the Aruba Central API. Due to this, explicitly catch
  # SystemExit exception and throw HTTPError.
  except SystemExit as error:
    raise requests.HTTPError(
        f"Exception occurred while making API call.\n{error}") from error
  except Exception as error:
    raise requests.HTTPError(
        f"Exception occurred while creating ArubaCentralBase client.\n{error}"
    ) from error

  # Create object for Audit class.
  audit = pycentral.audit_logs.Audit()

  # Calculate start time based on POLL_INTERVAL.
  start_time = utils.get_last_run_at()
  print(f"Audit logs will be fetched from {start_time}.")

  # Calculate the epoch time (in seconds) for start time and end time,
  # end time will be 'now'.
  epoch_start_time = int(start_time.timestamp())
  epoch_end_time = int(
      (datetime.datetime.now(datetime.timezone.utc).timestamp()))

  # Initialize the number of page to 0 for the first API call.
  page_index = 0

  # Total logs collected from Aruba Central platform.
  total_logs = 0

  # API response contains remaining_record key to indicate if next page is
  # available or not. In the first iteration, it is set to True.
  remaining_records = True

  # Iterate through all the pages until logs are available and ingest data into
  # Chronicle.
  # Raise HTTPEror if response contains error code other than 200.
  while remaining_records:
    # Fetch audit trails from the Aruba Central platform.
    response = audit.get_traillogs(
        client,
        offset=page_index,
        start_time=epoch_start_time,
        end_time=epoch_end_time)

    # If status code is other than 200, raise HTTPError.
    if response.get("code") != status.STATUS_OK:
      raise requests.HTTPError(
          f"Exception occurred while making API call. {response.get('msg')}"
      )

    # Per page response from the API.
    per_page_response = response.get("msg", {})

    audit_logs = per_page_response.get("audit_logs", [])
    record_count = per_page_response.get("total", 0)
    remaining_records = per_page_response.get("remaining_records", False)

    print(f"{record_count} audit log(s) collected from Aruba Central platform.")

    # Ingest data into the Chronicle.
    if audit_logs:
      try:
        ingest.ingest(audit_logs, CHRONICLE_DATA_TYPE)
      except Exception as err:
        raise Exception(
            "Unable to push the data to the Chronicle. Please check the"
            " Chronicle configuration parameters."
        ) from err

    total_logs += record_count
    page_index += 1

  print(f"Total {total_logs} log(s) ingested successfully into the Chronicle.")


def main(request):  # pylint: disable=unused-argument
  """Entry point for the script.

  Args:
    request: Argument to run cloud function.

  Returns:
    string: "Ingestion completed." if function execution is successful.
  """
  # Fetch the environment variables.
  client_id = utils.get_env_var(ENV_ARUBA_CLIENT_ID)
  client_secret = utils.get_env_var(
      ENV_ARUBA_CLIENT_SECRET_SECRET_PATH, is_secret=True)
  customer_id = utils.get_env_var(ENV_ARUBA_CUSTOMER_ID)
  username = utils.get_env_var(ENV_ARUBA_USERNAME)
  password = utils.get_env_var(
      ENV_ARUBA_PASSWORD_SECRET_PATH, is_secret=True)
  base_url = utils.get_env_var(ENV_ARUBA_BASE_URL)

  # Create a dictionary of parameters required to pass for creating
  # object of ArubaCentralBase class.
  central_info = {
      "client_id": client_id,
      "client_secret": client_secret,
      "customer_id": customer_id,
      "username": username,
      "password": password,
      "base_url": base_url,
  }

  # Get audit logs from Aruba Central and ingest it into Chronicle.
  get_and_ingest_audit_logs(central_info)

  return "Ingestion completed."
