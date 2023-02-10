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
"""Fetch audit logs from the Trend Micro Vision One and ingest into Chronicle."""

import requests

from common import ingest
from common import status
from common import utils

# The date format to be used for converting python datetime object to
# human-readable string.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Possible data types.
VALID_DATA_TYPES = ["audit_logs", "alerts"]

TREND_MICRO_AUDIT_LOGS_DATA_TYPE = "audit_logs"
TREND_MICRO_ALERTS_DATA_TYPE = "alerts"

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = {
    TREND_MICRO_AUDIT_LOGS_DATA_TYPE: "TREND_MICRO_VISION_AUDIT",
    TREND_MICRO_ALERTS_DATA_TYPE: "TREND_MICRO_VISION_ALERT"
}

# By default, the script will collect data of audit logs and alerts.
DEFAULT_TREND_MICRO_DATA_TYPE = (
    f"{TREND_MICRO_AUDIT_LOGS_DATA_TYPE}, {TREND_MICRO_ALERTS_DATA_TYPE}"
)

# Environment variable constants.
ENV_TREND_MICRO_AUTHENTICATION_TOKEN = "TREND_MICRO_AUTHENTICATION_TOKEN"
ENV_TREND_MICRO_DOMAIN = "TREND_MICRO_DOMAIN"
ENV_TREND_MICRO_DATA_TYPE = "TREND_MICRO_DATA_TYPE"


def get_and_ingest_vision_one_logs(
    authentication_token: str, domain: str, data_type: str
) -> None:
  """Fetch audit logs/alerts from Trend Micro Vision One platform and ingest them into Chronicle.

  Args:
    authentication_token (str): Authentication token used to authenticate with
      the API.
    domain (str): Region where the service endpoint is located.
    data_type (str): Type of data to fetch and ingest into Chronicle.

  Raises:
    RuntimeError: If any error occurred while fetching and ingesting audit
    logs/alerts.
  """

  # Calculate the start time based on the POLL_INTERVAL environment variable.
  start_time = utils.get_last_run_at().strftime(DATE_FORMAT)
  log_count = 0

  headers = {"Authorization": "Bearer " + authentication_token}

  # Set URL based on data types.
  if data_type == TREND_MICRO_AUDIT_LOGS_DATA_TYPE:  # URL for audit_logs.
    url = f"https://{domain}/v3.0/audit/logs?startDateTime={start_time}&labels=all&top=200"
  else:  # URL for alerts.
    url = f"https://{domain}/v3.0/workbench/alerts?startDateTime={start_time}"

  print(f"Retrieving {data_type} added after {start_time}.")

  # Get the audit logs/alerts from the Trend Micro Vision One until nextLink is
  # present in response.
  while True:
    response = requests.get(url, headers=headers)
    response_status = response.status_code

    # Retrieve the json response.
    try:
      json_response = response.json()
    except (ValueError, TypeError) as error:
      raise ValueError(
          f"Unexpected data format received while collecting {data_type} from"
          " Trend Micro Vision One."
      ) from error

    # If the response status code is other than 200, then raise the error.
    if response_status != status.STATUS_OK:
      error_message = json_response.get("message", json_response)
      raise RuntimeError(
          f"Failed to get {data_type} from Trend Micro Vision One with status"
          f" code {response_status}. Error message: {error_message}."
      )

    # Ingest Trend Micro Vision One audit logs/alerts to the Chronicle platform.
    data_list = json_response.get("items", [])

    if data_list:
      log_count += len(data_list)
      try:
        ingest.ingest(data_list, CHRONICLE_DATA_TYPE.get(data_type))
      except Exception as error:
        raise RuntimeError(
            f"Unable to push Trend Micro Vision One {data_type} into Chronicle:"
            f" {error}."
        ) from error

    # Update the URL for the next page, if the nextLink is present.
    if json_response.get("nextLink"):
      url = json_response["nextLink"]
    else:
      break

  if log_count:
    print(f"Successfully ingested {log_count} log(s) into Chronicle.")
  else:
    print(f"No new {data_type} found in the given time range.")


# Request is a user input dictionary passed while running the cloud function.
# The script does not use these parameters.
def main(request) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    request: Request to execute the cloud function.
  Returns:
    str: "Ingestion completed".
  """
  # Fetch the environment variables.
  authentication_token = utils.get_env_var(
      ENV_TREND_MICRO_AUTHENTICATION_TOKEN, is_secret=True)
  domain = utils.get_env_var(ENV_TREND_MICRO_DOMAIN)
  trend_micro_data_type = utils.get_env_var(
      ENV_TREND_MICRO_DATA_TYPE,
      required=False,
      default=DEFAULT_TREND_MICRO_DATA_TYPE,
  )

  # Create a list of data type from CSV string.
  data_type = [
      data.lower().strip() for data in trend_micro_data_type.strip().split(",")
  ]

  # Get audit logs from Trend Micro Vision One and ingest it into Chronicle.
  if TREND_MICRO_AUDIT_LOGS_DATA_TYPE in data_type:
    get_and_ingest_vision_one_logs(
        authentication_token, domain, TREND_MICRO_AUDIT_LOGS_DATA_TYPE
    )

  # Get alerts from Trend Micro Vision One and ingest it into Chronicle.
  if TREND_MICRO_ALERTS_DATA_TYPE in data_type:
    get_and_ingest_vision_one_logs(
        authentication_token, domain, TREND_MICRO_ALERTS_DATA_TYPE
    )

  return "Ingestion completed."
