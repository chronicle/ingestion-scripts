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
"""Fetch audit logs from the Trend Micro Vision One and ingest into Chronicle."""

import requests

from common import ingest
from common import status
from common import utils

# The date format to be used for converting python datetime object to
# human-readable string.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "TREND_MICRO_VISION_AUDIT"

# Environment variable constants.
ENV_TREND_MICRO_AUTHENTICATION_TOKEN = "TREND_MICRO_AUTHENTICATION_TOKEN"
ENV_TREND_MICRO_DOMAIN = "TREND_MICRO_DOMAIN"


def get_and_ingest_audit_logs(authentication_token: str, domain: str) -> None:
  """Fetch audit logs from Trend Micro Vision One platform and ingest them into Chronicle.

  Args:
    authentication_token (str): Authentication token used to authenticate with
      the API.
    domain (str): Region where the service endpoint is located.

  Raises:
    RuntimeError: If any error occurred while fetching and ingesting audit logs.
  """

  # Calculate the start time based on the POLL_INTERVAL environment variable.
  start_time = utils.get_last_run_at().strftime(DATE_FORMAT)
  log_count = 0

  headers = {"Authorization": "Bearer " + authentication_token}

  url = f"https://{domain}/v3.0/audit/logs?startDateTime={start_time}&labels=all&top=200"
  print(f"Retrieving audit logs added after {start_time}.")

  # Get the audit logs from the Trend Micro Vision One until nextLink is present
  # in response.
  while True:
    response = requests.get(url, headers=headers)
    response_status = response.status_code

    # Retrieve the json response.
    try:
      json_response = response.json()
    except (ValueError, TypeError) as error:
      raise ValueError(
          "Unexpected data format received while collecting audit logs from"
          " Trend Micro Vision One."
      ) from error

    # If the response status code is other than 200, then raise the error.
    if response_status != status.STATUS_OK:
      error_message = json_response.get("message", json_response)
      raise RuntimeError(
          "Failed to get audit logs from Trend Micro Vision One with status"
          f" code {response_status}. Error message: {error_message}."
      )

    # Ingest Trend Micro Vision One audit logs to the Chronicle platform.
    audit_list = json_response.get("items", [])

    if audit_list:
      log_count += len(audit_list)
      try:
        ingest.ingest(audit_list, CHRONICLE_DATA_TYPE)
      except Exception as error:
        raise RuntimeError(
            "Unable to push Trend Micro Vision One audit logs into Chronicle:"
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
    print("No new audit logs found in the given time range.")


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

  # Get audit logs from Trend Micro Vision One and ingest it into Chronicle.
  get_and_ingest_audit_logs(authentication_token, domain)

  return "Ingestion completed."
