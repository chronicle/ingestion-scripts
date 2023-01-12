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
"""Fetch audit logs from Slack environment."""

import datetime
import requests

from common import ingest
from common import status
from common import utils

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "SLACK_AUDIT"

# Slack logs API endpoint URL.
SLACK_LOGS_URL = "https://api.slack.com/audit/v1/logs"

# Environment variable constants.
ENV_SLACK_ADMIN_TOKEN = "SLACK_ADMIN_TOKEN"

# Default initialization of variable.
SLACK_ADMIN_TOKEN = None

# Date format to be used in the API.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def get_and_ingest_audit_logs() -> None:
  """Fetch audit logs from Slack API, process it and ingest into Chronicle.

  Raises:
    TypeError, ValueError: Error when response is not in json format.
  """
  # Calculating start_time based on the provided poll interval, it will be a
  # datetime object.
  start_time = utils.get_last_run_at()

  # Creating a human readable format of the start_time to print in the
  # logs for debugging purposes.
  start_time_str = start_time.strftime(DATE_FORMAT)

  # The API requires the time in the epoch. So, calculating total
  # seconds from the January 1970 and converting it into seconds.
  start_time = int((start_time - datetime.datetime(
      1970, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds())

  print(f"Retrieving the Slack audit logs since: {start_time_str}")
  print("Processing logs...")

  url = f"{SLACK_LOGS_URL}?oldest={start_time}"
  headers = {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "Authorization": f"Bearer {SLACK_ADMIN_TOKEN}",
  }

  # Iterate through all the pages if pagination available and ingest data
  # into Chronicle.
  while True:
    data_list = []

    print(f"Processing set of results with start time: {start_time}")

    resp = requests.get(url=url, headers=headers)

    try:
      response = resp.json()
    except (TypeError, ValueError) as error:
      print(
          "ERROR: Unexpected data format received while collecting audit logs")
      raise error

    if resp.status_code != status.STATUS_OK:
      print(f"HTTP Error: {resp.status_code}, Reason: {response}")

    resp.raise_for_status()

    log_count = len(response.get("entries", []))

    print(f"Retrieved {log_count} audit logs from the API call")

    # No need to ingest logs for empty response.
    if log_count == 0:
      break

    data_list.extend(iter(response["entries"]))
    print(f"Retrieved {len(data_list)} Slack audit logs from the last"
          " API call.")

    # Ingest data into Chronicle.
    ingest.ingest(data_list, CHRONICLE_DATA_TYPE)

    next_cursor = response["response_metadata"]["next_cursor"]
    # Update the url if next cursor is available.
    if next_cursor:
      url = f"{SLACK_LOGS_URL}?oldest={start_time}&cursor={next_cursor}"
      print(
          f"More records expected.. (processed {log_count} records)")
    else:
      print("Logs processed successfully.")
      break


def main(req) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    req: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """
  global SLACK_ADMIN_TOKEN

  # Slack admin token.
  SLACK_ADMIN_TOKEN = utils.get_env_var(
      ENV_SLACK_ADMIN_TOKEN, is_secret=True)

  # Method to fetch audit logs and ingest to chronicle.
  get_and_ingest_audit_logs()

  return "Ingestion completed."
