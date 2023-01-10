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
"""Fetch logs from DUO."""

import datetime
import json

import duo_client

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "DUO_ADMIN"

# Environment variables constants.
ENV_DUO_API_DETAILS = "DUO_API_DETAILS"

# Default initialization of environment variable.
DUO_API_IKEY = None
DUO_API_SKEY = None
DUO_API_HOSTNAME = None
POLL_INTERVAL = None

# Response consists of maximum 1000 log entries.
PAGE_SIZE = 1000

# Date format for the API.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def get_last_timestamp(duo_logs) -> int:
  """Get the last timestamp to retrieve the next set of Duo Admin logs.

  Args:
    duo_logs (list): List of Duo Admin logs.

  Returns:
    max_timestamp (int): Latest timestamp retrieved from the Duo Admin logs.
  """
  max_timestamp = 0
  for log in duo_logs:
    max_timestamp = max(max_timestamp, int(log["timestamp"]))

  return max_timestamp


def get_and_ingest_logs():
  """Fetch logs from Duo client and ingest into Chronicle."""
  # Calculating start time based on POLL_INTERVAL.
  start_time = utils.get_last_run_at()

  # Creating a human readable format of the start_time to print in the
  # logs for debugging purposes.
  start_time_str = start_time.strftime(DATE_FORMAT)

  # The API requires the time in the epoch. So, calculating total
  # seconds from the January 1970 and converting it into seconds.
  start_time = int((start_time - datetime.datetime(
      1970, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds())

  print(
      f"Retrieving the last {POLL_INTERVAL} mins of logs since {start_time_str}"
  )

  log_count = PAGE_SIZE

  # Creating session with Duo client.
  admin_api = duo_client.Admin(
      ikey=DUO_API_IKEY, skey=DUO_API_SKEY, host=DUO_API_HOSTNAME)

  # Iterate through all the pages if pagination available and ingest data into
  # Chronicle.
  # If log_count is less than 1000, no need to check for next entries.
  while log_count == PAGE_SIZE:
    data_list = []

    # Getting data from Duo platform.
    logs = admin_api.get_administrator_log(mintime=start_time)
    log_count = len(logs)

    # No need to ingest logs for empty response.
    if log_count == 0:
      break

    data_list.extend(iter(logs))
    print(f"Retrieved {log_count} Duo admin logs from the last API call.")

    # Fetching the maximum timestamp from the collected logs for the next API
    # call.
    if log_count == PAGE_SIZE:
      start_time = get_last_timestamp(logs) + 1
      # Human readable format of the start time.
      start_time_str = (datetime.datetime.fromtimestamp(
          start_time, tz=datetime.timezone.utc)).strftime(DATE_FORMAT)

      print(f"Next page records to be collected from {start_time_str}.")

    # Ingest data into the Chronicle.
    ingest.ingest(data_list, CHRONICLE_DATA_TYPE)


def main(req) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    req: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """
  global DUO_API_IKEY
  global DUO_API_SKEY
  global DUO_API_HOSTNAME
  global POLL_INTERVAL

  # Interval should match what you have configured in Cloud Scheduler.
  POLL_INTERVAL = utils.get_env_var(
      env_constants.ENV_POLL_INTERVAL, required=False, default=10)

  # Duo Admin API integration key.
  DUO_API_IKEY = json.loads(
      utils.get_env_var(ENV_DUO_API_DETAILS, is_secret=True))["ikey"]

  # Duo Admin API secret key.
  DUO_API_SKEY = json.loads(
      utils.get_env_var(ENV_DUO_API_DETAILS, is_secret=True))["skey"]

  # Duo Admin API hostname.
  DUO_API_HOSTNAME = json.loads(
      utils.get_env_var(ENV_DUO_API_DETAILS, is_secret=True))["api_host"]

  # Fetch and ingest Duo admin logs into Chronicle.
  get_and_ingest_logs()

  return "Ingestion completed."
