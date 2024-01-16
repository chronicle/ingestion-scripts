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
"""Main file to ingest data into Chronicle."""

import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from google.auth.transport import requests as Requests
from google.oauth2 import service_account

from common import env_constants
from common import utils

AUTHORIZATION_SCOPES = ["https://www.googleapis.com/auth/malachite-ingestion"]
CUSTOMER_ID = utils.get_env_var(env_constants.ENV_CHRONICLE_CUSTOMER_ID)
REGION = utils.get_env_var(
    env_constants.ENV_CHRONICLE_REGION, required=False, default="us"
)
SERVICE_ACCOUNT = utils.get_env_var(
    env_constants.ENV_CHRONICLE_SERVICE_ACCOUNT, is_secret=True
)

# Base URL for ingestion API.
INGESTION_API_BASE_URL = "malachiteingestion-pa.googleapis.com"

# Base URL for Reference list API
REFERENCE_LIST_API_BASE_URL = "backstory.googleapis.com"

# Threshold value in bytes for ingesting the logs to the Chronicle.
# A payload of maximum 0.95MB will be sent at a time to Chronicle.
# Chronicle Ingestion API allows the maximum 1MB of payload, however, we
# have kept 0.5MB as a buffer.
SIZE_THRESHOLD_BYTES = 950000

# Count of logs to check the batch size at once.
# We will check the payload size for 100 entries at once and
# ingest it into Chronicle if it exceeds more than 0.95MB.
LOG_BATCH_SIZE = 100

SERVICE_ACCOUNT_DICT = utils.load_service_account(SERVICE_ACCOUNT, "Chronicle")


def initialize_http_session(
    service_account_json: Dict[Any, Any],
    scopes: Optional[Sequence[str]] = None,
) -> Requests.AuthorizedSession:
  """Initializes an authenticated session with Google Chronicle.

  Args:
    service_account_json (dict): Service Account JSON.
    scopes (Optional[Sequence[str]], optional): Required scopes. Defaults to
      None.

  Returns:
    Requests.AuthorizedSession: Authorized session object.
  """
  credentials = service_account.Credentials.from_service_account_info(
      service_account_json,
      scopes=scopes or AUTHORIZATION_SCOPES,
  )
  return Requests.AuthorizedSession(credentials)


def ingest(data: list[Any], log_type: str):
  """Prepare the chunk size of 0.95MB and send it to Chronicle.

  Args:
    data (list[Any]): Raw logs to send to Google Chronicle.
    log_type (str): Chronicle log type, for example: STIX
  """
  http_session = initialize_http_session(
      SERVICE_ACCOUNT_DICT, scopes=AUTHORIZATION_SCOPES
  )

  index = 0
  namespace = os.getenv(env_constants.ENV_CHRONICLE_NAMESPACE)

  # Parse the data in a format expected by Ingestion API of Chronicle.
  # The Ingestion API of Chronicle expects log payload in the format of
  # [{"logText": str(log1)}, {"logText": str(log2)}, ...]
  parsed_data = list(
      map(
          lambda i: {"logText": str(json.dumps(i).encode("utf-8"), "utf-8")},
          data,
      )
  )
  # JSON payload to be sent to Chronicle.
  body = {
      "customerId": CUSTOMER_ID,
      "logType": log_type,
      "entries": [],
  }
  if namespace:
    body["namespace"] = namespace

  # Loop over the list of events to send to Chronicle.
  while index < len(parsed_data):
    # Chronicle Ingestion API can receive a maximum of 1 MB of data in a
    # single execution. To be on a safer side, a chunk of size 0.95MB is
    # created, keeping 0.5MB as a buffer.

    # If size of 100 logs is greater than 0.95MB, we will loop over each log
    # separately. Else we will add 100 logs at a time and check if size is
    # less than 0.95MB or not.
    next_batch_of_logs = parsed_data[index : index + LOG_BATCH_SIZE]
    size_of_current_payload = sys.getsizeof(json.dumps(body))
    size_of_next_batch = sys.getsizeof(json.dumps(next_batch_of_logs))

    # The size of next 100 logs to add is greater than 0.95MB.
    if size_of_next_batch >= SIZE_THRESHOLD_BYTES:
      print(
          "Size of next 100 logs to ingest is greater than 0.95MB. Hence,"
          " looping over each log separately."
      )
      # Looping over each log separately.
      size_of_next_log = sys.getsizeof(json.dumps(parsed_data[index]))
      if size_of_current_payload + size_of_next_log <= SIZE_THRESHOLD_BYTES:
        body["entries"].append(parsed_data[index])
        index += 1
        continue

    # Adding the next 100 logs in the payload if the size of the payload is not
    # exceeding 0.95MB.
    elif size_of_current_payload + size_of_next_batch <= SIZE_THRESHOLD_BYTES:
      print("Adding a batch of 100 logs to the Ingestion API payload.")
      body["entries"].extend(next_batch_of_logs)
      index += LOG_BATCH_SIZE
      continue

    # A batch of logs is prepared for ingestion into the Chronicle.
    _send_logs_to_chronicle(
        http_session,
        body,
        REGION,
    )
    body["entries"].clear()

  # If the data received to ingest is below 0.95MB, the above while loop is
  # yet to send the data to Chronicle. Hence, sending the data now.
  if body["entries"]:
    _send_logs_to_chronicle(http_session, body, REGION)


def _send_logs_to_chronicle(
    http_session: Requests.AuthorizedSession,
    body: Dict[str, List[Any]],
    region: str,
):
  """Sends unstructured log entries to the Chronicle backend for ingestion.

  Args:
    http_session (Requests.AuthorizedSession): Authorized session for HTTP
      requests.
    body (Dict[str, List[Any]]): JSON payload to send to Chronicle Ingestion
      API.
    region (str): Region of Ingestion API.

  Raises:
    RuntimeError: Raises if any error occured during log ingestion.
  """
  if region.lower() != "us":
    url = (
        "https://"
        + region.lower()
        + "-"
        + INGESTION_API_BASE_URL
        + "/v2/unstructuredlogentries:batchCreate"
    )
  else:
    url = (
        "https://"
        + INGESTION_API_BASE_URL
        + "/v2/unstructuredlogentries:batchCreate"
    )

  header = {"Content-Type": "application/json"}
  log_count = len(body["entries"])
  print(f"Attempting to push {log_count} log(s) to Chronicle.")

  # Calling the Chronicle Ingestion API.
  # Reference - https://github.com/chronicle/api-samples-python/blob/master/
  #   ingestion/create_unstructured_log_entries.py
  response = http_session.request("POST", url, json=body, headers=header)

  try:
    response.raise_for_status()
    # If the Ingestion API execution is successful, it will return an empty
    # dictionary.
    if not response.json():
      print(f"{log_count} log(s) pushed successfully to Chronicle.")
  except Exception as err:
    raise RuntimeError(
        "Error occurred while pushing logs to Chronicle. "
        f"Status code {response.status_code}. Reason: {response.json()}"
    ) from err


def get_reference_list(list_name: str) -> List[str] | None:
  """Get the reference list data from Chronicle.

  Args:
      list_name (str): reference list name in chronicle

  Raises:
      Exception: Raise error when list is not accessible

  Returns:
      list(str): The contents of the list
  """
  print(f"Fetching Reference list data for {list_name}.")
  http_session = initialize_http_session(
      SERVICE_ACCOUNT_DICT,
      scopes=["https://www.googleapis.com/auth/chronicle-backstory"],
  )
  if REGION.lower() != "us":
    url = (
        "https://"
        + REGION.lower()
        + "-"
        + REFERENCE_LIST_API_BASE_URL
        + f"/v2/lists/{list_name}"
    )
  else:
    url = "https://" + REFERENCE_LIST_API_BASE_URL + f"/v2/lists/{list_name}"
  header = {"Content-Type": "application/json"}
  response = http_session.request("GET", url, headers=header)
  try:
    response.raise_for_status()
    # If the Reference list API is successful, it will return a dictionary
    if response:
      list_content = response.json()["lines"]
      stripped_list_content = [s.strip() for s in list_content]
      stripped_list_content = [item for item in stripped_list_content if item]
      return stripped_list_content
  except Exception as err:
    raise err
