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
    env_constants.ENV_CHRONICLE_REGION, required=False, default="us")
SERVICE_ACCOUNT = utils.get_env_var(
    env_constants.ENV_CHRONICLE_SERVICE_ACCOUNT, is_secret=True)

# Base URL for ingestion API.
INGESTION_API_BASE_URL = "malachiteingestion-pa.googleapis.com"

# Threshold value in bytes for ingesting the logs to the Chronicle.
# A payload of maximum 0.95MB will be sent at a time to Chronicle.
# Chronicle Ingestion API allows the maximum 1MB of payload, however, we
# have kept 0.5MB as a buffer.
SIZE_THRESHOLD_BYTES = 950000

try:
  SERVICE_ACCOUNT_DICT = json.loads(SERVICE_ACCOUNT)
except json.JSONDecodeError as error:
  raise RuntimeError("Invalid Service Account JSON provided.") from error


def initialize_http_session(
    service_account_json: dict[Any, Any],
    scopes: Optional[Sequence[str]] = None,
) -> Requests.AuthorizedSession:
  """Initializes an authenticated session with Google Chronicle.

  Args:
    service_account_json (dict): Service Account JSON.
    scopes (Optional[Sequence[str]], optional): Required scopes.
      Defaults to None.

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
      SERVICE_ACCOUNT_DICT, scopes=AUTHORIZATION_SCOPES)

  index = 0
  namespace = os.getenv(env_constants.ENV_CHRONICLE_NAMESPACE)

  # JSON payload to be sent to Chronicle.
  body = {
      "customerId": CUSTOMER_ID,
      "logType": log_type,
      "entries": [],
  }
  if namespace:
    body["namespace"] = namespace

  # Loop over the list of events to send to Chronicle.
  while index < len(data):
    # Chronicle Ingestion API can receive a maximum of 1 MB of data in a
    # single execution. To be on a safer side, a chunk of size 0.95MB is
    # created, keeping 0.5MB as a buffer.
    if sys.getsizeof(json.dumps(data[index])) + sys.getsizeof(
        json.dumps(body)) <= SIZE_THRESHOLD_BYTES:
      temp_result = json.dumps(data[index]).encode("utf-8")
      temp_result = str(temp_result, "utf-8")
      body["entries"].append({"logText": temp_result})
      index += 1
    # A chunk of size 0.95MB is prepared. Hence sending data to Chronicle.
    else:
      _send_logs_to_chronicle(
          http_session,
          body,
          REGION,
      )
      body["entries"].clear()
  # If the data received to ingest is below 0.95MB, the above while loop is
  # yet to send the data to Chronicle. Hence, sending the data now.
  if body["entries"]:
    _send_logs_to_chronicle(
        http_session,
        body,
        REGION
    )


def _send_logs_to_chronicle(
    http_session: Requests.AuthorizedSession,
    body: Dict[str, List[Any]],
    region: str
):
  """Sends unstructured log entries to the Chronicle backend for ingestion.

  Args:
    http_session (Requests.AuthorizedSession): Authorized session for HTTP
      requests.
    body (Dict[str, List[Any]]): JSON payload to send to Chronicle
      Ingestion API.
    region (str): Region of Ingestion API.

  Raises:
    RuntimeError: Raises if any error occured during log ingestion.
  """
  if region.lower() != "us":
    url = ("https://" + region.lower() + "-" + INGESTION_API_BASE_URL +
           "/v2/unstructuredlogentries:batchCreate")
  else:
    url = ("https://" + INGESTION_API_BASE_URL +
           "/v2/unstructuredlogentries:batchCreate")

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
        f"Error occurred while pushing logs to Chronicle. "
        f"Status code {response.status_code}. Reason: {response.json()}"
    ) from err
