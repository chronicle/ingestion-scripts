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
"""Main file to ingest data into Chronicle."""

import base64
from collections.abc import Sequence
import json
import os
import sys
from typing import Any

import google.auth
from google.auth.transport import requests as Requests
from google.oauth2 import service_account

from common import env_constants
from common import utils


AUTHORIZATION_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
PROJECT_ID = utils.get_env_var(env_constants.ENV_CHRONICLE_PROJECT_NUMBER)
CUSTOMER_ID = utils.get_env_var(env_constants.ENV_CHRONICLE_CUSTOMER_ID)
REGION = utils.get_env_var(
    env_constants.ENV_CHRONICLE_REGION, required=False, default="us"
)

# Base URL for ingestion API.
INGESTION_API_BASE_URL = f"https://chronicle.{REGION}.rep.googleapis.com"

# Threshold value in bytes for ingesting the logs to the Chronicle.
# A payload of maximum 3.95MB will be sent at a time to Chronicle.
# Chronicle Ingestion API allows the maximum 4MB of payload, however, we
# have kept 0.05MB as a buffer.
SIZE_THRESHOLD_BYTES = 3_950_000

# Count of logs to check the batch size at once.
# We will check the payload size for 100 entries at once and
# ingest it into Chronicle if it exceeds more than 3.95MB.
LOG_BATCH_SIZE = 100


def initialize_http_session(
    scopes: Sequence[str] | None = None,
) -> Requests.AuthorizedSession:
  """Initializes an authenticated session with Google Chronicle.

  Args:
    scopes (Sequence[str] | None, optional): Required scopes. Defaults to
      None.

  Returns:
    Requests.AuthorizedSession: Authorized session object.

  Raises:
    RuntimeError: If service account is not found in the environment variable.
  """
  try:
    service_account_dict = utils.load_service_account(
        utils.get_env_var(
            env_constants.ENV_CHRONICLE_SERVICE_ACCOUNT, is_secret=True
        ),
        "Chronicle",
    )
    utils.cloud_logging(
        "Service account found in the environment variable. Using it for the"
        " authentication.",
        "INFO",
    )
    credentials = service_account.Credentials.from_service_account_info(
        service_account_dict,
        scopes=scopes or AUTHORIZATION_SCOPES,
    )
  except RuntimeError:
    utils.cloud_logging(
        "Service account not found in the environment variable. Using the"
        " default service account(ADC).",
        "INFO",
    )
    credentials, _ = google.auth.default(scopes=scopes or AUTHORIZATION_SCOPES)

  return Requests.AuthorizedSession(credentials)


def ingest(data: list[Any], log_type: str):
  """Prepare the chunk size of 3.95MB and send it to Chronicle.

  Args:
    data (list[Any]): Raw logs to send to Google Chronicle.
    log_type (str): Chronicle log type, for example: STIX
  """
  http_session = initialize_http_session()

  index = 0
  skipped_logs = 0

  namespace = os.getenv(env_constants.ENV_CHRONICLE_NAMESPACE)
  parent = f"projects/{PROJECT_ID}/locations/{REGION}/instances/{CUSTOMER_ID}/logTypes/{log_type}"

  # Parse the data in a format expected by Ingestion API of Chronicle.
  # The Ingestion API of Chronicle expects log payload in the format of
  # [{"data": encoded_log1, "environment_namespace": namespace},
  # {"data": encoded_log2, "environment_namespace": namespace}, ...]
  parsed_data = list(
      map(
          lambda i: {
              "data": (
                  base64.b64encode(json.dumps(i).encode("utf-8")).decode(
                      "utf-8"
                  )
              )
          }
          | ({"environment_namespace": namespace} if namespace else {}),
          data,
      )
  )
  # JSON payload to be sent to Chronicle.
  body = {"parent": parent, "inlineSource": {"logs": []}}

  # Loop over the list of events to send to Chronicle.
  while index < len(parsed_data):
    # Chronicle Ingestion API can receive a maximum of 4 MB of data in a
    # single execution. To be on a safer side, a chunk of size 3.95MB is
    # created, keeping 0.05MB as a buffer.

    # If size of 100 logs is greater than 3.95MB, we will loop over each log
    # separately. Else we will add 100 logs at a time and check if size is
    # less than 3.95MB or not.
    next_batch_of_logs = parsed_data[index : index + LOG_BATCH_SIZE]
    size_of_current_payload = sys.getsizeof(json.dumps(body))
    size_of_next_batch = sys.getsizeof(json.dumps(next_batch_of_logs))

    # The size of next 100 logs to add is greater than 3.95MB.
    if size_of_next_batch >= SIZE_THRESHOLD_BYTES:
      print(
          "Size of next 100 logs to ingest is greater than 3.95MB. Hence,"
          " looping over each log separately."
      )
      # Looping over each log separately.
      size_of_next_log = sys.getsizeof(json.dumps(parsed_data[index]))
      if size_of_current_payload + size_of_next_log <= SIZE_THRESHOLD_BYTES:
        body["inlineSource"]["logs"].append(parsed_data[index])
        index += 1
        continue

    # Adding the next 100 logs in the payload if the size of the payload is not
    # exceeding 3.95MB.
    elif size_of_current_payload + size_of_next_batch <= SIZE_THRESHOLD_BYTES:
      print("Adding a batch of 100 logs to the Ingestion API payload.")
      body["inlineSource"]["logs"].extend(next_batch_of_logs)
      index += LOG_BATCH_SIZE
      continue

    if body["inlineSource"]["logs"]:
      # A batch of logs is prepared for ingestion into the Chronicle.
      _send_logs_to_chronicle(
          http_session,
          body,
      )
      body["inlineSource"]["logs"].clear()
    else:
      print(
          "Current log size is greater than threshold limit. Hence, skipping"
          " ingestion for this log."
      )
      skipped_logs += 1
      index += 1  # because skipping current log

  # If the data received to ingest is below 3.95MB, the above while loop is
  # yet to send the data to Chronicle. Hence, sending the data now.
  if body["inlineSource"]["logs"]:
    _send_logs_to_chronicle(http_session, body)

  if skipped_logs:
    print(f"Total number of skipped logs: {skipped_logs}")


def _send_logs_to_chronicle(
    http_session: Requests.AuthorizedSession,
    body: dict[str, Any]
):
  """Sends unstructured log entries to the Chronicle backend for ingestion.

  Args:
    http_session (Requests.AuthorizedSession): Authorized session for HTTP
      requests.
    body (dict[str, list[Any]]): JSON payload to send to Chronicle Ingestion
      API.

  Raises:
    RuntimeError: Raises if any error occurred during log ingestion.
  """
  parent = body["parent"]
  url = INGESTION_API_BASE_URL + f"/v1beta/{parent}/logs:import"

  header = {"Content-Type": "application/json"}
  log_count = len(body.get("inlineSource", {}).get("logs", []))
  print(f"Attempting to push {log_count} log(s) to Chronicle.")

  # Calling the Chronicle Ingestion API.
  response = http_session.request("POST", url, json=body, headers=header)

  try:
    response.raise_for_status()
  except Exception as err:
    raise RuntimeError(
        "Error occurred while pushing logs to Chronicle. "
        f"Status code {response.status_code}. Reason: {response.json()}"
    ) from err
  else:
    # If the Ingestion API execution is successful, it will return an empty
    # dictionary.
    if not response.json():
      print(f"{log_count} log(s) pushed successfully to Chronicle.")
