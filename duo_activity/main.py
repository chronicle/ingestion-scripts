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
"""Fetch logs from the Duo Security API and ingest it to Chronicle."""

import base64
import datetime
import email.utils
import hashlib
import hmac
import logging
from typing import Any, Dict, List
import urllib.parse

import requests

from common import env_constants  # pylint: disable=unused-import
from common import ingest
from common import utils

# Configure logging
logging.basicConfig(level=logging.INFO)

ENV_BACKSTORY_API_V1_URL = "BACKSTORY_API_V1_URL"
ENV_SCOPES = "SCOPES"
ENV_SERVICE_ACCOUNT_FILE = "SERVICE_ACCOUNT_FILE"
ENV_CHECKPOINT_FILE_PATH = "CHECKPOINT_FILE_PATH"
ENV_LOG_FETCH_DURATION = "LOG_FETCH_DURATION"
ENV_DUO_SECRET_KEY = "DUO_SECRET_KEY"
ENV_DUO_INTEGRATION_KEY = "DUO_INTEGRATION_KEY"
ENV_CHRONICLE_CUSTOMER_ID = "CHRONICLE_CUSTOMER_ID"


# Define the scope
SCOPES = utils.get_env_var(
    ENV_SCOPES, default="https://www.googleapis.com/auth/chronicle-backstory"
).split(",")


def sign(
    method: str,
    host: str,
    path: str,
    params: Dict[str, str],
    skey: str,
    ikey: str,
) -> Dict[str, str]:
  """Generate the authorization headers for the request.

  Args:
      method (str): HTTP method (e.g., "GET").
      host (str): Hostname of the API endpoint.
      path (str): Path of the API endpoint.
      params (dict): Query parameters.
      skey (str): Secret key.
      ikey (str): Integration key.

  Returns:
      dict: Headers including the Date and Authorization fields.
  """

  skey = str(skey)
  ikey = str(ikey)
  if not isinstance(method, str):
    raise TypeError("Method must be a string.")
  if not isinstance(host, str):
    raise TypeError("Host must be a string.")
  now = email.utils.formatdate()
  canon = [now, method.upper(), host.lower(), path]
  args = []
  if params is None or not isinstance(params, dict):
    raise ValueError("Params must be a non-null dictionary")

  for key in sorted(params.keys()):
    val = params[key].encode("utf-8")
    args.append(
        f'{urllib.parse.quote(key, "")}='
        f'{urllib.parse.quote(val.decode("utf-8"), "")}'
    )
  canon.append("&".join(args))
  canon = "\n".join(canon)
  sig = hmac.new(
      bytes(skey, encoding="utf-8"),
      bytes(canon, encoding="utf-8"),
      hashlib.sha1,
  )
  auth = f"{ikey}:{sig.hexdigest()}"
  return {
      "Date": now,
      "Authorization": (
          f'Basic {base64.b64encode(bytes(auth, encoding="utf-8")).decode()}'
      ),
  }


def write_checkpoint(timestamp: int) -> None:
  """Write the latest processed timestamp to the checkpoint file.

  Args:
      timestamp (int): Latest processed timestamp in milliseconds since epoch.
  """
  if timestamp < 0:
    raise ValueError("Timestamp cannot be negative.")

  checkpoint_file = utils.get_env_var(
      ENV_CHECKPOINT_FILE_PATH, default="checkpoint.json"
  )
  with open(checkpoint_file, "w") as file:
    file.write(str(timestamp))


def fetch_logs_and_ingest(file_path="output.json") -> None:  # pylint: disable=unused-argument
  """Fetch logs from the Duo Security API and ingest them directly into Chronicle.
  """
  url = utils.get_env_var(
      ENV_BACKSTORY_API_V1_URL,
      default="https://api-a0bd0de3.duosecurity.com/admin/v2/logs/activity",
  )

  log_fetch_duration = utils.get_env_var(ENV_LOG_FETCH_DURATION, default="1")
  log_fetch_duration = int(log_fetch_duration)

  today = datetime.datetime.now(tz=datetime.timezone.utc)

  # Calculate the start and end times based on log_fetch_duration
  if log_fetch_duration == 1:
    start_of_period = today - datetime.timedelta(days=1)
  else:
    start_of_period = today - datetime.timedelta(days=log_fetch_duration)

  # Create start and end timestamps for the period
  start_of_period = datetime.datetime(
      start_of_period.year,
      start_of_period.month,
      start_of_period.day,
      0, 0, 0,
      tzinfo=datetime.timezone.utc,
  )

  end_of_period = datetime.datetime(
      today.year,
      today.month,
      today.day,
      0, 0, 0,
      tzinfo=datetime.timezone.utc,
  )

  if log_fetch_duration > 1:
    end_of_period -= datetime.timedelta(seconds=1)

  start_epoch = int(start_of_period.timestamp()*1000)
  end_epoch = int(end_of_period.timestamp()*1000)

  params = {"mintime": str(start_epoch), "maxtime": str(end_epoch)}

  headers = sign(
      method="GET",
      host="api-a0bd0de3.duosecurity.com",
      path="/admin/v2/logs/activity",
      params=params,
      skey=utils.get_env_var("DUO_SECRET_KEY", is_secret=True,),
      ikey=utils.get_env_var("DUO_INTEGRATION_KEY", is_secret=True,)
  )

  response = None
  try:
    response = requests.get(
        url, headers=headers, params=params, stream=True
    )
    # Check if response is valid
    if isinstance(response, str):
      logging.error("Expected a response object, got a string instead.")
      return

    response.raise_for_status()  # Raise an exception for HTTP errors
    logs = response.json()
    if not isinstance(logs, dict):
      logging.info("Received logs is not a dictionary.")
      print("Received logs is not a dictionary.")
      return
    logging.info("Fetched logs: %s", logs)
    # Specify the file path
    data_json = []
    for item in logs["response"]["items"]:
      # Append each item to the extracted_items list
      data_json.append(item)

    merged_dict = {}
    # Loop through each item in the list and update the merged_dict
    for item in data_json:
      merged_dict.update(item)

    # Ingest the logs directly into Chronicle
    if isinstance(merged_dict, dict):
      ingest_to_chronicle(data_json)
    else:
      logging.info("Received logs is not a dictionary.")

    # Update checkpoint with the latest timestamp
    write_checkpoint(int(end_epoch))
  except requests.RequestException as e:
    logging.info("Failed to retrieve activity logs. Error: %s", e)
    logging.info(
        "Response content: %s",
        response.text if response else "No response received",
    )


def ingest_to_chronicle(logs: List[Dict[str, Any]]) -> str:
  """Ingest logs directly into Google Chronicle.

  Args:
      logs (Dict[str, any]): The logs to ingest.

  Returns:
      str: Status of ingestion.
  """
  if not logs:
    logging.info("No logs provided for ingestion.")
    return "No logs to ingest."
  if not isinstance(logs, list):
    raise TypeError("Logs must be a list of dictionaries.")
  for log in logs:
    if not isinstance(log, dict):
      raise TypeError("Each log must be a dictionary.")
  try:

    # Ingest logs
    ingest.ingest(logs, "DUO_ACTIVITY")
    logging.info("Successfully ingested logs into Chronicle.")
    return "Logs successfully ingested into Chronicle."

  except Exception as e:  # pylint: disable=broad-except
    logging.info("Failed to ingest logs into Chronicle. Error: %s", e)
    return "Failed to ingest logs into Chronicle. Error: %s" % e


def main(request=None) -> str:  # pylint: disable=unused-argument
  try:
    fetch_logs_and_ingest("output.json")
    return "Scheduled ingestion completed successfully.\n"
  except Exception as e:  # pylint: disable=broad-except
    logging.info("Unexpected error occurred. Error: %s", e)
    return "Ingestion not completed due to unexpected error.\n"
