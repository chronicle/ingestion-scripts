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
# API endpoint: https://developer.sophos.com/docs/siem-v1/1/routes/events/get

"""Fetch audit logs from Sophos Central environment."""

import datetime
import requests

from common import ingest
from common import status
from common import utils

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "SOPHOS_CENTRAL"

# Sophos Auth URL.
ENV_SOPHOS_AUTH_URL = "SOPHOS_AUTH_URL"
ENV_SOPHOS_CLIENT_ID = "SOPHOS_CLIENT_ID"
ENV_SOPHOS_CLIENT_SECRET = "SOPHOS_CLIENT_SECRET"
ENV_SOPHOS_TENANT_ID = "SOPHOS_TENANT_ID"

ENV_SOPHOS_EVENTS_URL = "SOPHOS_EVENTS_URL"
ENV_SOPHOS_ALERTS_URL = "SOPHOS_ALERTS_URL"  


# Date format to be used in the API.
# The starting date from which alerts will be retrieved defined as Unix timestamp in UTC.Ignored if cursor is set. Must be within last 24 hours.

def get_and_ingest_audit_logs(token,sophos_url,tenant_id) -> None:
  """Fetch logs from Sophos Central API, process it and ingest into Chronicle.

  Raises:
    TypeError, ValueError: Error when response is not in json format.
  """
  # Calculating start_time based on the provided poll interval, it will be a
  # datetime object.
  start_time = utils.get_last_run_at()

  epoch_start_time = int(start_time.timestamp())

  print(f"Retrieving the Sophos Central logs since: {start_time}")
  print("Processing logs...")

  

  url = f"{sophos_url}?from_date={epoch_start_time}"

  print(f"Debug: {url}")
  headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenant_id
    }

  # Iterate through all the pages if pagination available and ingest data
  # into Chronicle.
  
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

  log_count = len(response.get("items", []))

  print(f"Retrieved {log_count} logs from the API call")


  data_list.extend(iter(response["items"]))
  print(f"Retrieved {len(data_list)} Sophos logs from the last"
        " API call.")

  # Ingest data into Chronicle.
  ingest.ingest(data_list, CHRONICLE_DATA_TYPE)
   

def get_jwt_token(auth_url, payload):
    response = requests.post(auth_url, data=payload)
    if response.status_code == 200:
        token_info = response.json()
        return token_info['access_token']
    else:
        print(f'Error obtaining JWT token: {response.status_code} - {response.text}')
        return None

def main(req) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    req: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """
  auth_url = utils.get_env_var(ENV_SOPHOS_AUTH_URL, is_secret=False)
  client_id = utils.get_env_var(ENV_SOPHOS_CLIENT_ID, is_secret=True)
  client_secret = utils.get_env_var(ENV_SOPHOS_CLIENT_SECRET, is_secret=True)
  tenant_id = utils.get_env_var(ENV_SOPHOS_TENANT_ID, is_secret=True)

  events_url = utils.get_env_var(ENV_SOPHOS_EVENTS_URL, is_secret=False)
  alerts_url = utils.get_env_var(ENV_SOPHOS_ALERTS_URL, is_secret=False)

  payload = {
    'grant_type': 'client_credentials',
    'client_id': client_id,
    'client_secret': client_secret,
    'scope': 'token'
  }

  jwt_token = get_jwt_token(auth_url,payload)
  
  if jwt_token:
    # Method to fetch logs and ingest to chronicle.
    print(f"URL: {events_url}")
    get_and_ingest_audit_logs(jwt_token,events_url,tenant_id)
    
    print(f"URL: {alerts_url}")
    get_and_ingest_audit_logs(jwt_token,alerts_url,tenant_id)
    

  return "Ingestion completed."
