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
"""Fetch data from MISP API."""

from typing import Optional

import requests

# copybara:strip_begin(imports)
from google3.third_party.chronicle.ingestion_scripts.common import env_constants
from google3.third_party.chronicle.ingestion_scripts.common import ingest
from google3.third_party.chronicle.ingestion_scripts.common import status
from google3.third_party.chronicle.ingestion_scripts.common import utils
# copybara:strip_end


# Environment variable constants.
ENV_API_KEY = "API_KEY"
ENV_TARGET_SERVER = "TARGET_SERVER"
ENV_ORG_NAME = "ORG_NAME"

# List of unwanted keys in event json.
KEYS_TO_REMOVE = [
    "Event",
    "Tag",
    "EventReport",
    "Object",
    "Galaxy",
    "RelatedEvent",
    "ShadowAttribute",
    "Orgc",
    "Org",
    "Feed",
]

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "MISP_IOC"


def get_and_ingest_events(api_key: str,
                          target_server: str,
                          start_time: str,
                          org_name: Optional[str] = None):
  """Get logs from 3p resources.

  Args:
    api_key(str): key for authentication.
    target_server(str): 3p resource ip address.
    start_time(str): add time interval in minutes.
    org_name(Optional[str]): organization name to filter data.
  """
  headers = {
      "Authorization": api_key,
      "Accept": "application/json",
      "Content-Type": "application/json",
  }

  params = {
      # Timestamp represents start time i.e.,
      # start_time minutes before current time.
      "timestamp": f"{start_time}m",
  }
  print(f"Retrieving event data from last {start_time}m.")

  # If organization name provided, update params.
  if org_name is not None:
    params["org_name"] = org_name

  data_list = []
  response_events = None
  try:
    url = f"https://{target_server}/events/restSearch"
    req = requests.post(url, json=params, headers=headers)

    response_events = req.json()

    if req.status_code != status.STATUS_OK:
      print(f"HTTP Error: {req.status_code}, Reason: {response_events}")

    req.raise_for_status()

    # Iterate through all the events and ingest data into Chronicle.
    for data in response_events.get("response", []):
      event_json = data.get("Event", {})

      # Remove unwanted key-value and append the
      # updated dictionary to data_list.
      updated_dict = {
          key: event_json.get(key)
          for key in event_json
          if key not in KEYS_TO_REMOVE
      }
      data_list.append(updated_dict)

    print(f"Retrieved {len(data_list)} MISP events from the last API call.")

    # Ingest the logs to the Chronicle.
    ingest.ingest(data_list, CHRONICLE_DATA_TYPE)

  except Exception as error:
    print(
        "ERROR: Unexpected error occured while fetching events from the MISP"
        " API."
    )
    raise error


def main(req):  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    req: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """

  api_key = utils.get_env_var(ENV_API_KEY, is_secret=True)
  target_server = utils.get_env_var(ENV_TARGET_SERVER)
  poll_interval = utils.get_env_var(
      env_constants.ENV_POLL_INTERVAL, required=False, default=5)
  org_name = utils.get_env_var(ENV_ORG_NAME)

  get_and_ingest_events(api_key, target_server, poll_interval, org_name)

  return "Ingestion completed."
