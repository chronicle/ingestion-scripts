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
"""fetch logs from MISP."""

import requests

from chronicle import ingest
from chronicle.utils import get_env_var


def get_logs_from_misp(
    api_key: str, target_server: str, pool_interval: str, org_name: str = None
):
    """Get logs from 3p resources.

    Args:
        api_key(str): key for authentication.
        target_server(str): 3p resource ip address.
        pool_interval(str): add time interval in minutes.
        org_name(str): organization name to filter data.
    Returns:
        list of required data for ingestion.
    """
    headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    params = {
        # timestamp represents start time i.e.,
        # pool_interval minutes before current time.
        "timestamp": f"{pool_interval}m",
    }
    print(f"Retrieving event data from last {pool_interval}m")

    # If organisation name provided, update params.
    if org_name is not None:
        params["org_name"] = org_name

    # list of unwanted keys in event json
    key_to_remove = [
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

    data_list = []
    try:
        url = f"https://{target_server}/events/restSearch"
        req = requests.post(url, json=params, headers=headers, verify=False)
        req.raise_for_status()
        response_events = req.json()

        # Iterate through response and locate events
        for data in response_events["response"]:
            event_json = data["Event"]

            # remove unwanted key-value and append the
            # updated dictionary to data_list
            updated_dict = {
                key: event_json[key] for key in event_json if key not in key_to_remove
            }
            data_list.append(updated_dict)

    except Exception as e:
        print("ERROR: Unexpected error occured while fetching events from API.")
        raise e

    print(f"Retrieved {len(data_list)} event data from the API call")

    # return list od event data list.
    return data_list


def main(req):
    """Entrypoint."""

    API_KEY = get_env_var("API_KEY", is_secret=True)
    TARGET_SERVER = get_env_var("TARGET_SERVER")
    POOL_INTERVAL = get_env_var("POLL_INTERVAL")
    ORG_NAME = get_env_var("ORG_NAME")

    data_list = get_logs_from_misp(API_KEY, TARGET_SERVER, POOL_INTERVAL, ORG_NAME)
    ingest(data_list, "MISP_IOC")
