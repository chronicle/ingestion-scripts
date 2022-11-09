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
from datetime import datetime, timedelta, timezone

from chronicle import ingest
from chronicle.auth import OAuthClientCredentialsAuth
import requests

from chronicle.utils import get_env_var

# Fetch audit logs from citrix API and ingest

def create_new_session(url_domain, cust_id):
    client_id = get_env_var("CITRIX_CLIENT_ID")
    client_secret = get_env_var("CITRIX_CLIENT_SECRET", is_secret=True)

    session = OAuthClientCredentialsAuth(
        f"https://{url_domain}/cctrustoauth2/{cust_id}/tokens/clients",
        client_id,
        client_secret,
    ).session

    return session

def get_access_token(session):
    try:
        access_token = session.headers["Authorization"].split()[1]
    except (KeyError, IndexError) as e:
        print("Unable to fetch access token from the session")
        raise e

    return access_token

def get_audit_logs(session):

    global CUSTOMER_ID, CHRONICLE_FUNCTION_INTERVAL
    global CHRONICLE_DATA_TYPE, URL_DOMAIN

    # get access token from session header
    access_token = get_access_token(session)

    # Calc start time, end time will be 'now'
    start_date_time = str(datetime.now(timezone.utc) - timedelta(
        minutes=int(CHRONICLE_FUNCTION_INTERVAL)
    )).replace(" ", "T")[:-9] + "Z"

    end_date_time = str(datetime.now(timezone.utc)).replace(" ", "T")[:-9] + "Z"

    print(f"Retrieving audit logs from {start_date_time} to {end_date_time}")

    headers_json = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Citrix-CustomerId": CUSTOMER_ID,
        # changing the prefix as citrix need a specific prefix
        "Authorization": f"CwsAuth Bearer= \
            {access_token}",
    }

    url = f"https://{URL_DOMAIN}/systemlog/records"

    params_json = {
        "startDateTime": start_date_time,
        "endDateTime": end_date_time,
        "limit": "200",
    }

    new_session_count = 0

    # Iterate through all the pages if pagination
    # available and add data to data_list
    while True:
        response = requests.get(
            url,
            headers=headers_json,
            params=params_json,
        )

        try:
            resp_json = response.json()
        except (ValueError, TypeError) as e:
            print(
                "ERROR: Unexpected data format received while collecting \
                 audit logs"
            )
            raise e

        if response.status_code == 200:
            # If creating new session creation resolves the 401 error
            new_session_count = 0
        elif response.status_code == 401:

            # Checking if session creation retries == max retries
            if new_session_count == 3:
                print("Unable to fetch the access token for data collection. Exiting...")
            else:
                new_session_count = new_session_count + 1
                print("Previous session expired. Creating new session...")
                session = create_new_session(URL_DOMAIN, CUSTOMER_ID)

                # Getting new access token from the session
                access_token = get_access_token(session)
                headers_json["Authorization"] = f"CwsAuth Bearer={access_token}"

                print("Created new session. Resuming data collection")
                continue
        else:
            print("HTTP Error: {}, Reason: {}".format(response.status_code, resp_json))
        
        response.raise_for_status()

        data_list = list(resp_json["items"])
        print(f"Retrieved {len(data_list)} audit logs from the API call")

        if data_list:
            # Ingest data
            ingest(data_list, CHRONICLE_DATA_TYPE)

        # Break the loop if next token unavailable
        if resp_json.get("continuationToken") is None:
            print("Data collection completed")
            break

        # update params if more data available
        params_json["continuationToken"] = resp_json["continuationToken"]


def main(req):
    global CUSTOMER_ID, CHRONICLE_FUNCTION_INTERVAL
    global CHRONICLE_DATA_TYPE, URL_DOMAIN
    # Citrix url domain according to region
    URL_DOMAIN = get_env_var("URL_DOMAIN")
    CUSTOMER_ID = get_env_var("CITRIX_CUSTOMER_ID")
    CHRONICLE_FUNCTION_INTERVAL = get_env_var("CHRONICLE_FUNCTION_INTERVAL", required=False, default=60)
    CHRONICLE_DATA_TYPE = "CITRIX_MONITOR"

    session = create_new_session(URL_DOMAIN, CUSTOMER_ID)
    get_audit_logs(session)

    return "OK"
