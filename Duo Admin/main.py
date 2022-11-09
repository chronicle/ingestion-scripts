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
import json
from datetime import datetime, timedelta
import duo_client

from chronicle import ingest
from chronicle.utils import get_env_var


def main(req):
    global CHRONICLE_DATA_TYPE, DEBUG
    global DUO_API_IKEY, DUO_API_SKEY, DUO_API_HOSTNAME
    global FUNCTION_MINUTE_INTERVAL
    CHRONICLE_DATA_TYPE = "DUO_ADMIN"
    # Interval should match what you have configured in Cloud Scheduler
    FUNCTION_MINUTE_INTERVAL = get_env_var("FUNCTION_MINUTE_INTERVAL", required=False, default=10)
    # Duo Admin API integration key
    DUO_API_IKEY = json.loads(get_env_var("DUO_API_DETAILS", is_secret=True))["ikey"]
    # Duo Admin API secret key
    DUO_API_SKEY = json.loads(get_env_var("DUO_API_DETAILS", is_secret=True))["skey"]
    # Duo Admin API hostname
    DUO_API_HOSTNAME = json.loads(get_env_var("DUO_API_DETAILS", is_secret=True))[
        "api_host"
    ]
    # Debug flag. GREATLY increases the verbosity of logging
    DEBUG = get_env_var("DEBUG", required=False, default=False)

    get_and_ingest_logs()


# Fetch logs from client, process it and ingest
def get_and_ingest_logs():

    # Calc start time, end time will be 'now'
    min_time = datetime.utcnow() - timedelta(minutes=int(FUNCTION_MINUTE_INTERVAL))
    min_time_str = min_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    min_time = int((min_time - datetime(1970, 1, 1)).total_seconds())
    print(
        "Retrieving "
        + str(FUNCTION_MINUTE_INTERVAL)
        + " mins of logs since: "
        + min_time_str
    )
    print("Processing logs...")
    # response consists of maximum 1000 log entries.
    log_count = 1000

    admin_api = duo_client.Admin(
        ikey=DUO_API_IKEY, skey=DUO_API_SKEY, host=DUO_API_HOSTNAME
    )

    # If log_count is less than 1000, no need to check for next entries.
    while log_count == 1000:
        data_list = []
        if DEBUG:
            print(f"Processing set of results with mintime: {str(min_time)}")

        logs = admin_api.get_administrator_log(mintime=min_time)
        log_count = len(logs)

        if DEBUG:
            print(f"Retrieved {log_count} administrator logs from the API call")

        # No need to ingest logs for empty response
        if log_count == 0:
            break

        data_list.extend(iter(logs))
        # Getting the next checkpoint for data collection
        min_time = logs[0]["timestamp"]

        # ingest collected logs
        ingest(data_list, CHRONICLE_DATA_TYPE)
