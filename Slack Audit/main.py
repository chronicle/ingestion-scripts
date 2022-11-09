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
from datetime import datetime, timedelta
import requests
from chronicle import ingest
from chronicle.utils import get_env_var

# Fetch logs from API, process it and ingest
def get_and_ingest_audit_logs():

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

    url = f"https://api.slack.com/audit/v1/logs?oldest={min_time}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SLACK_ADMIN_TOKEN}",
    }

    # Iterate through all the pages if pagination
    # available and add data to data_list
    while True:
        data_list = []

        if DEBUG:
            print(f"Processing set of results with mintime: {min_time}")

        resp = requests.get(url=url, headers=headers)

        try:
            r = resp.json()
        except (TypeError, ValueError) as e:
            print(
                "ERROR: Unexpected data format received while collecting \
                 audit logs"
            )
            raise(e)

        if resp.status_code != 200:
            print("HTTP Error: {}, Reason: {}".format(resp.status_code, r))

        resp.raise_for_status()

        log_count = len(r.get("entries", []))

        if DEBUG:
            print(f"Retrieved {log_count} audit logs from the API call")

        # No need to ingest logs for empty response
        if log_count == 0:
            break

        data_list.extend(iter(r["entries"]))

        # Ingest list of data to chronicle
        ingest(data_list, CHRONICLE_DATA_TYPE)

        # update the url if next cursor is available
        if r["response_metadata"]["next_cursor"]:
            url = "https://api.slack.com/audit/v1/logs?oldest={} \
                &cursor={}".format(
                min_time, r["response_metadata"]["next_cursor"]
            )
            print('More records expected so re-running! (processed '+str(log_count)+' records)')
        else:
            print("Logs processed successfully.")
            break


def main(req):
    global CHRONICLE_DATA_TYPE, DEBUG
    global SLACK_ADMIN_TOKEN, FUNCTION_MINUTE_INTERVAL
    CHRONICLE_DATA_TYPE = "SLACK_AUDIT"
    FUNCTION_MINUTE_INTERVAL = get_env_var("FUNCTION_MINUTE_INTERVAL", 60)
    # Slack admin token
    SLACK_ADMIN_TOKEN = get_env_var("SLACK_ADMIN_TOKEN", is_secret=True)
    # Debug flag. GREATLY increases the verbosity of logging
    DEBUG = get_env_var("DEBUG", required=False, default=False)

    # Method to fetch audit logs and ingest to chronicle
    get_and_ingest_audit_logs()
    return "OK"
