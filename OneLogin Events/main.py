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
"""Main Execution Method."""

import datetime

from chronicle import ingest
from chronicle.utils import get_env_var, get_last_run_at
from chronicle.auth import OAuthClientCredentialsAuth


def get_events(http_session):
    """Get event data from third-party API.

    Args:
        http_session (session): session object to get events from.
    """
    time_now = str(datetime.datetime.now()).replace(" ", "T")[:-3] + "Z"
    time_then = str(get_last_run_at()).replace(" ", "T")[:-3] + "Z"
    next_url = (
        "https://api.us.onelogin.com/api/1/events?since={}&until={}".format(
            time_then, time_now
        )
    )
    log_type = "ONELOGIN_SSO"
    while next_url is not None:
        events_url = next_url
        request_events = http_session.get(events_url)
        try:
            response_events = request_events.json()
        except (TypeError, ValueError) as error:
            print(
                "ERROR: Unexpected data format received while collecting OneLogin events"
            )
            raise error

        if response_events.get("data"):
            ingest(response_events["data"], log_type)
    
        next_url = response_events.get("pagination", {}).get("next_link")

def main(request):
    """Entrypoint."""
    token_endpoint = get_env_var(
        "TOKEN_ENDPOINT",
        required=False,
        default="https://api.us.onelogin.com/auth/oauth2/v2/token",
    )
    client_id = get_env_var("CLIENT_ID")
    client_secret = get_env_var("CLIENT_SECRET", is_secret=True)

    session = OAuthClientCredentialsAuth(
        token_endpoint, client_id, client_secret
    )
    get_events(session)
    return {}
