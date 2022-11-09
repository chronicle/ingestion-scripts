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
"""fetch events from box."""
from datetime import datetime

from chronicle import ingest
from chronicle.auth import OAuthClientCredentialsAuth
from chronicle.utils import get_env_var, get_last_run_at


PAGE_SIZE = 100

def get_events_from_box(session, start_time, end_time):
    """Fetch events from BOX platform.

    Args:
        session : Authorized session for HTTP requests.
        start_time : time interval.

    Returns:
        list: A collection of events.
    """
    params = {
        "stream_type": "admin_logs",
        "limit": PAGE_SIZE,
        "created_after": start_time,
        "created_before": end_time,
        "stream_position": None,
    }
    url = "https://api.box.com/2.0/events"

    def before_next(request, response):
        request.params["stream_position"] = response.json().get(
            "next_stream_position"
        )
        return request

    for response in session.paginate(
        "GET",
        url,
        params=params,
        has_next=lambda response: response.json().get("chunk_size") != 0,
        before_next=before_next,
    ):

        try:
            box_response = response.json()
        except (TypeError, ValueError) as error:
            print(
                "ERROR: Unexpected data format received while collecting Box events"
            )
            raise error
        
        if box_response.get("entries"):
            ingest(box_response["entries"], "BOX")


def main(request):
    """Entrypoint."""
    CLIENT_ID = get_env_var("BOX_CLIENT_ID")
    CLIENT_SECRET = get_env_var("BOX_CLIENT_SECRET", is_secret=True)
    BOX_SUBJECT_ID = get_env_var("BOX_SUBJECT_ID")

    def before_request(request):
        request.data["box_subject_type"] = "enterprise"
        request.data["box_subject_id"] = BOX_SUBJECT_ID
        return request

    session = OAuthClientCredentialsAuth(
        "https://api.box.com/oauth2/token",
        CLIENT_ID,
        CLIENT_SECRET,
        before_request=before_request,
    )

    start_time = get_last_run_at().strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    get_events_from_box(session, start_time, end_time)

    return {}
