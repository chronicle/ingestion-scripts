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
"""Fetch events from the Onelogin platform."""

import datetime

from common import auth
from common import ingest
from common import status
from common import utils

# API URL for OneLogin Events.
ONELOGIN_EVENTS_URL = "https://api.us.onelogin.com/api/1/events"

# OneLogin Authentication URL.
ONELOGIN_AUTH_URL = "https://api.us.onelogin.com/auth/oauth2/v2/token"

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "ONELOGIN_SSO"

# Date format to be used in API.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

# Environment variable constants.
ENV_CLIENT_ID = "CLIENT_ID"
ENV_CLIENT_SECRET = "CLIENT_SECRET"
ENV_TOKEN_ENDPOINT = "TOKEN_ENDPOINT"


def get_and_ingest_events(http_session: auth.OAuthClientCredentialsAuth):
  """Get events from the OneLogin platform and ingest into Chronicle.

  Args:
    http_session (auth.OAuthClientCredentialsAuth): Session object to get
      events from.

  Raises:
    TypeError, ValueError: Error when response is not in json format.
  """
  # Calculate start time based on POLL_INTERVAL, end time will be 'now'.
  # Convert datetime object into the expected format (YYYY-MM-DDTHH:MM:SSSZ).
  start_time = utils.get_last_run_at().strftime(DATE_FORMAT)[:-3] + "Z"
  end_time = datetime.datetime.now(
      datetime.timezone.utc).strftime(DATE_FORMAT)[:-3] + "Z"

  next_url = (f"{ONELOGIN_EVENTS_URL}?since={start_time}&until={end_time}")

  # Iterate through all the pages if pagination available and ingest data
  # into Chronicle.
  while next_url is not None:
    events_url = next_url

    # Get the response from the OneLogin API.
    request_events = http_session.get(events_url)

    try:
      response_events = request_events.json()
    except (TypeError, ValueError) as error:
      print(
          "ERROR: Unexpected data format received while collecting OneLogin"
          " events."
      )
      raise error

    # If REST API status code is not 200.
    if request_events.status_code != status.STATUS_OK:
      print(f"HTTP Error: {request_events.status_code},"
            " Reason: {resp_json}.")

    request_events.raise_for_status()

    data_list = response_events.get("data", [])
    print(
        f"Retrieved {len(data_list)} OneLogin events from the last"
        " API call."
    )

    # Ingest data into Chronicle.
    if data_list:
      ingest.ingest(response_events["data"], CHRONICLE_DATA_TYPE)

    # Prepare the URL to fetch the next page for OneLogin events.
    next_url = response_events.get("pagination", {}).get("next_link")


def main(request):  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    request: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """

  # Fetching values from the environment variables.
  token_endpoint = utils.get_env_var(
      ENV_TOKEN_ENDPOINT,
      required=False,
      default=ONELOGIN_AUTH_URL,
  )
  client_id = utils.get_env_var(ENV_CLIENT_ID)
  client_secret = utils.get_env_var(ENV_CLIENT_SECRET, is_secret=True)

  # Creating the session object.
  session = auth.OAuthClientCredentialsAuth(token_endpoint, client_id,
                                            client_secret)

  # Fetch and ingest the events from OneLogin platform into Chronicle.
  get_and_ingest_events(session)

  return "Ingestion completed."
