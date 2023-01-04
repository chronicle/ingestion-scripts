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
"""Fetch user data from Onelogin Users API."""

import datetime

# copybara:strip_begin(imports)
from common import auth
from common import ingest
from common import status
from common import utils
# copybara:strip_end

# API URL for OneLogin Users.
ONELOGIN_USERS_URL = "https://api.us.onelogin.com/api/1/users"

# Onelogin authentication endpoint URL.
ONELOGIN_AUTH_URL = "https://api.us.onelogin.com/auth/oauth2/v2/token"

# Log type to push data in Chronicle.
CHRONICLE_DATA_TYPE = "ONELOGIN_USER_CONTEXT"

# Date format to be used in API.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

# Environment variable constants.
ENV_CLIENT_ID = "CLIENT_ID"
ENV_CLIENT_SECRET = "CLIENT_SECRET"
ENV_TOKEN_ENDPOINT = "TOKEN_ENDPOINT"


def get_and_ingest_users(http_session: auth.OAuthClientCredentialsAuth) -> None:
  """Get user data from the OneLogin platform and ingest into Chronicle.

  Args:
    http_session (OAuthClientCredentialsAuth): Session object to get users from.

  Raises:
    TypeError, ValueError: Error when response is not in json format.
  """
  # Calculate start time based on POLL_INTERVAL, end time will be 'now'.
  # Convert datetime object into the expected format (YYYY-MM-DDTHH:MM:SSSZ).
  start_time = utils.get_last_run_at().strftime(DATE_FORMAT)[:-3] + "Z"
  end_time = datetime.datetime.now(
      datetime.timezone.utc).strftime(DATE_FORMAT)[:-3] + "Z"

  next_url = (f"{ONELOGIN_USERS_URL}?since={start_time}&until={end_time}")

  # Iterate through all the pages if pagination available and ingest data
  # into Chronicle.
  while next_url is not None:
    users_url = next_url

    # Get the response from the OneLogin API.
    request_users = http_session.get(users_url)

    try:
      response_users = request_users.json()
    except (ValueError, TypeError) as error:
      print(
          "ERROR: Unexpected data format received while collecting OneLogin"
          " users."
      )
      raise error

    # If REST API status code is not 200.
    if request_users.status_code != status.STATUS_OK:
      print(f"HTTP Error: {request_users.status_code},"
            " Reason: {resp_json}.")

    request_users.raise_for_status()

    data_list = response_users.get("data", [])
    print(
        f"Retrieved {len(data_list)} OneLogin users data from the last"
        " API call."
    )

    # Ingest data into Chronicle.
    if data_list:
      ingest.ingest(response_users["data"], CHRONICLE_DATA_TYPE)

    # Prepare the URL to fetch the next page for OneLogin users.
    next_url = response_users.get("pagination", {}).get("next_link")


def main(request) -> str:  # pylint: disable=unused-argument
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

  # Fetch and ingest the user data from OneLogin platform into Chronicle.
  get_and_ingest_users(session)

  return "Ingestion completed."
