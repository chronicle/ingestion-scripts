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
"""Fetch session metadata from Citrix API."""

import datetime

import requests

# copybara:strip_begin(imports)
from common import auth
from common import ingest
from common import status
from common import utils
# copybara:strip_end

# Environment variables name.
ENV_CITRIX_URL_DOMAIN = "URL_DOMAIN"
ENV_CITRIX_CUSTOMER_ID = "CUSTOMER_ID"
ENV_CITRIX_CLIENT_ID = "CITRIX_CLIENT_ID"
ENV_CITRIX_CLIENT_SECRET = "CITRIX_CLIENT_SECRET"

# Initializing values for environment variables.
# Declaring as global variables as they are being used in multiple functions.
CUSTOMER_ID = None
URL_DOMAIN = None

# Date format for API.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

# Number of maximum retries to create a new Citrix session.
MAX_RETRIES = 3

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "CITRIX_SESSION_METADATA"


def create_new_session() -> requests.Session:
  """Create Session for citrix.

  Returns:
    requests.Sessions: Session created for citrix.
  """
  client_id = utils.get_env_var(ENV_CITRIX_CLIENT_ID)
  client_secret = utils.get_env_var(ENV_CITRIX_CLIENT_SECRET, is_secret=True)

  session = auth.OAuthClientCredentialsAuth(
      f"https://{URL_DOMAIN}/cctrustoauth2/{CUSTOMER_ID}/tokens/clients",
      client_id,
      client_secret,
  ).session

  return session


def get_access_token(session: requests.Session) -> str:
  """Get access token from session header.

  Args:
    session (requests.Session): Session created for citrix api.

  Returns:
    str: Token from session header.

  Raises:
    KeyError, IndexError: Error when Authorization is not obtained.
  """
  try:
    # If session is created successfully, access token will be present in the
    # Authorization key of headers as "<some_string> <access_token>."
    access_token = session.headers["Authorization"].split()[1]
  except (KeyError, IndexError) as error:
    print("Unable to fetch access token from the session.")
    raise error

  return access_token


def get_and_ingest_session_metadata(session: requests.Session):
  """Get session metadata from citrix.

  Args:
    session (requests.Session): Session created for citrix api.

  Raises:
    TypeError, ValueError: Error when response is not in json format.
  """
  # Get access token from session header.
  access_token = get_access_token(session)

  # Calculate start time based on POLL_INTERVAL, end time will be 'now'.
  # Convert datetime object into the expected format (YYYY-MM-DDTHH:MM:SSSZ).
  start_time = utils.get_last_run_at().strftime(DATE_FORMAT)[:-3] + "Z"
  end_time = (datetime.datetime.now(
      datetime.timezone.utc)).strftime(DATE_FORMAT)[:-3] + "Z"

  print(
      f"Retrieving session metadata from {start_time} to {end_time}")

  headers_json = {
      "Accept": "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "Citrix-CustomerId": CUSTOMER_ID,
      # Changing the prefix as citrix need a specific prefix.
      "Authorization": f"CwsAuth Bearer= {access_token}",
  }

  params_json = {
      "$filter":
          f"ModifiedDate ge {start_time} and ModifiedDate le {end_time}",
      "$orderby":
          "ModifiedDate asc",
      "$expand":
          "User($select=UserName,FullName)"
  }

  citrix_url = f"https://{URL_DOMAIN}/monitorodata/Sessions?"

  for key, value in params_json.items():
    citrix_url = citrix_url + f"{key}={value}&"

  citrix_url = citrix_url.strip("&")

  new_session_count = 0
  # Iterate through all the pages if pagination available and ingest data into
  # Chronicle.
  while True:
    response = requests.get(
        citrix_url,
        headers=headers_json,
    )

    try:
      resp_json = response.json()
    except (ValueError, TypeError) as error:
      print(
          "ERROR: Unexpected data format received while collecting session"
          " metadata."
      )
      raise error

    if response.status_code == status.STATUS_OK:
      # Resetting the value of session count as the access token is active.
      new_session_count = 0

    # If access token expires, the API will raise 401 error. Hence, attempting
    # to create a new session.
    elif response.status_code == status.STATUS_UNAUTHORIZED:
      # Checking if session creation retries == max retries.
      # Maximum 3 retries will be done to create a session.
      if new_session_count == MAX_RETRIES:
        print(
            "Unable to fetch the access token for data collection. Exiting...")
      else:
        new_session_count = new_session_count + 1
        print("Previous session expired. Creating new session...")
        session = create_new_session()

        # Getting new access token from the session.
        access_token = get_access_token(session)
        headers_json["Authorization"] = f"CwsAuth Bearer={access_token}"

        print("Created new session. Resuming data collection.")
        continue
    else:
      print(f"HTTP Error: {response.status_code}, Reason: {resp_json}.")

    response.raise_for_status()

    data_list = list(resp_json["value"])
    print(
        f"Retrieved {len(data_list)} records for Citrix session metadata from"
        " the last API call."
    )

    if data_list:
      # Ingest data into Chronicle.
      ingest.ingest(data_list, CHRONICLE_DATA_TYPE)

    # Get the next page URL if available.
    if resp_json.get("@odata.nextLink"):
      citrix_url = resp_json["@odata.nextLink"]
      print(f"Next page URL: {citrix_url}")
    else:
      print("Data collection completed")
      break


def main(req):  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    req: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """
  global CUSTOMER_ID
  global URL_DOMAIN

  # Fetching values from the environment variables.
  URL_DOMAIN = utils.get_env_var(ENV_CITRIX_URL_DOMAIN)
  CUSTOMER_ID = utils.get_env_var(ENV_CITRIX_CUSTOMER_ID)

  # Create new Citrix session.
  session = create_new_session()

  # Fetch and ingest Citrix session metadata into Chronicle.
  get_and_ingest_session_metadata(session)

  return "Ingestion completed."
