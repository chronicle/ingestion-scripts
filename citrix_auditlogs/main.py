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
"""Fetch Audit logs from citrix API."""

import datetime

import requests

# copybara:strip_begin(imports)
from google3.third_party.chronicle.ingestion_scripts.common import auth
from google3.third_party.chronicle.ingestion_scripts.common import env_constants
from google3.third_party.chronicle.ingestion_scripts.common import ingest
from google3.third_party.chronicle.ingestion_scripts.common import status
from google3.third_party.chronicle.ingestion_scripts.common import utils
# copybara:strip_end

# Environment variables name.
ENV_CITRIX_URL_DOMAIN = "URL_DOMAIN"
ENV_CITRIX_CUSTOMER_ID = "CUSTOMER_ID"
ENV_CITRIX_CLIENT_ID = "CITRIX_CLIENT_ID"
ENV_CITRIX_CLIENT_SECRET = "CITRIX_CLIENT_SECRET"

# Initializing values for environment variables.
# Declaring as global variables as they are being used in multiple functions.
CUSTOMER_ID = None
POLL_INTERVAL = 30
URL_DOMAIN = None

# Date format for API.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

# Number of maximum retries to create a new Citrix session.
MAX_RETRIES = 3

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "CITRIX_MONITOR"

# Maximum number of records to expect in one API call.
PAGE_SIZE = 200


def create_new_session() -> requests.Session:
  """Create Session for citrix.

  Returns:
    requests.Sessions: Session created for citrix.
  """
  client_id = utils.get_env_var(ENV_CITRIX_CLIENT_ID)
  client_secret = utils.get_env_var(ENV_CITRIX_CLIENT_SECRET, is_secret=True)

  return auth.OAuthClientCredentialsAuth(
      f"https://{URL_DOMAIN}/cctrustoauth2/{CUSTOMER_ID}/tokens/clients",
      client_id,
      client_secret,
  ).session


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


def get_and_ingest_audit_logs(session: requests.Session):
  """Get audit logs from citrix.

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

  print(f"Retrieving audit logs from {start_time} to {end_time}")

  headers_json = {
      "Accept": "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "Citrix-CustomerId": CUSTOMER_ID,
      # Changing the prefix as citrix need a specific prefix.
      "Authorization": f"CwsAuth Bearer= {access_token}",
  }

  citrix_url = f"https://{URL_DOMAIN}/systemlog/records"

  params_json = {
      "startDateTime": start_time,
      "endDateTime": end_time,
      "limit": PAGE_SIZE,
  }

  new_session_count = 0

  # Iterate through all the pages if pagination available and ingest data into
  # Chronicle.
  while True:
    response = requests.get(
        citrix_url,
        headers=headers_json,
        params=params_json,
    )

    try:
      resp_json = response.json()
    except (ValueError, TypeError) as error:
      print(
          "ERROR: Unexpected data format received while collecting audit logs.")
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

    data_list = list(resp_json["items"])
    print(f"Retrieved {len(data_list)} Citrix audit logs from the last"
          " API call.")

    if data_list:
      # Ingest data into Chronicle.
      ingest.ingest(data_list, CHRONICLE_DATA_TYPE)

    # Break the loop if next token unavailable.
    if not resp_json.get("continuationToken"):
      print("Data collection completed")
      break

    # Update params if more data available.
    params_json["continuationToken"] = resp_json["continuationToken"]


def main(req) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    req: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """
  global CUSTOMER_ID, POLL_INTERVAL
  global URL_DOMAIN

  # Fetching values from the environment variables.
  URL_DOMAIN = utils.get_env_var(ENV_CITRIX_URL_DOMAIN)
  CUSTOMER_ID = utils.get_env_var(ENV_CITRIX_CUSTOMER_ID)
  POLL_INTERVAL = utils.get_env_var(
      env_constants.ENV_POLL_INTERVAL, required=False, default=POLL_INTERVAL)

  # Create new Citrix session.
  session = create_new_session()

  # Fetch and ingest Citrix audit logs into Chronicle.
  get_and_ingest_audit_logs(session)

  return "Ingestion completed."
