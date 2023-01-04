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
"""Fetch events data from Box API."""

import datetime
import requests

# copybara:strip_begin(imports)
from common import auth
from common import ingest
from common import utils
# copybara:strip_end

# Default page size to fetch events from box.
PAGE_SIZE = 100

# Box event API endpoint URL.
BOX_EVENTS_URL = "https://api.box.com/2.0/events"

# Box authentication endpoint URL.
BOX_AUTH_URL = "https://api.box.com/oauth2/token"

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "BOX"

# Environment variables constants.
ENV_BOX_CLIENT_ID = "BOX_CLIENT_ID"
ENV_BOX_CLIENT_SECRET = "BOX_CLIENT_SECRET"
ENV_BOX_SUBJECT_ID = "BOX_SUBJECT_ID"

BOX_SUBJECT_TYPE = "enterprise"


def get_and_ingest_events_from_box(
    session: auth.OAuthClientCredentialsAuth) -> None:
  """Fetch events from BOX platform and ingest into Chronicle.

  Args:
    session (OAuthClientCredentialsAuth): Authorized session for HTTP requests.

  Raises:
    TypeError, ValueError: Error when response is not in json format.
  """
  # Calculate start time based on POLL_INTERVAL, end time will be 'now'.
  # Convert datetime object into the expected format (YYYY-MM-DDTHH:MM:SSSZ).
  start_time = utils.get_last_run_at().strftime("%Y-%m-%dT%H:%M:%SZ")
  end_time = datetime.datetime.now(
      datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

  params = {
      "stream_type": "admin_logs",
      "limit": PAGE_SIZE,
      "created_after": start_time,
      "created_before": end_time,
  }

  def before_next(request: requests.Request, response: requests.Response):
    """Execute function before executing next API call.

    Args:
      request (requests.Request): User created request object.
      response (requests.Response): Response from HTTP request.

    Returns:
      request: Updated request object.
    """
    request.params["stream_position"] = response.json().get(
        "next_stream_position")
    return request

  # Iterate through all the pages if pagination available and ingest data into
  # Chronicle.
  for response in session.paginate(
      "GET",
      BOX_EVENTS_URL,
      params=params,
      has_next=lambda response: response.json().get("chunk_size") != 0,
      before_next=before_next,
  ):

    try:
      box_response = response.json()
    except (TypeError, ValueError) as error:
      print(
          "ERROR: Unexpected data format received while collecting Box events")
      raise error

    data_list = box_response.get("entries", [])
    print(f"Retrieved {len(data_list)} Box events from the last API call.")

    # Ingest data into the Chronicle.
    if data_list:
      ingest.ingest(data_list, CHRONICLE_DATA_TYPE)


def main(request):  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    request: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """
  # Fetching values from the environment variables.
  client_id = utils.get_env_var(ENV_BOX_CLIENT_ID)
  client_secret = utils.get_env_var(ENV_BOX_CLIENT_SECRET, is_secret=True)
  box_subject_id = utils.get_env_var(ENV_BOX_SUBJECT_ID)

  def before_request(request):
    request.data["box_subject_type"] = BOX_SUBJECT_TYPE
    request.data["box_subject_id"] = box_subject_id
    return request

  # Create a new Box session.
  session = auth.OAuthClientCredentialsAuth(
      BOX_AUTH_URL,
      client_id,
      client_secret,
      before_request=before_request,
  )

  get_and_ingest_events_from_box(session)

  return "Ingestion completed."
