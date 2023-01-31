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
"""Fetch the data of Very Attacked People in an organization from Proofpoint and ingest into Chronicle."""

from requests import exceptions

from common import auth
from common import ingest
from common import status
from common import utils

# Proofpoint People API supports data collection for last 14, 30 and 90 days
# only.
VALID_PROOFPOINT_WINDOW = ["14", "30", "90"]

# Environment variable constants.
ENV_PROOFPOINT_SERVER_URL = "PROOFPOINT_SERVER_URL"
ENV_PROOFPOINT_SERVICE_PRINCIPLE = "PROOFPOINT_SERVICE_PRINCIPLE"
ENV_PROOFPOINT_SECRET = "PROOFPOINT_SECRET"
ENV_PROOFPOINT_RETRIEVAL_RANGE = "PROOFPOINT_RETRIEVAL_RANGE"
ENV_CHRONICLE_DATA_TYPE = "CHRONICLE_DATA_TYPE"

# Error message dictionary for different error codes.
# This dictionary can be used while raising exception for various error codes.
# The Proofpoint API is not giving proper error message with error codes,
# so using below custom messages.(Proofpoint specific)
# Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/People_API#Standard_responses   # pylint: disable=line-too-long

ERROR_CODES = {
    "400":
        "Status code 400. Bad Request. Possible reason could be, the "
        "Proofpoint retrieval range provided is having a value other than 14, "
        "30 or 90.",
    "401": "Status code 401. Authentication failed. Possible reason could be, "
           "Proofpoint service principle or Proofpoint secret is invalid.",
    "429":
        "Status code 429. API rate limit exceeded. The API rate limit for the "
        "Proofpoint People API is 50 per day.",
    "500": "Status code 500. Internal server error occurred.",
    "default": "Error occurred while making the API request.",
}


class InvalidValueError(Exception):
  """Custom exception class for invalid values."""

  def __init__(self, message: str) -> None:
    """Constructor for InvalidValueError class.

    Args:
      message (str): Error message.
    """
    self.message = message
    super().__init__(message)


def validate_params(retrieval_range: str) -> None:
  """Validate the configuration parameter retrieval_range.

  Args:
    retrieval_range (str): How many days the data should be retrieved for.

  Raises:
    InvalidValueError: If retrieval_range has non-accepted values.
  """
  # Check whether the provided retrieval range is either 14, 30 or 90.
  if retrieval_range not in VALID_PROOFPOINT_WINDOW:
    raise InvalidValueError(
        f"Invalid value provided for retrieval range. Supported values are: {', '.join(VALID_PROOFPOINT_WINDOW)}"
    )


def get_and_ingest_users(session: auth.UsernamePasswordAuth, server_url: str,
                         retrieval_range: str,
                         chronicle_data_type: str) -> None:
  """Fetch the Very Attacked People from Proofpoint and ingest the events into Chronicle.

  Args:
    session (auth.UsernamePasswordAuth): The required session object for API
      calls.
    server_url (str): Base URL of Proofpoint Server API gateway.
    retrieval_range (str): Number indicating from how many days the data should
      be retrieved.
    chronicle_data_type (str): Log type to push data into the Chronicle
      platform.

  Raises:
    RuntimeError: If any error occurred while fetching and ingesting users
    identities.
  """
  page_index = 1
  log_count = 0

  # Loop until all the Very Attacked People user data is collected in the given
  # time range.
  while True:
    url = f"{server_url}/v2/people/vap?window={retrieval_range}&page={page_index}"

    try:
      # Fetching the identities and attack index breakdown of Very Attacked
      # People.
      response = session.get(url)
      response_status = response.status_code
    except exceptions.HTTPError as error:
      response_status = error.response.status_code
    except Exception as exc:
      raise RuntimeError(ERROR_CODES.get("default")) from exc

    # Raise runtime error if the response status code is not equal to 200.
    if response_status != status.STATUS_OK:
      raise RuntimeError(
          ERROR_CODES.get(str(response_status), ERROR_CODES["default"]))

    # Retrieve the json response and calculate number of users as log count.
    try:
      json_response = response.json()
    except (ValueError, TypeError) as error:
      raise RuntimeError(
          "Unexpected data format received while collecting users from Proofpoint."
      ) from error

    vap_users = json_response.get("users", [])
    log_count += len(vap_users)

    if vap_users:
      try:
        # Ingest the Very Attacked People user identities into Chronicle.
        ingest.ingest(vap_users, chronicle_data_type)
      except Exception as error:
        # Raise an exception if the data can't be pushed into Chronicle.
        raise Exception("Unable to push the data to the Chronicle.") from error

    # Exit the while loop if number of logs collected is equal to totalVapUsers.
    if log_count == json_response.get("totalVapUsers", 0):
      break

    page_index += 1

  if not log_count:
    print("No logs found for the given retrieval range.")
  else:
    print(f"Total {log_count} log(s) ingested successfully into the Chronicle.")


# Request is a user input dictionary passed while running the cloud function.
# The script does not use this parameter.
def main(request):   # pylint: disable=unused-argument
  """EntryPoint.

  Args:
    request: Argument to run cloud function.

  Returns:
    str: "Ingestion Completed." if function execution is successful.
  """
  # Fetch the environment variables.
  server_url = utils.get_env_var(ENV_PROOFPOINT_SERVER_URL)
  service_principle = utils.get_env_var(ENV_PROOFPOINT_SERVICE_PRINCIPLE)
  secret = utils.get_env_var(ENV_PROOFPOINT_SECRET, is_secret=True)

  # Retrieval range indicates the number of days to fetch the data from.
  retrieval_range = utils.get_env_var(
      ENV_PROOFPOINT_RETRIEVAL_RANGE, required=False, default="30")

  chronicle_data_type = utils.get_env_var(ENV_CHRONICLE_DATA_TYPE)

  # Validate the window parameter.
  validate_params(retrieval_range=retrieval_range)

  # Using UsernamePasswordAuth to get and set bearer token.
  session = auth.UsernamePasswordAuth(service_principle, secret)

  # Get the Very Attacked People from Proofpoint and ingest them in Chronicle.
  get_and_ingest_users(session, server_url, retrieval_range,
                       chronicle_data_type)

  return "Ingestion completed."
