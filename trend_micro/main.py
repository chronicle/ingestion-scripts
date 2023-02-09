# Copyright 2023 Google LLC
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
"""Fetch security logs from the Trend Micro and ingest into Chronicle."""
import datetime
import time
from typing import Any, List

import requests

from common import ingest
from common import status
from common import utils

# The date format to be used for converting python datetime object to
# human-readable string.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# A list of possible Trend Micro services.
VALID_TREND_MICRO_SERVICES = ["exchange", "sharepoint", "onedrive", "dropbox",
                              "box", "googledrive", "gmail", "teams",
                              "exchangeserver", "salesforce_sandbox",
                              "salesforce_production", "teams_chat"]

# A list of possible Trend Micro events.
VALID_TREND_MICRO_EVENTS = ["securityrisk", "virtualanalyzer",
                            "ransomware", "dlp"]

# The default value for Trend Micro services and events.
# By default, data will be collected for all the Trend Micro services.
DEFAULT_TREND_MICRO_SERVICE = ",".join(VALID_TREND_MICRO_SERVICES)

# By default, data will be collected for all the Trend Micro events.
DEFAULT_TREND_MICRO_EVENT = ",".join(VALID_TREND_MICRO_EVENTS)

# Environment variable constants.
ENV_TREND_MICRO_SERVICE_URL = "TREND_MICRO_SERVICE_URL"
ENV_TREND_MICRO_AUTHENTICATION_TOKEN = "TREND_MICRO_AUTHENTICATION_TOKEN"
ENV_TREND_MICRO_SERVICE = "TREND_MICRO_SERVICE"
ENV_TREND_MICRO_EVENT = "TREND_MICRO_EVENT"
ENV_CHRONICLE_DATA_TYPE = "CHRONICLE_DATA_TYPE"


class InvalidValueError(Exception):
  """Custom exception class for invalid values."""

  def __init__(self, message: str) -> None:
    """Constructor for InvalidValueError class.

    Args:
      message (str): Error message.
    """
    self.message = message
    super().__init__(message)


def validate_params(services: List[Any], event_types: List[Any]) -> None:
  """Validate the configuration parameters.

  Args:
    services (List): List of user provided Trend Micro service.
    event_types (List): List of user provided Trend Micro event types.

  Raises:
    InvalidValueError: If any parameter has non-accepted value.
  """
  # Check whether the provided services are valid or not.
  for service in services:
    if service not in VALID_TREND_MICRO_SERVICES:
      raise InvalidValueError(
          "Validation error: Invalid value provided for service. "
          f"Supported values are: {VALID_TREND_MICRO_SERVICES}")

  # Check whether the provided event types are valid or not.
  for event in event_types:
    if event not in VALID_TREND_MICRO_EVENTS:
      raise InvalidValueError(
          "Validation error: Invalid value provided for event. "
          f"Supported values are: {VALID_TREND_MICRO_EVENTS}")


def get_and_ingest_security_logs(authentication_token: str,
                                 chronicle_data_type: str, service_url: str,
                                 services: List[Any],
                                 event_types: List[Any]) -> None:
  """Fetch security logs from Trend Micro platform and ingest them into Chronicle.

  Args:
    authentication_token (str): Authentication token used to authenticate with
    the API.
    chronicle_data_type (str): Log type to push the data into Chronicle.
    service_url (str): Service URL of the Cloud App Security service.
    services (List): A list of the protected service, whose logs are to be
      fetched and ingested.
    event_types (List): A list of event types that needs to be fetched and
      ingested.

  Raises:
    RuntimeError: If any error occurred while fetching and ingesting security
    logs.
  """

  # Calculate the start time and end time based on the POLL_INTERVAL
  # environment variable.
  start_time = utils.get_last_run_at().strftime(DATE_FORMAT)
  end_time = datetime.datetime.now(datetime.timezone.utc).strftime(DATE_FORMAT)

  headers = {"Authorization": "Bearer " + authentication_token}

  # Iterating over the list of services provided by the user and ingesting logs.
  for service in services:
    # Iterating over the list of event_types for each Trend Micro service.
    for event in event_types:
      url = f"https://{service_url}/v1/siem/security_events?service={service}&event={event}&start={start_time}&end={end_time}"
      print(f"Retrieving security logs of {service} service for {event} event "
            f" which are added after {start_time}.")

      service_event_log_count = 0
      retry_count = 0
      # Get the security logs from the Trend Micro API until next_link is
      # present in the response.
      while True:
        response = requests.get(url, headers=headers)
        response_status = response.status_code

        # Trend Micro Cloud API has a rate limit of 20 requests per second.
        # Reference: https://docs.trendmicro.com/en-us/enterprise/cloud-app-security-integration-api-online-help/api-responses.aspx   # pylint: disable=line-too-long
        if response_status == status.STATUS_TOO_MANY_REQUESTS:
          # If the response status code is 429, then sleep for 5, 10, 15, 20,
          # and 25 seconds, and request again with the same URL.
          # Keep retrying 5 times(total 75 seconds),
          # otherwise the following code will raise an exception.
          if retry_count < 5:
            retry_count += 1
            print(f"Maximum allowed requests in 1 minute exceeded for Trend Micro API. Retrying after {str(5 * retry_count)} second(s).")
            time.sleep(5 * retry_count)
            continue
          else:
            print("Maximum retry limit reached. Exiting the function...")

        try:
          json_response = response.json()
        except (ValueError, TypeError) as error:
          raise ValueError("Unexpected data format received while collecting "
                           "security logs from Trend Micro.") from error

        # If the response status code is other than 200, then raise the error.
        if response_status != status.STATUS_OK:
          error_message = json_response.get("msg", json_response)
          raise RuntimeError("Failed to get security logs from Trend Micro "
                             f"with status code {response_status}. "
                             f"Error message: {error_message}")

        # Ingest Trend Micro security logs to the Chronicle platform.
        security_event_list = json_response.get("security_events", [])
        try:
          ingest.ingest(security_event_list, chronicle_data_type)
          service_event_log_count += len(security_event_list)
        except Exception as error:
          raise RuntimeError("Unable to push Trend Micro security logs into "
                             f"Chronicle: {error}.") from error

        # Update the URL for the next page, if the next_link is present.
        if json_response.get("next_link"):
          # Reset retry_count for the next page,
          # so sleep time will start from 1 second again.
          retry_count = 0
          url = json_response["next_link"]
        else:
          break

      if service_event_log_count:
        print(f"Ingested {service_event_log_count} log(s) of {service} service "
              f" for {event} event into the Chronicle.")
      else:
        print(f"No new logs found from the {service} service for the {event} "
              "event.")


# Request is a user input dictionary passed while running the cloud function.
# The script does not use these parameter.
def main(request) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    request: Request to execute the cloud function.

  Returns:
    str: "Ingestion completed".
  """
  # Fetch the environment variables.
  authentication_token = utils.get_env_var(
      ENV_TREND_MICRO_AUTHENTICATION_TOKEN, is_secret=True)
  service_url = utils.get_env_var(ENV_TREND_MICRO_SERVICE_URL)
  trend_micro_services = utils.get_env_var(
      ENV_TREND_MICRO_SERVICE,
      required=False,
      default=DEFAULT_TREND_MICRO_SERVICE)
  trend_micro_events = utils.get_env_var(
      ENV_TREND_MICRO_EVENT, required=False, default=DEFAULT_TREND_MICRO_EVENT)
  chronicle_data_type = utils.get_env_var(ENV_CHRONICLE_DATA_TYPE)

  # Create a list of Trend Micro services and events from CSV string.
  service_list = [
      service.lower().strip()
      for service in trend_micro_services.strip().split(",")
  ]
  event_list = [
      event.lower().strip() for event in trend_micro_events.strip().split(",")
  ]

  # Validate user provided Trend Micro services and event types.
  validate_params(services=service_list, event_types=event_list)

  # Get security logs from Trend Micro and ingest it into Chronicle.
  get_and_ingest_security_logs(authentication_token, chronicle_data_type,
                               service_url, service_list, event_list)

  return "Ingestion completed."
