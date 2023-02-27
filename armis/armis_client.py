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
"""A common module for fetching data from Armis platform."""

import datetime
import multiprocessing
import os
import time
from typing import Any, Callable, Dict, Optional
from urllib import parse
import requests
from common import status
from common import utils


# Initialing Lock for shared memory.
LOCK = multiprocessing.Lock()

# CONSTANTS
TYPE_VULNERABILITIES = "vulnerabilities"
METHOD_GET = "GET"
ACCESS_TOKEN = "access_token"
EXPIRATION_TIME = "expiration_time"

ERRORS = {
    "ConnectTimeout": lambda error: (  # pylint: disable=g-long-lambda
        f"API call failed. Failed due to connection timeout. Error = {error}"
    ),
    "ConnectionError": (
        "API call failed. Invalid Server URL. Failed to establish a connection."
    ),
    "ReadTimeout": lambda error: (  # pylint: disable=g-long-lambda
        f"API call failed. Failed due to read timeout. Error = {error}"
    ),
    "TooManyRedirects": lambda error: (  # pylint: disable=g-long-lambda
        f"API call failed. Too many redirects. Error - {error}"
    ),
    "HTTPError": lambda error: f"API call failed. HTTP error. Error = {error}",
    "Error": lambda error: f"API call failed. Error = {error}",
}

# Dateformat supported by Armis API.
ARMIS_API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"

# Armis API endpoints.
ARMIS_ACCESS_TOKEN_ENDPOINT = "api/v1/access_token/"
ARMIS_SEARCH_ENDPOINT = "api/v1/search/"

# Default page size to fetch logs from Armis.
PAGE_SIZE = 1000

# Maximum number of retries to connect with Armis API.
MAX_RETRIES_SERVER_ERROR = 3

# Maximum number of retries to generate access token for Armis API.
MAX_RETRIES_ACCESS_TOKEN = 1

# Initial wait time before retrying an API call.
WAIT_TIME = 30

# Required proxy prefix.
PROXY_PREFIXES = [
    "http://",
    "https://",
    "socks5://",
    "socks5h://",
    "socks4://",
    "socks4a://",
]

# Initial value of access token.
INITIAL_ACCESS_TOKEN = ""


def error_handler(func: Callable[..., Any]) -> Any:
  """Handle all possible API call exception and raise an exception based on that.

  Args:
    func (Callable): Function that needs to be executed.

  Returns:
    Any: Wrapper function.
  """

  def wrapper(*args, **kwargs):
    try:
      return func(*args, **kwargs)
    except requests.exceptions.ProxyError as error:
      raise RuntimeError(
          f"API call failed. Failed due to proxy error. Error = {error}"
      ) from error
    except requests.ConnectTimeout as error:
      raise RuntimeError(ERRORS["ConnectTimeout"](error)) from error
    except requests.ConnectionError as error:
      raise RuntimeError(ERRORS["ConnectionError"]) from error
    except requests.ReadTimeout as error:
      raise RuntimeError(ERRORS["ReadTimeout"](error)) from error
    except requests.TooManyRedirects as error:
      raise RuntimeError(ERRORS["TooManyRedirects"](error)) from error
    except requests.HTTPError as error:
      raise RuntimeError(ERRORS["HTTPError"](error)) from error
    except Exception as error:
      raise RuntimeError(ERRORS["Error"](error)) from error

  return wrapper


class ArmisClient:
  """Armis Client to work with Armis API."""

  def __init__(
      self,
      server_url: str,
      secret_key: str,
      start_time: Optional[datetime.datetime] = None,
  ) -> None:
    """Constructor for ArmisClient class.

    Args:
      server_url (str): Server URL of Armis platform.
      secret_key (str): Secret key to authenticate Armis platform.
      start_time (datetime.datetime): Start time to fetch the data. Defaults to
        None.
    """
    self.server_url = server_url
    self.secret_key = secret_key
    self.start_time = start_time

    # Handle Proxy URL
    self.handle_proxy()

  def sleep_and_retry(self, retry_count: int, error: str) -> int:
    """Holds the execution of the function for the time calculated from retry count and increases retry count.

    Args:
      retry_count (int): Retry count to calculate wait time of function.
      error (str): Error occurred while executing API call.

    Returns:
      int: Incremented retry count.
    """
    # Time to stop the function in seconds before retrying.
    stop_time = WAIT_TIME * retry_count
    print(
        f"{error} API call to Armis platform failed. "
        f"Retrying after {stop_time} seconds."
    )

    # Stop the function for specified time.
    time.sleep(stop_time)

    # Increment retry count.
    return retry_count + 1

  def handle_proxy(self) -> None:
    """Adds `http://` prefix to the proxy address in case it is missing."""
    https_proxy = utils.get_env_var("HTTPS_PROXY", required=False)
    if https_proxy:
      for prefix in PROXY_PREFIXES:
        if https_proxy.startswith(prefix):
          break
      else:
        os.environ["HTTPS_PROXY"] = "http://" + https_proxy

  def create_time_frame_string(self) -> str:
    """Calculates a formatted timeframe string and rounds the result into seconds.

    Returns:
      time_frame_string: An Armis API compatible time frame string based
        on the poll interval.
    """
    current_time = datetime.datetime.now(datetime.timezone.utc)
    time_frame_seconds = round((current_time - self.start_time).total_seconds())
    time_frame_string = f' timeFrame:"{time_frame_seconds} seconds"'
    return time_frame_string

  @error_handler
  def http_request(
      self, method: str, endpoint: str, **kwargs
  ) -> Dict[str, Any]:
    """Constructs URL and sends request.

    Args:
      method (str): Request method.
      endpoint (str): Endpoint for http request.
      **kwargs: Any keyword arguments to be passed.

    Raises:
      requests.HTTPError: When an HTTP response has a status
      code other than 200, an exception occurs.
      ConnectionError: When invalid server URL passed.

    Returns:
      Dict[str, Any]: Response JSON from the API.
    """
    # Join Armis server URL with required endpoint.
    url = parse.urljoin(self.server_url, endpoint)

    # Initialize retry count
    retry_count_server_error = 1
    retry_count_access_token = 1

    headers = kwargs.pop("headers")
    access_token_info = kwargs.pop("access_token_info", "")

    # Make a call to the API. If ConnectionError, TimeoutError, or any
    # other HttpError occurs, then retry for a maximum of 3 times.
    while True:
      try:
        # Send request for provided URL. Break the loop if response
        # is received.
        response = requests.request(
            method=method, url=url, headers=headers, **kwargs
        )

        # If status code is greater than 500, retry API call.
        if (
            response.status_code >= status.STATUS_INTERNAL_SERVER_ERROR
            and retry_count_server_error <= MAX_RETRIES_SERVER_ERROR
        ):
          retry_count_server_error = self.sleep_and_retry(
              retry_count_server_error, "Internal server error occurred."
          )
          continue

        if (
            response.status_code == status.STATUS_UNAUTHORIZED
            and retry_count_access_token <= MAX_RETRIES_ACCESS_TOKEN
            and access_token_info
        ):
          headers["Authorization"] = self.get_access_token(
              access_token_info,
              access_token_used_to_get_response=headers["Authorization"],
          )
          retry_count_access_token += 1
          continue

        # Convert response in JSON format.
        response_json = response.json()
        break

      # Retry API calls for Timeout and ConnectionError.
      except (requests.Timeout, requests.ConnectionError) as error:
        if retry_count_server_error <= MAX_RETRIES_SERVER_ERROR:
          if isinstance(error, requests.Timeout):
            error = "Timeout error occurred."
          else:
            error = "Connection error occurred."
          retry_count_server_error = self.sleep_and_retry(
              retry_count_server_error, error
          )
          continue
        raise error

      # If response is not in a JSON format, raise HTTP error.
      except requests.JSONDecodeError as error:
        raise requests.HTTPError(
            f"{response.status_code}: {response.reason}"
        ) from error

    # If status code is other than 200 raise HTTPError.
    if response.status_code != status.STATUS_OK:
      raise requests.HTTPError(
          f"{response.status_code}: {response.reason}. "
          f"{response_json.get('message')}"
      )
    return response_json

  def get_access_token(
      self,
      access_token_info: Dict[str, Any],
      access_token_used_to_get_response: Optional[str] = None,
  ) -> str:
    """Get access token for Armis API.

    Args:
      access_token_info (Dict[str,Any]): Access token information of Armis API.
      access_token_used_to_get_response (str, optional): Access token used to
        get response for Armis API. Defaults to None.

    Returns:
      str: Access token.
    """
    with LOCK:
      current_timestamp = datetime.datetime.now(
          datetime.timezone.utc
      ).timestamp()
      if (
          access_token_used_to_get_response == access_token_info[ACCESS_TOKEN]
          or access_token_info[ACCESS_TOKEN] == INITIAL_ACCESS_TOKEN
          or access_token_info[EXPIRATION_TIME] <= current_timestamp
      ):
        self.generate_access_token(access_token_info)
      return access_token_info[ACCESS_TOKEN]

  def generate_access_token(self, access_token_info: Dict[str, Any]):
    """Generate access token for Armis API.

    Args:
      access_token_info (Dict[str,Any]): Access token information of Armis API.
    """
    # Parameter required for access token endpoint.
    print("Generating new access token")
    params = {"secret_key": {self.secret_key}}

    # Headers required for access token endpoint.
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # Send API request for generating access token.
    response = self.http_request(
        method="POST",
        endpoint=ARMIS_ACCESS_TOKEN_ENDPOINT,
        data=params,
        headers=headers,
    )

    armis_auth_data = response.get("data", {})

    # Assigning access token value.
    access_token_info[ACCESS_TOKEN] = armis_auth_data.get("access_token")

    # Assigning expiration time.
    access_token_info[EXPIRATION_TIME] = datetime.datetime.strptime(
        armis_auth_data.get("expiration_utc"), ARMIS_API_DATE_FORMAT
    ).timestamp()

  def search_armis_api(
      self,
      armis_label: str,
      offset: int,
      access_token_info: Dict[str, Any],
      order_by: str = "time",
  ) -> Dict[str, Any]:
    """Fetch Armis data from the Armis platform.

    Args:
      armis_label (str): Type of the Armis data. Supported values: Alerts,
        Activities,Devices, and Vulnerabilities.
      offset (int): Offset for pagination.
      access_token_info (Dict[str,Any]): Access token information of Armis API.
      order_by (str): Sort order to fetch Armis data. Defaults to time.

    Returns:
      Dict[str, Any]: Response JSON from the API.
    """

    # Prepare parameter to fetch Armis data.
    aql = f"in:{armis_label}"
    if armis_label != TYPE_VULNERABILITIES:
      aql += self.create_time_frame_string()

    params = {
        "aql": aql,
        "length": PAGE_SIZE,
        "from": offset,
        "orderBy": order_by,
    }
    headers = {
        "Authorization": self.get_access_token(access_token_info),
        "Accept": "application/json",
    }
    # Send API request for fetch Armis data.
    response = self.http_request(
        method=METHOD_GET,
        endpoint=ARMIS_SEARCH_ENDPOINT,
        params=params,
        headers=headers,
        access_token_info=access_token_info,
    )

    return response
