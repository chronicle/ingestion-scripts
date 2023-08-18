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
"""A common module for fetching data from Dataminr platform."""

import os
import time
from typing import Any, Callable, Dict
from urllib import parse
import requests
from common import status
from common import utils


METHOD_GET = "GET"
ACCESS_TOKEN = "dmaToken"
EXPIRATION_TIME = "expire"

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


# Dataminr API endpoints.
DATAMINR_ACCESS_TOKEN_ENDPOINT = "auth/2/token"
DATAMINR_GET_LISTS_ENDPOINT = "account/2/get_lists"
DATAMINR_GET_ALERTS_ENDPOINT = "api/3/alerts"
DATAMINR_HEADER_ACCEPT = "application/json"
DATAMINR_ALERT_VERSION = "14"
DATAMINR_ALERT_PAGE_SIZE = "4"


# Dataminr base url
DATAMINR_SERVER_URL = "https://gateway.dataminr.com"

# Maximum number of retries to connect with Dataminr API.
MAX_RETRIES_SERVER_ERROR = 3

# Maximum number of retries to generate access token for Dataminr API.
MAX_RETRIES_ACCESS_TOKEN = 1

# Initial wait time before retrying an API call.
WAIT_TIME = 30

# Required proxy prefix.
PROXY_PREFIXES = [
    "http://",
    "https://",
]


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


class DataminrClient:
  """Dataminr Client to work with Dataminr API."""

  def __init__(
      self,
      client_id: str,
      client_secret: str,
  ) -> None:
    """Constructor for DataminrClient class.

    Args:
      client_id (str) : Client Id of Dataminr platform.
      client_secret (str): Client Secret to authenticate Dataminr platform.
    """
    self.server_url = DATAMINR_SERVER_URL
    self.client_id = client_id
    self.client_secret = client_secret
    self.__access_token_info = {}
    self.generate_access_token()
    # Handle Proxy URL
    self.handle_proxy()

  def handle_proxy(self) -> None:
    """Adds `http://` prefix to the proxy address in case it is missing."""
    https_proxy = utils.get_env_var("HTTPS_PROXY", required=False)
    if https_proxy:
      for prefix in PROXY_PREFIXES:
        if https_proxy.startswith(prefix):
          break
      else:
        os.environ["HTTPS_PROXY"] = "http://" + https_proxy

  def sleep_and_retry(
      self,
      wait_time: int,
      retry_count: int,
      error: str,
  ) -> int:
    """Holds the execution of the function for the time calculated from retry count and increases retry count.

    Args:
      wait_time (int) : wait time for function.
      retry_count (int): Retry count to calculate wait time of function.
      error (str): Error occurred while executing API call.

    Returns:
      int: Incremented retry count.
    """
    # Time to stop the function in seconds before retrying.
    stop_time = wait_time
    print(
        f"{error} API call to Dataminr platform failed. "
        f"Retrying after {stop_time} seconds."
    )

    # Stop the function for specified time.
    time.sleep(stop_time)

    # Increment retry count.
    return retry_count + 1

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
    # Join Dataminr server URL with required endpoint.
    url = parse.urljoin(self.server_url, endpoint)

    # Initialize retry count
    retry_count_server_error = 1
    retry_count_access_token = 1

    headers = kwargs.pop("headers")
    response = {}
    response_json = {}
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
              WAIT_TIME,
              retry_count_server_error,
              "Internal server error occurred.",
          )
          continue

        # If status code is greater than 429, retry API call.
        if (
            response.status_code == status.STATUS_TOO_MANY_REQUESTS
            and retry_count_server_error <= MAX_RETRIES_SERVER_ERROR
        ):
          wait_time = int(
              response.headers.get("x-rate-limit-reset") / 1000
          ) - int(time.time())
          retry_count_server_error = self.sleep_and_retry(
              wait_time,
              retry_count_server_error,
              "Too many request to server.",
          )
          continue

        if (
            response.status_code == status.STATUS_UNAUTHORIZED
            and retry_count_access_token <= MAX_RETRIES_ACCESS_TOKEN
            and self.__access_token_info
        ):
          headers["Authorization"] = f"Dmauth {self.get_token()}"
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
              WAIT_TIME, retry_count_server_error, error
          )
          continue
        raise error

    # If status code is other than 200 raise HTTPError.
    if response.status_code != status.STATUS_OK:
      raise requests.HTTPError(
          f"{response.status_code}:"
          f" {response_json.get('errors') if response_json.get('errors') else response_json.get('error') }. "
      )
    return response_json

  def get_token(self) -> str:
    """Get access token for Dataminr API.

    Returns:
      str: Access token.
    """
    current_epoch = time.time()
    if self.__access_token_info[EXPIRATION_TIME] <= current_epoch:
      self.generate_access_token()
    return self.__access_token_info[ACCESS_TOKEN]

  def generate_access_token(self) -> None:
    """Generate access token for Dataminr API."""
    # Parameter required for access token endpoint.
    print("Generating new access token")
    params = {
        "grant_type": "api_key",
        "client_id": {self.client_id},
        "client_secret": {self.client_secret},
    }

    # Headers required for access token endpoint.
    headers = {
        "Accept": DATAMINR_HEADER_ACCEPT,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # Send API request for generating access token.
    dataminr_auth_data = self.http_request(
        method="POST",
        endpoint=DATAMINR_ACCESS_TOKEN_ENDPOINT,
        data=params,
        headers=headers,
    )
    # Assigning access token value.
    self.__access_token_info[ACCESS_TOKEN] = dataminr_auth_data.get(
        ACCESS_TOKEN
    )

    # Assigning expiration time.
    self.__access_token_info[EXPIRATION_TIME] = dataminr_auth_data.get(
        EXPIRATION_TIME
    )

  def get_lists_api(self) -> Dict[str, Any]:
    """Fetch Dataminr lists from the Dataminr platform.

    Returns:
      Dict[str, Any]: Response JSON from the API.
    """

    # Prepare parameter to fetch dataminr data.
    headers = {
        "Authorization": f"Dmauth {self.__access_token_info[ACCESS_TOKEN]}",
        "Accept": DATAMINR_HEADER_ACCEPT,
    }
    # Send API request for fetch Dataminr lists.
    response = self.http_request(
        method=METHOD_GET, endpoint=DATAMINR_GET_LISTS_ENDPOINT, headers=headers
    )

    return response

  def get_alerts_api(
      self,
      params: Dict[Any, Any]
    ) -> Dict[str, Any]:
    """Fetch Dataminr alert from the Dataminr platform.

    Args:
      params(Dict): parameter to fetch alert from dataminr platform.

    Returns:
      Dict[str, Any]: Response JSON from the API.
    """

    # Prepare parameter to fetch dataminr data.
    headers = {
        "Authorization": f"Dmauth {self.__access_token_info[ACCESS_TOKEN]}",
        "Accept": DATAMINR_HEADER_ACCEPT,
    }

    # Prepare parameter to fetch dataminr data.
    params["alertversion"] = DATAMINR_ALERT_VERSION

    # Send API request for fetch Dataminr lists.
    response = self.http_request(
        method=METHOD_GET,
        endpoint=DATAMINR_GET_ALERTS_ENDPOINT,
        headers=headers,
        params=params,
    )

    return response
