# Copyright 2024 Google LLC
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
# pylint: disable=g-importing-member
# pylint: disable=invalid-name

"""Team Cymru Scout Client for API calls."""

import json
import sys

import requests
from requests.adapters import HTTPAdapter
from requests.adapters import Retry

from common import utils
from teamcymru_scout_constants import Endpoints
from teamcymru_scout_constants import IPS_CHUNKSIZE
from teamcymru_scout_constants import PROTOCOL
from teamcymru_scout_constants import Rest
from teamcymru_scout_constants import SIZE_THRESHOLD_BYTES
from teamcymru_scout_constants import VERIFY_SSL


def divide_chunks(_list, chunksize=IPS_CHUNKSIZE):
  """Divide a list into chunks of a specified size.

  Args:
    _list (list): The list to be divided into chunks.
    chunksize (int): The size of each chunk. Defaults to IPS_CHUNKSIZE.

  Yields:
    list: A chunk of the original list.
  """
  # Iterate over the list in chunks of the specified size
  for i in range(0, len(_list), chunksize):
    # Yield a chunk of the list
    yield _list[i : i + chunksize]  # noqa:E203


class TeamCymruScoutClient:
  """Team Cymru Scout Client for API calls."""

  def __init__(self, cymru_config):
    self.cymru_config = cymru_config
    self.auth_type = self.cymru_config.get("auth_type").strip()
    self.username = self.cymru_config.get("username", "").strip()
    self.password = self.cymru_config.get("password", "").strip()
    self.api_key = self.cymru_config.get("api_key", "").strip()
    self.threshold_size = str(
        self.cymru_config.get("threshold_size", "200")
    ).strip()  # noqa:E501
    self.verify = VERIFY_SSL
    self.session = self.__get_session()

  def get(
      self,
      endpoint,
      timeout=Rest.REQUEST_TIMEOUT,
      retry=True,
      params=None
  ):
    """Get API call to Cymru.

    Args:
      endpoint (str): The endpoint to make the request to.
      timeout (int, optional): The timeout for the request in seconds.Defaults
      to Rest.REQUEST_TIMEOUT.
      retry (bool, optional): Whether to retry the request
      if it fails.Defaults to True.
      params (dict, optional): The parameters for the request.Defaults to None.

    Returns:
      dict: The JSON response from the request.

    Raises:
      requests.exceptions.ProxyError: If there is an error
      with the configured proxy.
      requests.exceptions.SSLError: If there is an error
      with the SSL certificate.
      requests.exceptions.ConnectionError: If there is an error
      connecting to the server.
      requests.exceptions.HTTPError: If there is an HTTP error with the request.
      Exception: If there is any other error with the request.
    """  # noqa:E501
    try:
      full_url = f"{PROTOCOL}{Endpoints.CYMRU_SERVER_ADDRESS}{endpoint}"
      session = self.session if retry else self.__get_session(retries=0)

      utils.cloud_logging(
          "HttpRequest, type=Get, "
          f"endpoint={endpoint}, "
          f"timeout={timeout}, "
          f"retry={retry}, "
          f"verify={self.verify}, params={params}, initiating...",
          severity="DEBUG",
      )

      response = session.get(full_url, timeout=timeout, params=params)

      utils.cloud_logging(
          "HttpRequest, "
          "type=Get, "
          f"url={endpoint}, "
          f"status={response.status_code}",
          severity="DEBUG",
      )

      response.raise_for_status()

      # Return the JSON response
      return response.json()

    except requests.exceptions.ProxyError as e:
      # Log and raise an error if there is an error with the configured proxy
      error_msg = "Please verify the configured proxy."
      utils.cloud_logging(f"{error_msg}: {e}", severity="ERROR")
      raise type(e)(error_msg) from None

    except requests.exceptions.SSLError as e:
      # Log and raise an error if there is an error with the SSL certificate
      error_msg = (
          "Please verify the SSL certificate for the provided configuration."
      )
      utils.cloud_logging(f"{error_msg}: {e}", severity="ERROR")
      raise type(e)(error_msg) from None

    except requests.exceptions.ConnectionError as e:
      # Log and raise an error if there is an error connecting to the server
      error_msg = (
          "Could not connect to the server. "
          "Please verify the provided credentials or proxy configurations."
      )
      utils.cloud_logging(f"{error_msg}: {e}", severity="ERROR")
      raise type(e)(error_msg) from None

    except requests.exceptions.HTTPError as e:
      status_code = e.response.status_code

      # Log and raise an error if there is an HTTP error with the request
      if status_code == 401:
        error_msg = "Please verify the provided credentials."
        utils.cloud_logging(f"{error_msg}: {e}", severity="ERROR")
        raise type(e)(error_msg) from None

      if status_code == 429:
        error_msg = "Team Cymru Scout API Limit Exceeded."
        utils.cloud_logging(f"{error_msg}: {e}", severity="ERROR")
        # raise Exception
        raise type(e)(error_msg) from None

      utils.cloud_logging(f"HttpRequest Failed: {e}", severity="ERROR")
      raise

    except Exception as e:
      # Log and raise an error if there is any other error with the request
      utils.cloud_logging(f"HttpRequest Failed: {e}", severity="ERROR")
      raise

  def __get_session(  # pylint: disable=dangerous-default-value
      self,
      retries: int = Rest.MAX_RETRIES,
      backoff_factor: int = Rest.BACKOFF_FACTOR,
      status_forcelist: list = Rest.STATUS_FORCELIST,   # pylint: disable=g-bare-generic
      allowed_methods: list = [   # pylint: disable=g-bare-generic
          "GET",
          "POST",
          "HEAD",
      ],  # List of HTTP methods to retry
  ) -> requests.Session:
    """Returns a Session object with the specified configuration.

    Args:
      retries (int): Number of retries for the request. Default is 5.
      backoff_factor (int): Factor to calculate the time to wait between
      retries. Default is 60.
      status_forcelist (list): List of status codes to force retry.
      Default is Rest.STATUS_FORCELIST.
      allowed_methods (list): List of HTTP methods to retry.
      Default is ["GET", "POST", "HEAD"].

    Returns:
      requests.Session: Session object with the specified configuration.
    """  # noqa:E501
    session = requests.Session()
    session.verify = self.verify

    if self.auth_type == "basic_auth":
      session.auth = (self.username, self.password)
    else:
      session.headers.update({"Authorization": f"Token {self.api_key}"})

    if retries == 0:
      return session

    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=allowed_methods,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    utils.cloud_logging(
        f"Session initialized with retries={retries}, "
        f"backoff_factor={backoff_factor}, "
        f"status_forcelist={status_forcelist}, "
        f"allowed_methods={allowed_methods}",
        severity="DEBUG",
    )

    return session

  def get_usage(self, retry=True):
    """Get usage details from Team Cymru Scout API.

    Args:
      retry (bool, optional): Whether to retry the request if it fails.
      Defaults to True.

    Returns:
      dict: JSON response containing usage details.

    Raises:
      Exception: If there is an error while getting usage details.
    """  # noqa:E501
    try:
      utils.cloud_logging("Checking Usage of API.", severity="INFO")

      response = self.get(endpoint=Endpoints.USAGE, retry=retry)
      return response
    except Exception as e:
      utils.cloud_logging(
          f"Error occurred while getting usage details: {e}",
          severity="ERROR",
      )
      raise

  def get_foundation_ip_data(self, ip_list):
    """Get IP Foundation data.

    Args:
      ip_list (list): List of IP addresses.

    Yields:
      dict: Dictionaries containing IP Foundation data.

    Raises:
      Exception: If there is an error while getting IP Foundation data.
    """
    try:
      utils.cloud_logging(
          "Started collecting IP Foundation data.", severity="INFO"
      )

      for list_indicator in divide_chunks(ip_list):
        response = self.get(
            endpoint=Endpoints.IP_FOUNDATION,
            params={"ips": ",".join(ips for ips in list_indicator)},
        )
        if response.get("data") is not None:
          yield from response.get("data", [])

    except Exception as e:
      utils.cloud_logging(
          f"Error occurred while getting foundation IP data: {e}",
          severity="ERROR",
      )
      raise

  def get_details_domain_data(self, domain_list):
    """Retrieves Domain Details data for each domain in the list.

    Args:
      domain_list (list): List of domain names.

    Yields:
      dict: Dictionaries containing Domain Details data.

    Raises:
      Exception: If there is an error while getting Domain Details data.
    """
    try:
      utils.cloud_logging(
          "Started collecting Domain Details data.", severity="INFO"
      )

      for domain in domain_list:
        response = self.get(
            endpoint=Endpoints.DOMAIN_DETAILS, params={"query": domain}
        )
        if response.get("ips") is not None:
          response["ips"] = [
              {**ip_response, "query": response.get("query", "")}
              for ip_response in response.get("ips", [])
          ]
          yield from response.get("ips", [])
    except Exception as e:
      utils.cloud_logging(
          f"Error occurred while getting domain details data: {e}",
          severity="ERROR",
      )
      raise

  def get_details_ip_data(self, ip_addresses, is_live_investigation=False):
    """Retrieve IP details for each IP in the list.

    Args:
      ip_addresses (list): List of IP addresses.
      is_live_investigation (bool): Flag indicating if
      it's a live investigation.

    Yields:
      dict: Dictionaries containing IP details.

    Raises:
      Exception: If there is an error while getting IP details.
    """
    utils.cloud_logging("Started collecting IP details.", severity="INFO")

    sections = "identity,comms,pdns,open_ports,x509,fingerprints,whois,summary"

    if is_live_investigation:
      sections += ",proto_by_ip,top_tags_by_ip,top_services_by_ip,top_country_codes_by_ip,top_asns_by_ip"   # pylint: disable=line-too-long

    for ip_address in ip_addresses:
      try:
        response = self.get(
            endpoint=Endpoints.IP_DETAILS.format(ip=ip_address),
            params={"size": self.threshold_size, "sections": sections},
        )
        if sys.getsizeof(json.dumps(response)) < SIZE_THRESHOLD_BYTES:
          yield response
        else:
          utils.cloud_logging(
              f"Skipping enrichment for IP {ip_address} due to its response size exceeding the limit of 0.95 MB. "  # pylint: disable=line-too-long
              "Try again by setting a smaller threshold size in the environment variable IP_ENRICHMENT_SIZE.",  # pylint: disable=line-too-long
              severity="WARNING",
          )
      except Exception as e:  # pylint: disable=broad-except
        utils.cloud_logging(
            f"Skipping {ip_address} from enrichment due to an unexpected "
            f"issue has occurred while getting IP details: {e}",
            severity="WARNING",
        )
