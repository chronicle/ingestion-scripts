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
"""DomainTools Client class to get the enriched domains information."""

from typing import List

import domaintools
import requests

from common import utils

ERROR_MSG = "Error: {}"


class DomainToolClient:
  """DomainToolClient class which will enrich the domains."""

  def __init__(self, domaintool_user: str, domaintool_password: str) -> None:
    self.domaintool_user = domaintool_user
    self.domaintool_password = domaintool_password
    self.api = self.generate_api()

  def enrich(self, queued_domains: List[str]):
    """Enrich the domains and return them.

    Args:
        queued_domains (List): The domains to enrich from DomainTools

    Raises:
        NotAuthorizedException: When request in unauthorized
        ServiceUnavailableException: When the Query limits are exhausted
        requests.exceptions.ProxyError: Unable to connect to Proxy
        requests.exceptions.SSLError: Problem in SSL configuration
        Exception: Any other Exception raised
    Returns:
        List: List of enriched domains
    """

    try:
      response = self.api.iris_enrich(*list(queued_domains)).response()
      return response
    except domaintools.exceptions.NotAuthorizedException as e:
      utils.cloud_logging(
          "The credentials provided for DomainTools are invalid.",
          severity="ERROR",
      )
      raise e
    except domaintools.exceptions.ServiceUnavailableException as e:
      raise e
    except requests.exceptions.ProxyError as e:
      utils.cloud_logging(ERROR_MSG.format(e), severity="ERROR")
    except requests.exceptions.SSLError as e:
      utils.cloud_logging(ERROR_MSG.format(e), severity="ERROR")
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(ERROR_MSG.format(e), severity="ERROR")
      raise e

  def generate_api(self):
    """Generate the API Object for DomainTools.

    Returns:
        Any: Object of Generated API
    """
    return domaintools.API(
        self.domaintool_user,
        self.domaintool_password
    )
