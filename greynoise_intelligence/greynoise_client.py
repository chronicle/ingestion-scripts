# Copyright 2025 Google LLC
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

"""GreyNoise Utility for SDK calls."""

from typing import Any

from greynoise import api

from common import utils
import constant


class GreyNoiseUtility:
  """A GreyNoise utility for handling SDK operations."""

  def __init__(self, api_key: str) -> None:
    """Initialize the instance.

    Args:
        api_key: API Key for GreyNoise
    """
    self.api_config = api.APIConfig(
        api_key=api_key,
        integration_name=constant.GREYNOISE_INTEGRATION_NAME,
    )
    self.greynoise_client = api.GreyNoise(self.api_config)
    utils.cloud_logging("GreyNoise Client Initialized.")

  def gnql_query(
      self,
      query: str,
      scroll: str | None = None,
      page_size: int = constant.GNQL_PAGE_SIZE,
  ) -> dict[str, Any] | tuple:  # pylint: disable=g-bare-generic
    """Fetch GNQL query result from GreyNoise.

    Args:
        query: GNQL query string
        scroll: Scroll token for pagination
        page_size: Number of results per page

    Returns:
        Dictionary containing query results and metadata
    """
    return self.greynoise_client.query(  # pytype: disable=bad-return-type
        query,
        exclude_raw=True,
        size=page_size,
        scroll=scroll,
    )

  def lookup_ips(self, ip_list: list[str]) -> list[dict[str, Any]] | None:
    """Fetch IP Lookup result from GreyNoise.

    Args:
        ip_list: List of IP addresses to lookup

    Returns:
        List of dictionaries containing IP intelligence data
    """
    return self.greynoise_client.ip_multi(ip_list, include_invalid=True)
