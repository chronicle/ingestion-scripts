# Copyright 2026 Google LLC
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
"""Cyjax API client for fetching and ingesting IOCs."""

import datetime
import json
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib

import requests

from common import ingest_v1
from common import utils
import constant as con
import exception_handler
import utility


class CyjaxClient:
  """Cyjax API client for fetching and ingesting IOCs.

  Attributes:
    bucket_name: GCS bucket name for checkpoints.
    historical_ioc_duration: Days of historical data to fetch.
    enable_enrichment: Enable enrichment API calls.
    query: Filter query for indicators.
    indicator_type: Pipe-separated indicator types.
  """

  def __init__(
      self,
      api_token: str,
      bucket_name: str,
      historical_ioc_duration: int,
      enable_enrichment: bool = False,
      query: Optional[str] = None,
      indicator_type: Optional[str] = None,
  ) -> None:
    """Initialize Cyjax API client.

    Args:
        api_token: Cyjax API authentication token.
        bucket_name: GCS bucket name for checkpoints.
        historical_ioc_duration: Days of historical data to fetch.
        enable_enrichment: Enable enrichment API calls.
        query: Filter query for indicators.
        indicator_type: Pipe-separated indicator types.
    """
    self.__api_key = api_token
    self.bucket_name = bucket_name
    self.historical_ioc_duration = historical_ioc_duration
    self.enable_enrichment = enable_enrichment
    self.query = query
    self.indicator_type = indicator_type

  @classmethod
  def _get_response_message(cls, response: requests.Response) -> str:
    """Extract message from API response body.

    Args:
        response: API response object.

    Returns:
        str: The message from the response JSON, or the raw
            response text if JSON parsing fails.
    """
    try:
      json_data = response.json()
      if isinstance(json_data, dict):
        return json_data.get("message", response.text)
      return response.text
    except (ValueError, json.decoder.JSONDecodeError):
      return response.text

  def _request_cyjax(
      self,
      method: str,
      endpoint: str,
      params: Optional[Dict[str, Any]] = None,
      data: Optional[Dict[str, Any]] = None,
  ) -> requests.Response:  # pylint: disable=g-bare-generic
    """Make HTTP request to Cyjax API.

    Args:
        method: HTTP method (GET, POST, etc.).
        endpoint: API endpoint path.
        params: Query parameters.
        data: Request body data.

    Returns:
        requests.Response: API response object.
    """
    if data is None:
      data = {}
    if params is None:
      params = {}
    if not self.__api_key:
      raise exception_handler.ApiKeyNotFoundException()
    url = f"{con.BASE_URI}/{endpoint}"
    response = requests.Response()
    for attempt in range(con.RETRY_COUNT):
      response = requests.api.request(
          method=method,
          url=url,
          params=params,
          data=data,
          headers={
              con.HEADER_AUTHORIZATION: f"Bearer {self.__api_key}",
              con.HEADER_USER_AGENT: con.USER_AGENT,
          },
          timeout=con.TIMEOUT,
          verify=True,
      )

      if response.status_code == 200:
        return response

      response_message = self._get_response_message(response)

      if response.status_code == 400:
        utils.cloud_logging(
            con.API_RESPONSE_LOG_MESSAGE.format(
                endpoint=endpoint,
                status_code=response.status_code,
                response_message=response_message,
            ),
            severity="ERROR",
        )
        raise exception_handler.ResponseErrorException(
            response.status_code,
            f"Bad Request: {response_message}",
        )
      elif response.status_code == 401:
        utils.cloud_logging(
            con.API_RESPONSE_LOG_MESSAGE.format(
                endpoint=endpoint,
                status_code=response.status_code,
                response_message=response_message,
            ),
            severity="ERROR",
        )
        raise exception_handler.UnauthorizedException()
      elif response.status_code == 403:
        utils.cloud_logging(
            con.API_RESPONSE_LOG_MESSAGE.format(
                endpoint=endpoint,
                status_code=response.status_code,
                response_message=response_message,
            ),
            severity="ERROR",
        )
        raise exception_handler.ForbiddenException()
      elif response.status_code == 404:
        utils.cloud_logging(
            con.API_RESPONSE_LOG_MESSAGE.format(
                endpoint=endpoint,
                status_code=response.status_code,
                response_message=response_message,
            ),
            severity="ERROR",
        )
        raise exception_handler.NotFoundException()
      elif response.status_code == 422:
        utils.cloud_logging(
            con.API_RESPONSE_LOG_MESSAGE.format(
                endpoint=endpoint,
                status_code=response.status_code,
                response_message=response_message,
            ),
            severity="ERROR",
        )
        raise exception_handler.ValidationException(response.json())
      elif response.status_code == 429:
        if attempt < con.RETRY_COUNT - 1:
          utils.cloud_logging(
              f"Rate limit hit (429) for endpoint '{endpoint}'. "
              f"Retrying in {con.RETRY_DELAY} seconds... "
              f"(Attempt {attempt + 1}/{con.RETRY_COUNT})",
              severity="WARNING",
          )
          time.sleep(con.RETRY_DELAY)
          continue
        utils.cloud_logging(
            f"Rate limit hit (429) for endpoint '{endpoint}'. "
            f"(Attempt {attempt + 1}/{con.RETRY_COUNT}) "
            "Max retries exceeded.",
            severity="ERROR",
        )
        raise exception_handler.TooManyRequestsException()
      elif response.status_code >= 500:
        if attempt < con.RETRY_COUNT - 1:
          utils.cloud_logging(
              f"Server error ({response.status_code}) for endpoint "
              f"'{endpoint}'. Retrying in {con.RETRY_DELAY} "
              f"seconds... (Attempt {attempt + 1}/{con.RETRY_COUNT})",
              severity="WARNING",
          )
          time.sleep(con.RETRY_DELAY)
          continue
        utils.cloud_logging(
            f"Server error ({response.status_code}) for endpoint "
            f"'{endpoint}' (Attempt {attempt + 1}/{con.RETRY_COUNT})."
            " Max retries exceeded.",
            severity="ERROR",
        )
        raise exception_handler.ResponseErrorException(
            response.status_code,
            f"Server error ({response.status_code}). Max retries exceeded.",
        )
      elif response.status_code != 200 and response.status_code != 201:
        utils.cloud_logging(
            con.API_RESPONSE_LOG_MESSAGE.format(
                endpoint=endpoint,
                status_code=response.status_code,
                response_message=response_message,
            ),
            severity="ERROR",
        )
        try:
          json_data = response.json()
          raise exception_handler.ResponseErrorException(
              response.status_code,
              (json_data["message"] if "message" in json_data else "Unknown"),
          )
        except json.decoder.JSONDecodeError as exc:
          raise exception_handler.ResponseErrorException(
              response.status_code,
              f"Error parsing response: {response.text}",
          ) from exc

    return response

  def _get_indicators_of_compromise(
      self,
      page: Optional[int] = None,
      per_page: Optional[int] = None,
      since: Optional[str] = None,
      until: Optional[str] = None,
      query: Optional[str] = None,
      ioc_type: Optional[str] = None,
  ) -> requests.Response:  # pylint: disable=g-bare-generic
    """Fetch indicators of compromise from Cyjax API.

    Args:
        page: Page number.
        per_page: Items per page.
        since: Start datetime in ISO8601 format.
        until: End datetime in ISO8601 format.
        query: Filter query.
        ioc_type: Indicator type filter.

    Returns:
        API response with indicators.
    """
    params = {}
    if page is not None:
      params["page"] = page
    if per_page is not None:
      params["per-page"] = per_page
    if since:
      params["since"] = since
    if until:
      params["until"] = until
    if query:
      params["query"] = query
    if ioc_type:
      params["type"] = ioc_type

    return self._request_cyjax(
        "GET", con.ENDPOINT_INDICATOR_OF_COMPROMISE, params=params
    )

  def _get_indicator_enrichment(
      self, value: str
  ) -> Dict[str, Any]:  # pylint: disable=g-bare-generic
    """Get enrichment information for a specific indicator.

    Args:
        value: The indicator value to enrich

    Returns:
        Enrichment data for the indicator
    """
    try:
      response = self._request_cyjax(
          "GET",
          con.ENDPOINT_INDICATOR_ENRICHMENT,
          params={"value": value},
      )
      enrichment_data = response.json()
      utils.cloud_logging(
          f"Successfully enriched indicator: {value}.",
          severity="DEBUG",
      )
      return enrichment_data
    except Exception as e:  # pylint: disable=broad-exception-caught
      utils.cloud_logging(
          f"Failed to fetch enrichment for indicator '{value}': {repr(e)}.",
          severity="WARNING",
      )
      return {}

  def _create_end_time(
      self, indicator: Dict[str, Any]
  ) -> None:  # pylint: disable=g-bare-generic
    """Create end time as current time + 7 days in ISO8601 format.

    Args:
        indicator: Indicator data to add custom_end_time field
    """
    current_time = datetime.datetime.now(datetime.timezone.utc)
    end_time = current_time + datetime.timedelta(days=7)
    indicator[con.END_TIME_FIELD_NAME] = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

  def _get_indicators_page(
      self, since: str, until: str, page: int, params_config: Dict[str, Any]
  ) -> Tuple[
      List[Dict[str, Any]], bool, Optional[int]
  ]:  # pylint: disable=g-bare-generic
    """Get a single page of indicators from Cyjax.

    Args:
        since (str): Start datetime in ISO8601 format
        until (str): End datetime in ISO8601 format
        page (int): Page number to fetch
        params_config (dict): Configuration parameters

    Returns:
        A tuple (indicators_list, has_next_page, next_page_number), where
        indicators_list is a list of indicator dictionaries, has_next_page is
        a boolean indicating if there are more pages, and next_page_number is
        the next page number to fetch or None if there is no next page.
    """
    try:
      response = self._get_indicators_of_compromise(
          page=page,
          per_page=con.PAGE_SIZE,
          since=since,
          until=until,
          query=params_config.get("query"),
          ioc_type=params_config.get("type"),
      )
      indicators = response.json()

      has_next = (
          "next" in response.links if hasattr(response, "links") else False
      )
      next_page = None

      if has_next:
        parsed = urllib.parse.urlparse(response.links["next"]["url"])
        next_page = int(urllib.parse.parse_qs(parsed.query)["page"][0])

      return indicators, has_next, next_page
    except Exception as e:
      error_message = f"Error fetching indicators page {page}: {repr(e)}"
      utils.cloud_logging(error_message, severity="ERROR")
      raise exception_handler.CyjaxException(error_message) from e

  def _ingest_indicators(
      self,
      indicators: List[Dict[str, Any]],
  ) -> int:  # pylint: disable=g-bare-generic
    """Ingest indicators into Google SecOps.

    Args:
        indicators: List of indicators to ingest.

    Returns:
        Count of indicators ingested.
    """
    if not indicators:
      return 0

    last_run_initiation_time = utility.get_last_checkpoint(
        self.bucket_name,
        con.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
    )

    if last_run_initiation_time:
      try:
        last_run_time = float(last_run_initiation_time)
        current_time = time.time()
        time_diff_minutes = (current_time - last_run_time) / 60

        if time_diff_minutes >= con.INGESTION_TIME_CHECK_MINUTES:
          utils.cloud_logging(
              "Execution time has exceeded "
              f"{con.INGESTION_TIME_CHECK_MINUTES} minutes "
              f"(running for {time_diff_minutes:.2f} minutes). "
              "Raising RunTimeExceeded exception.",
              severity="WARNING",
          )
          raise exception_handler.RunTimeExceeded(
              "Execution time exceeded "
              f"{con.INGESTION_TIME_CHECK_MINUTES} minutes"
          )
      except (ValueError, TypeError) as e:
        utils.cloud_logging(
            f"Error checking execution time: {repr(e)}. "
            "Continuing with ingestion.",
            severity="WARNING",
        )

    try:
      utils.cloud_logging(
          f"Ingesting {len(indicators)} indicators into Google SecOps."
      )
      ingest_v1.ingest(indicators, con.GOOGLE_SECOPS_DATA_TYPE)
      utils.cloud_logging(
          f"Successfully ingested {len(indicators)} indicators."
      )
      return len(indicators)
    except Exception as e:
      utils.cloud_logging(
          f"Ingestion failed: {repr(e)}.",
          severity="ERROR",
      )
      raise

  def fetch_and_ingest_indicators(self) -> None:
    """Fetch indicators from Cyjax and ingest into Google SecOps."""
    since, until, starting_page, params_config = (
        utility.get_checkpoints_and_config(
            self.bucket_name,
            self.historical_ioc_duration,
            self.query,
            self.indicator_type,
        )
    )

    utils.cloud_logging(
        f"Starting indicator ingestion. Since: {since}, Until: {until}, "
        f"Starting Page: {starting_page}."
    )

    page = starting_page
    total_ingested = 0

    while True:
      utils.cloud_logging(f"Fetching page {page}...")

      indicators_data, has_next, next_page = self._get_indicators_page(
          since, until, page, params_config
      )

      if not indicators_data or len(indicators_data) == 0:
        utils.cloud_logging(
            f"No more indicators found on page {page}. "
            "Completed window processing."
        )
        utility.set_last_checkpoint(
            self.bucket_name,
            con.CHECKPOINT_KEY_PAGE_NUMBER,
            0,
        )
        break

      utils.cloud_logging(
          f"Retrieved {len(indicators_data)} indicators from page {page}."
      )

      processed_indicators = []
      for indicator in indicators_data:
        indicator_value = indicator.get("value")
        if not indicator_value:
          utils.cloud_logging(
              f"Indicator missing 'value' field, skipping: {indicator}",
              severity="WARNING",
          )
          continue

        if self.enable_enrichment:
          enrichment = self._get_indicator_enrichment(indicator_value)
          combined_data = {**indicator, "enrichment": enrichment}
          self._create_end_time(combined_data)
          processed_indicators.append(combined_data)
        else:
          self._create_end_time(indicator)
          processed_indicators.append(indicator)

      if processed_indicators:
        ingested_count = self._ingest_indicators(processed_indicators)
        utils.cloud_logging(
            "Successfully ingested "
            f"{ingested_count} indicators from page {page}."
        )
        total_ingested += ingested_count

      # Check if there's a next page
      if not has_next:
        utils.cloud_logging(
            "No next page available. Completed window processing."
        )
        utility.set_last_checkpoint(
            self.bucket_name,
            con.CHECKPOINT_KEY_PAGE_NUMBER,
            0,
        )
        break

      # Update checkpoint with next page number
      page = next_page if next_page else page + 1
      utility.set_last_checkpoint(
          self.bucket_name,
          con.CHECKPOINT_KEY_PAGE_NUMBER,
          page,
      )

    utils.cloud_logging(
        f"Indicator ingestion completed. Total ingested: {total_ingested}."
    )
