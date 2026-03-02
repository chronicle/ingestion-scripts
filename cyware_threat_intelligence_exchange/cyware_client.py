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
#


"""Cyware CTIX Client for API calls."""

import base64
import datetime
import hashlib
import hmac
import itertools
import time
import traceback
from typing import Any
from urllib.parse import quote  # pylint: disable=g-importing-member
from urllib.parse import urlencode  # pylint: disable=g-importing-member

import requests

from common import ingest_v1
from common import utils
import constant
import exception_handler
import utility


def extract_ioc_values(
        indicators_data: list[dict[str, Any]]
) -> list[str]:
  """Extract IOC values from indicators data for bulk lookup.

  Args:
      indicators_data: List of indicator dictionaries

  Returns:
      List of unique IOC values (names)
  """
  if not indicators_data:
    return []

  ioc_values = set()
  for indicator in indicators_data:
    ioc_value = indicator.get("sdo_name", "")
    if ioc_value:
      ioc_values.add(ioc_value)
  return list(ioc_values)


def get_start_time(lookback_days: str | None = None) -> int:
  """Get start time as epoch timestamp based on lookback days.

  Args:
      lookback_days: Number of days to look back (string from env)

  Returns:
      Epoch timestamp for the start time
  """
  if lookback_days:
    try:
      days = int(lookback_days)
      if days < 0:
        raise ValueError(
            "lookback_days must be non-negative, got %s" % days
        )
      start_time = datetime.datetime.now(
          datetime.timezone.utc
      ) - datetime.timedelta(days=days)
      epoch_time = int(start_time.timestamp())
      start_time_str = start_time.strftime(
          constant.TIMESTAMP_PATTERN
      )
      utils.cloud_logging(
          "Calculated start time from lookback_days (%s): "
          "%s" % (days, start_time_str)
      )
      return epoch_time
    except (ValueError, TypeError) as e:
      default_days = constant.DEFAULT_VALUES.get(
          constant.ENV_INDICATOR_LOOKBACK_DAYS, 7
      )
      utils.cloud_logging(
          "Error parsing lookback_days '%s': %s. "
          "Using default %s days." % (
              lookback_days, e, default_days
          ),
          severity="WARNING",
      )

  default_days = constant.DEFAULT_VALUES.get(
      constant.ENV_INDICATOR_LOOKBACK_DAYS, 7
  )
  start_time = datetime.datetime.now(
      datetime.timezone.utc
  ) - datetime.timedelta(days=default_days)
  epoch_time = int(start_time.timestamp())
  start_time_str = start_time.strftime(constant.TIMESTAMP_PATTERN)
  utils.cloud_logging(
      "Using default lookback of %s days, "
      "Calculated start time : %s" % (default_days, start_time_str)
  )
  return epoch_time


class CTIXClient:
  """A client for interacting with the Cyware CTIX API."""

  def __init__(
      self,
      base_url: str,
      access_id: str,
      secret_key: str,
      tenant_name: str,
      enrichment_enabled: bool = False,
      label_name: str | None = None,
      bucket_name: str | None = None,
      lookback_days: str | None = None,
  ) -> None:
    """Initialize CTIX Client with required credentials."""
    self.base_url = base_url.rstrip("/")
    self.access_id = access_id
    self.secret_key = secret_key
    self.tenant_name = tenant_name
    self.label_name = label_name
    self.enrichment_enabled = enrichment_enabled
    self.bucket_name = bucket_name
    self.lookback_days = lookback_days

  @exception_handler.exception_handler(action_name="CTIX REST API")
  def _ctix_rest_api(self, method, url, params, json_body=None):
    """Make API call to CTIX.

    Args:
        method (str): HTTP method (GET or POST)
        url (str): Full URL to call
        params (dict): Query parameters with auth
        json_body (dict, optional): JSON body for POST requests

    Returns:
        dict: Dict containing response if call is successful.
    """
    encoded_label_name = ""
    if params.get("label_name"):
      safe_chars = constant.LABEL_NAME_SAFE_CHARS
      encoded_label_name = quote(params.get("label_name", ""), safe=safe_chars)
      del params["label_name"]
    encoded_params = urlencode(params)
    if encoded_label_name:
      encoded_url = f"{url}?{encoded_params}&label_name={encoded_label_name}"
    else:
      encoded_url = f"{url}?{encoded_params}"

    response = requests.request(
        method=method,
        url=encoded_url,
        headers={"User-Agent": constant.USER_AGENT_NAME},
        json=json_body,
        timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
        verify=True,
    )
    return {"response": response, "status": True, "retry": False}

  def _parse_and_handle_response(self, return_dict, result, fetch_type):
    """Parse and handle the API response.

    Args:
        return_dict (dict): dict containing the return values
        result (dict): api response
        fetch_type (str): to identify which api call response is passed

    Returns:
        dict: api call response
    """
    try:
      response = result["response"]
      return_dict["response"] = response
      if response.status_code == 200:
        return_dict["data"] = response.json()
        return_dict["status"] = True
      elif response.status_code == 401:
        return_dict["status"] = False
        return_dict["error"] = "Invalid API credentials."
        utils.cloud_logging(
            "Failed to fetch %s, received status code - %s. "
            "Response - %s." % (
                fetch_type, response.status_code, response.text
            ),
            severity="ERROR",
        )
      elif response.status_code == 403:
        return_dict["status"] = False
        return_dict["error"] = f"Access denied for {fetch_type}."
        utils.cloud_logging(
            "Failed to fetch %s, received status code - %s. "
            "Response - %s." % (
                fetch_type, response.status_code, response.text
            ),
            severity="ERROR",
        )
      elif response.status_code == 429:
        return_dict["status"] = False
        return_dict["retry"] = True
        return_dict["error"] = (
            f"Rate limit exceeded while fetching {fetch_type}."
        )
        utils.cloud_logging(
            "Failed to fetch %s, received status code - %s. "
            "Response - %s." % (
                fetch_type, response.status_code, response.text
            ),
            severity="ERROR",
        )
      elif response.status_code >= 500:
        return_dict["status"] = False
        return_dict["retry"] = True
        return_dict["error"] = f"Server error while fetching {fetch_type}."
        utils.cloud_logging(
            "Failed to fetch %s, received status code - %s. "
            "Response - %s." % (
                fetch_type, response.status_code, response.text
            ),
            severity="ERROR",
        )
      else:
        return_dict["status"] = False
        return_dict["error"] = (
            f"Failed to fetch {fetch_type}, status code: {response.status_code}"
        )
        utils.cloud_logging(
            "Failed to fetch %s, received status code - %s. "
            "Response - %s." % (
                fetch_type, response.status_code, response.text
            ),
            severity="ERROR",
        )
    except ValueError as ex:
      utils.cloud_logging(
          "Failed to parse response: %s. Error: %s\nTraceback: "
          "%s" % (
              result["response"].text, ex, traceback.format_exc()
          ),
          severity="ERROR",
      )
    except Exception as ex:  # pylint: disable=broad-except
      response = result.get("response")
      utils.cloud_logging(
          "Error handling response. Response: %s. Error: "
          "%s\nTraceback: %s" % (
              response.text if response else "N/A",
              repr(ex),
              traceback.format_exc()
          ),
          severity="ERROR",
      )
    return return_dict

  def _log_and_sleep_before_retry(self, sleep_time=constant.DEFAULT_SLEEP_TIME):
    """Log a retry message and sleep before retrying.

    Args:
        sleep_time (int): The time in seconds to sleep before retrying.
    """
    utils.cloud_logging(constant.RETRY_MESSAGE.format(delay=sleep_time))
    time.sleep(sleep_time)

  def get_ctix_auth_params(
      self, access_id: str, secret_key: str
  ) -> dict[str, str | int]:
    """Generate authentication query parameters for CTIX API requests.

    Args:
        access_id: The API Access ID.
        secret_key: The API Secret Key.

    Returns:
        dict[str, str | int]: A dictionary containing the authentication
        parameters: "AccessID", "Expires", and "Signature".
    """
    expires = int(time.time()) + constant.SIGNATURE_EXPIRY_SECONDS
    to_sign = f"{access_id}\n{expires}"
    signature = base64.b64encode(
        hmac.new(
            secret_key.encode("utf-8"),
            to_sign.encode("utf-8"),
            hashlib.sha1,
        ).digest()
    ).decode("utf-8")
    return {
        "AccessID": access_id,
        "Expires": expires,
        "Signature": signature,
    }

  def make_api_call(
      self,
      method: str,
      url: str,
      params: dict[str, Any] | None = None,
      json_body: dict[str, Any] | None = None,
      fetch_type: str = "CTIX Data",
  ) -> dict[str, Any]:
    """Make REST API call to CTIX with retry logic.

    Args:
        method (str): HTTP method (GET or POST)
        url (str): Full URL to call
        params (dict, optional): Query parameters
        json_body (dict, optional): JSON body for POST requests
        fetch_type (str): Type of data being fetched for logging

    Returns:
        dict: Response with status, data, and error fields
    """
    auth_params = self.get_ctix_auth_params(self.access_id, self.secret_key)
    all_params = {**auth_params, **(params or {})}

    return_dict = {"status": False, "data": {}, "error": "", "retry": False}
    count = 0
    result = {}
    while count < constant.RETRY_COUNT:
      result = self._ctix_rest_api(method, url, all_params, json_body)

      if result.get("retry") or not result.get("status"):
        if result.get("retry"):
          count += 1
          if count == constant.RETRY_COUNT:
            return_dict.update(result)
            return return_dict
          self._log_and_sleep_before_retry()
          continue
        return result

      result = self._parse_and_handle_response(return_dict, result, fetch_type)

      if result["status"]:
        return result
      if not result.get("retry", False):
        return result
      count += 1
      if count == constant.RETRY_COUNT:
        break
      self._log_and_sleep_before_retry()

    return_dict.update(result)
    return return_dict

  def get_saved_result_set_page(
      self, from_timestamp: int, to_timestamp: int, page: int
  ) -> dict[str, Any]:
    """Get a single page of saved result set data from CTIX.

    Args:
        from_timestamp (int): Epoch timestamp to fetch data from
        to_timestamp (int): Epoch timestamp to fetch data to
        page (int): Page number to fetch

    Returns:
        dict: Response containing indicators and pagination info
    """
    url = f"{self.base_url}/{constant.SAVED_RESULT_SET_ENDPOINT}"
    params = {
        "page_size": constant.PAGE_SIZE_FOR_SAVED_RESULT,
        "page": page,
        "from_timestamp": from_timestamp,
        "to_timestamp": to_timestamp,
        "version": constant.CTIX_API_VERSION,
    }

    if self.label_name:
      escaped_label = self.label_name.replace("\\", "\\\\").replace('"', '\\"')
      params["label_name"] = escaped_label

    response = self.make_api_call("GET", url, params=params)

    if not response.get("status"):
      error_message = (
          f"Error fetching saved result set page {page}: "
          f"{response.get('error')}"
      )
      raise exception_handler.CywareCTIXException(error_message)

    return response.get("data", {})

  def _deduplicate_indicators(
      self, indicators: list[dict[str, Any]]
  ) -> list[dict[str, Any]]:
    """Deduplicate indicators by keeping only the latest based on ctix_modified.

    Args:
        indicators: List of indicator dictionaries

    Returns:
        Deduplicated list with only the latest version of each indicator
    """
    if not indicators:
      return []

    latest_indicators = {}
    missing_modified_count = 0
    missing_sdo_name_count = 0

    for indicator in indicators:
      sdo_name = indicator.get("sdo_name")
      ctix_modified = indicator.get("ctix_modified")

      if not sdo_name:
        utils.cloud_logging(
            "Indicator missing sdo_name field, skipping: %s" % (
                indicator.get("id"),
            ),
            severity="WARNING",
        )
        missing_sdo_name_count += 1
        continue

      if not ctix_modified:
        utils.cloud_logging(
            "Indicator %s is missing ctix_modified field" % (sdo_name,),
            severity="WARNING",
        )
        missing_modified_count += 1
        if sdo_name not in latest_indicators:
          latest_indicators[sdo_name] = indicator
        continue

      if sdo_name in latest_indicators:
        existing_modified = latest_indicators[sdo_name].get("ctix_modified")
        if existing_modified and ctix_modified > existing_modified:
          latest_indicators[sdo_name] = indicator
      else:
        latest_indicators[sdo_name] = indicator

    log_msgs = []
    if missing_sdo_name_count > 0:
      log_msgs.append(
          f"Found {missing_sdo_name_count} indicators without sdo_name field"
      )
    if missing_modified_count > 0:
      log_msgs.append(
          f"Found {missing_modified_count} indicators "
          "without ctix_modified field"
      )
    if log_msgs:
      utils.cloud_logging(", ".join(log_msgs), severity="WARNING")

    return list(latest_indicators.values())

  def _get_checkpoints_and_timestamps(self) -> tuple[int, int, int]:
    """Load checkpoints and calculate from/to timestamps with validation.

    Returns:
        A tuple of (from_timestamp, to_timestamp, starting_page) where
        from_timestamp is the start epoch time, to_timestamp is the end
        epoch time, and starting_page is the page number to resume from.
    """
    last_from_timestamp = utility.get_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
    )
    last_to_timestamp = utility.get_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_TO_TIMESTAMP,
    )
    last_page_number = utility.get_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_PAGE_NUMBER,
    )

    current_time = int(datetime.datetime.now(
        datetime.timezone.utc).timestamp())

    if last_from_timestamp:
      try:
        from_timestamp = int(last_from_timestamp)
        if from_timestamp <= 0:
          utils.cloud_logging(
              "Invalid from_timestamp checkpoint: %s "
              "(non-positive). Resetting to default based on "
              "lookback days." % (from_timestamp,),
              severity="WARNING",
          )
          from_timestamp = get_start_time(self.lookback_days)
        elif from_timestamp > current_time:
          utils.cloud_logging(
              "Invalid from_timestamp checkpoint: %s (future "
              "timestamp). Resetting to default based on "
              "lookback days." % (from_timestamp,),
              severity="WARNING",
          )
          from_timestamp = get_start_time(self.lookback_days)
        else:
          utils.cloud_logging(
              "Checkpoint exists, from_timestamp: %s" % (from_timestamp,),
              severity="INFO",
          )
      except (ValueError, TypeError) as e:
        utils.cloud_logging(
            "Invalid from_timestamp checkpoint: %s (not a "
            "valid number). Error: %s. Resetting to default "
            "based on lookback days.\nTraceback: %s" % (
                last_from_timestamp, repr(e),
                traceback.format_exc()
            ),
            severity="WARNING",
        )
        from_timestamp = get_start_time(self.lookback_days)
    else:
      from_timestamp = get_start_time(self.lookback_days)

    if last_to_timestamp:
      try:
        to_timestamp = int(last_to_timestamp)
        if to_timestamp <= 0:
          utils.cloud_logging(
              "Invalid to_timestamp checkpoint: %s "
              "(non-positive). Resetting to current time." % (
                  to_timestamp,
              ),
              severity="WARNING",
          )
          to_timestamp = current_time
          utility.set_last_checkpoint(
              self.tenant_name,
              self.bucket_name,
              constant.CHECKPOINT_KEY_TO_TIMESTAMP,
              None,
          )
        elif to_timestamp > current_time:
          utils.cloud_logging(
              "Invalid to_timestamp checkpoint: %s (future "
              "timestamp). Resetting to current time." % (
                  to_timestamp,
              ),
              severity="WARNING",
          )
          to_timestamp = current_time
          utility.set_last_checkpoint(
              self.tenant_name,
              self.bucket_name,
              constant.CHECKPOINT_KEY_TO_TIMESTAMP,
              None,
          )
        else:
          utils.cloud_logging(
              "Checkpoint exists, to_timestamp: %s" % (to_timestamp,),
              severity="INFO",
          )
      except (ValueError, TypeError) as e:
        utils.cloud_logging(
            "Invalid to_timestamp checkpoint: %s (not a valid "
            "number). Error: %s. Resetting to current time."
            "\nTraceback: %s" % (
                last_to_timestamp, repr(e),
                traceback.format_exc()
            ),
            severity="WARNING",
        )
        to_timestamp = current_time
        utility.set_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_TO_TIMESTAMP,
            None,
        )
    else:
      to_timestamp = current_time

    if from_timestamp >= to_timestamp:
      utils.cloud_logging(
          "Invalid checkpoint state: from_timestamp (%s) >= "
          "to_timestamp (%s). This creates a backwards or "
          "zero-length time window. Resetting to_timestamp to "
          "current time." % (from_timestamp, to_timestamp),
          severity="ERROR",
      )
      to_timestamp = current_time
      utility.set_last_checkpoint(
          self.tenant_name,
          self.bucket_name,
          constant.CHECKPOINT_KEY_TO_TIMESTAMP,
          None,
      )

    if last_page_number:
      try:
        starting_page = int(last_page_number)
        if starting_page <= 0:
          utils.cloud_logging(
              "Invalid page_number checkpoint: %s "
              "(non-positive). Resetting to page 1." % (
                  starting_page,
              ),
              severity="WARNING",
          )
          starting_page = 1
        else:
          utils.cloud_logging(
              "Resuming from page %s" % (starting_page,),
              severity="INFO",
          )
      except (ValueError, TypeError) as e:
        utils.cloud_logging(
            "Invalid page_number checkpoint: %s (not a valid "
            "number). Error: %s. Resetting to page 1."
            "\nTraceback: %s" % (
                last_page_number, repr(e),
                traceback.format_exc()
            ),
            severity="WARNING",
        )
        starting_page = 1
    else:
      starting_page = 1

    return from_timestamp, to_timestamp, starting_page

  def _extract_indicators_from_page_data(
      self, data: dict[str, Any]
  ) -> list[dict[str, Any]]:
    """Extract and filter indicators from page data with deduplication.

    Note: Indicators are NOT sorted here. Sorting happens in
    _filter_indicators() after IOC length filtering and before
    checkpoint filtering.

    Args:
        data (dict[str, Any]): Page data from saved result set API

    Returns:
        list[dict[str, Any]]: List of filtered and deduplicated indicators
    """
    if not data:
      return []

    results = data.get("results", [])
    all_indicators = list(itertools.chain.from_iterable(
        result.get("data", []) for result in results
    ))

    indicators_list = [
        indicator
        for indicator in all_indicators
        if indicator.get("sdo_type", None) == "indicator"
    ]

    deduplicated_indicators = self._deduplicate_indicators(indicators_list)

    if deduplicated_indicators and len(indicators_list) != len(
        deduplicated_indicators
    ):
      removed = len(indicators_list) - len(deduplicated_indicators)
      utils.cloud_logging(
          "Deduplicated page data: %s unique indicators "
          "(removed %s duplicates)" % (
              len(deduplicated_indicators), removed
          )
      )

    return deduplicated_indicators

  def _ingest_indicators(
      self,
      indicators: list[dict[str, Any]],
      from_timestamp: int,
      to_timestamp: int,
      page: int,
      chunk_info: str = "",
  ) -> int:
    """Ingest indicators into Google SecOps.

    Args:
        indicators (list): List of indicators to ingest
        from_timestamp (int): From timestamp for checkpoint on error
        to_timestamp (int): To timestamp for checkpoint on error
        page (int): Current page number for checkpoint on error
        chunk_info (str): Optional chunk information for logging

    Returns:
        int: Count of indicators ingested

    Raises:
        Exception: If ingestion fails after saving checkpoint
    """
    if not indicators:
      return 0

    last_run_initiation_time = utility.get_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
    )

    if last_run_initiation_time:
      try:
        last_run_time = float(last_run_initiation_time)
        current_time = time.time()
        time_diff_minutes = (current_time - last_run_time) / 60

        if time_diff_minutes >= constant.INGESTION_TIME_CHECK_MINUTES:
          utils.cloud_logging(
              "Execution time has exceeded %s minutes "
              "(running for %.2f minutes). Raising "
              "RunTimeExceeded exception." % (
                  constant.INGESTION_TIME_CHECK_MINUTES,
                  time_diff_minutes
              ),
              severity="WARNING",
          )
          raise exception_handler.RunTimeExceeded(
              "Execution time exceeded %s minutes" % (
                  constant.INGESTION_TIME_CHECK_MINUTES,
              )
          )
      except (ValueError, TypeError) as e:
        utils.cloud_logging(
            "Error checking execution time: %s. Continuing with "
            "ingestion.\\nTraceback: %s" % (
                repr(e), traceback.format_exc()
            ),
            severity="WARNING",
        )

    log_prefix = f"{chunk_info}: " if chunk_info else ""
    try:
      utils.cloud_logging(
          "%sIngesting %s indicators into Google SecOps." % (
              log_prefix, len(indicators)
          ),
      )
      ingest_v1.ingest(indicators, constant.GOOGLE_SECOPS_DATA_TYPE)
      utils.cloud_logging(
          "%sSuccessfully ingested %s indicators." % (
              log_prefix, len(indicators)
          ),
      )
      return len(indicators)
    except Exception as e:
      utils.cloud_logging(
          "%sIngestion failed: %s\\nTraceback: %s" % (
              log_prefix, repr(e), traceback.format_exc()
          ),
          severity="ERROR",
      )
      self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
      raise

  def _ingest_without_enrichment(
      self,
      indicators_list: list[dict[str, Any]],
      from_timestamp: int,
      to_timestamp: int,
      page: int,
  ) -> int:
    """Ingest indicators without enrichment.

    Args:
        indicators_list (list): List of indicators to ingest
        from_timestamp (int): From timestamp for checkpoint on error
        to_timestamp (int): To timestamp for checkpoint on error
        page (int): Current page number for checkpoint on error

    Returns:
        int: Count of indicators ingested
    """
    for indicator in indicators_list:
      indicator["tenant_name"] = self.tenant_name

    try:
      ingested_count = self._ingest_indicators(
          indicators_list, from_timestamp, to_timestamp, page
      )
      return ingested_count
    except exception_handler.RunTimeExceeded as e:
      utils.cloud_logging(
          "RunTimeExceeded during ingestion: %s\\nTraceback: %s" % (
              repr(e), traceback.format_exc()
          ),
          severity="WARNING",
      )
      self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
      raise

  def _process_enrichment_chunk(
      self,
      batch_idx: int,
      indicator_batch: list[dict[str, Any]],
      checkpoint_value: int,
      from_timestamp: int,
      to_timestamp: int,
      page: int,
  ) -> int:
    """Process a single batch: fetch enrichment, merge, and ingest.

    Args:
        batch_idx (int): Current batch index (0-based)
        indicator_batch (list): Indicator objects in this batch
        checkpoint_value (int): Pre-determined ctix_modified checkpoint value
        from_timestamp (int): From timestamp for checkpoint on error
        to_timestamp (int): To timestamp for checkpoint on error
        page (int): Current page number for checkpoint on error

    Returns:
        int: Count of indicators ingested for this batch
    """
    if not indicator_batch:
      return 0

    ioc_values = [
        ind.get("sdo_name") for ind in indicator_batch if ind.get("sdo_name")
    ]
    if not ioc_values:
      utils.cloud_logging(
          "Batch %s: No valid IOC values to enrich." % (batch_idx + 1,),
          severity="WARNING",
      )
      return 0

    url = f"{self.base_url}/{constant.BULK_IOC_LOOKUP_ENDPOINT}"
    params = {
        "enrichment_data": constant.FETCH_ENRICHMENT_DATA,
        "relation_data": constant.FETCH_RELATION_DATA,
        "fields": ",".join(constant.ENRICHMENT_FIELDS),
        "page": 1,
        "page_size": constant.PAGE_SIZE_FOR_BULK_IOC,
    }
    json_body = {"value": ioc_values}

    try:
      response = self.make_api_call(
          "POST",
          url,
          params=params,
          json_body=json_body,
          fetch_type="Enrichment Data",
      )

      if not response.get("status"):
        error_message = (
            f"Failed to fetch enrichment data for batch {batch_idx + 1}"
            f"containing {len(ioc_values)} IOC(s) on page {page}. "
            f"Error: {response.get('error')}"
        )
        utils.cloud_logging(error_message, severity="ERROR")
        raise exception_handler.CywareCTIXException(error_message)

      data = response.get("data", {})
      results = data.get("results", [])

      enrichment_map = {}
      for result in results:
        sdo_name = result.get("name")
        if sdo_name:
          enrichment_map[sdo_name] = {
              field: result.get(field)
              for field in constant.ENRICHMENT_FIELDS
              if field != "name" and result.get(field)
          }

      utils.cloud_logging(
          "Batch %s: enriched %s indicators." % (
              batch_idx + 1, len(enrichment_map)
          ),
      )

      batch_to_ingest = []
      for indicator in indicator_batch:
        indicator["tenant_name"] = self.tenant_name
        sdo_name = indicator.get("sdo_name")
        if sdo_name and sdo_name in enrichment_map:
          indicator.update(enrichment_map[sdo_name])
        batch_to_ingest.append(indicator)

      ingested_count = self._ingest_indicators(
          batch_to_ingest,
          from_timestamp,
          to_timestamp,
          page,
          chunk_info=f"Batch {batch_idx + 1}",
      )

      if checkpoint_value and checkpoint_value > 0:
        utility.set_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_CTIX_MODIFIED,
            checkpoint_value,
        )
        utils.cloud_logging(
            "Saved checkpoint: ctix_modified = %s" % (checkpoint_value,),
        )

      return ingested_count

    except exception_handler.RunTimeExceeded as e:
      utils.cloud_logging(
          "RunTimeExceeded during enrichment batch processing: "
          "%s\nTraceback: %s" % (repr(e), traceback.format_exc()),
          severity="WARNING",
      )
      self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
      raise
    except Exception as e:
      utils.cloud_logging(
          "Exception during enrichment batch processing: %s\\nTraceback: %s"
          % (repr(e), traceback.format_exc()),
          severity="ERROR",
      )
      self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
      raise

  def _filter_indicators(
      self, indicators_list: list[dict[str, Any]]
  ) -> list[dict[str, Any]]:
    """Filter indicators by IOC length, sort by ctix_modified.

    Args:
        indicators_list (list): List of indicator dictionaries

    Returns:
        list: Filtered and sorted list of indicators
    """
    if not indicators_list:
      return []

    max_ioc_length = constant.MAX_IOC_LENGTH_FOR_BULK_LOOKUP
    filtered_indicators = []
    skipped_count = 0

    for indicator in indicators_list:
      sdo_name = indicator.get("sdo_name", "")
      if sdo_name and len(sdo_name) <= max_ioc_length:
        filtered_indicators.append(indicator)
      else:
        skipped_count += 1

    if skipped_count > 0:
      utils.cloud_logging(
          "Filtered out %s indicator(s) with IOC length > %s" % (
              skipped_count, max_ioc_length
          ),
          severity="WARNING",
      )

    sorted_indicators = sorted(
        filtered_indicators, key=lambda x: x.get("ctix_modified", 0)
    )
    utils.cloud_logging(
        "Sorted %s indicators by ctix_modified in ascending "
        "order." % (len(sorted_indicators),)
    )

    checkpoint_keys = [
        constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
        constant.CHECKPOINT_KEY_TO_TIMESTAMP,
        constant.CHECKPOINT_KEY_PAGE_NUMBER,
        constant.CHECKPOINT_KEY_CTIX_MODIFIED,
    ]

    checkpoints = {
        key: utility.get_last_checkpoint(
            self.tenant_name, self.bucket_name, key
        )
        for key in checkpoint_keys
    }

    if all(checkpoints.values()):
      last_ctix_modified_int = int(
          checkpoints[constant.CHECKPOINT_KEY_CTIX_MODIFIED]
      )
      checkpoint_filtered = [
          ind
          for ind in sorted_indicators
          if ind.get("ctix_modified", 0) >= last_ctix_modified_int
      ]
      removed_count = len(sorted_indicators) - len(checkpoint_filtered)
      if removed_count > 0:
        utils.cloud_logging(
            "Filtered out %s indicator(s) with "
            "ctix_modified < %s based on checkpoint "
            "(mid-ingestion resume detected)." % (
                removed_count, last_ctix_modified_int
            ),
            severity="INFO",
        )
      return checkpoint_filtered

    return sorted_indicators

  def _enrich_and_ingest_by_chunks(
      self,
      indicators_list: list[dict[str, Any]],
      from_timestamp: int,
      to_timestamp: int,
      page: int,
  ) -> int:
    """Process indicators in batches, enriching and ingesting each batch.

    Args:
        indicators_list (list): List of indicators to process
        from_timestamp (int): From timestamp for checkpoint on error
        to_timestamp (int): To timestamp for checkpoint on error
        page (int): Current page number for checkpoint on error

    Returns:
        int: Total count of indicators ingested

    Raises:
        Exception: If enrichment or ingestion fails
    """
    if not indicators_list:
      utils.cloud_logging("No indicators to process.", severity="WARNING")
      return 0

    if not self.enrichment_enabled:
      utils.cloud_logging("Enrichment is disabled.")
      return self._ingest_without_enrichment(
          indicators_list, from_timestamp, to_timestamp, page
      )

    utils.cloud_logging(
        "Enrichment is enabled. Processing indicators in batches."
    )

    filtered_indicators = self._filter_indicators(indicators_list)
    if not filtered_indicators:
      utils.cloud_logging("No indicators remaining after filtering.")
      return 0

    batch_size = constant.MAX_BULK_IOC_BATCH_SIZE
    total_batches = (len(filtered_indicators) + batch_size - 1) // batch_size

    utils.cloud_logging(
        "Processing %s indicators in %s batch(es) of %s." % (
            len(filtered_indicators), total_batches, batch_size
        )
    )

    total_ingested = 0
    for batch_idx in range(total_batches):
      start_idx = batch_idx * batch_size
      end_idx = min(start_idx + batch_size, len(filtered_indicators))
      indicator_batch = filtered_indicators[start_idx:end_idx]

      checkpoint_value = indicator_batch[-1].get("ctix_modified")

      batch_count = self._process_enrichment_chunk(
          batch_idx,
          indicator_batch,
          checkpoint_value,
          from_timestamp,
          to_timestamp,
          page,
      )
      total_ingested += batch_count

    return total_ingested

  def _save_error_checkpoint(
      self,
      from_timestamp: int,
      to_timestamp: int,
      page: int,
      error: Exception,
  ) -> None:
    """Save checkpoint on ingestion error.

    Args:
        from_timestamp (int): Original from_timestamp to resume from
        to_timestamp (int): Original to_timestamp used in the API call
        page (int): Current page number
        error (Exception): The exception that occurred
    """
    utils.cloud_logging(
        "Error ingesting indicators for page %s: %s\n"
        "Traceback: %s" % (
            page,
            repr(error),
            "".join(traceback.format_exception(
                type(error), error, error.__traceback__
            ))
        ),
        severity="ERROR",
    )
    utility.set_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
        from_timestamp,
    )
    utility.set_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_TO_TIMESTAMP,
        to_timestamp,
    )
    utility.set_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_PAGE_NUMBER,
        page,
    )

  def fetch_indicators_by_labels(self) -> None:
    """Universal entry point for indicator ingestion.

    Handles both single-label and multi-label ingestion with checkpoint-based
    resume logic.

    Single Label:
        - Directly calls fetch_indicator_data() for the single label

    Multi-Label Case 1 (First-time execution):
        - Reads comma-separated label list
        - Saves label list to checkpoint
        - Calculates from/to timestamps ONCE for all labels
        - Iterates through each label, updating current_label checkpoint
        - Calls fetch_indicator_data() for each label with same timestamps
        - Clears label checkpoints after successful completion

    Multi-Label Case 2 (Resume after failure):
        - Compares saved label list with new label list
        - If different: treats as fresh run (Case 1)
        - If same: resumes from last active label
        - Removes already-processed labels from the list
        - Continues ingestion from the current label
    """
    current_label_list = self.label_name
    if not current_label_list:
      utils.cloud_logging(
          "No saved result set list provided. Skipping ingestion.",
          severity="WARNING",
      )
      return

    labels_to_process = [
        label.strip()
        for label in current_label_list.split(",")
        if label.strip()
    ]

    if not labels_to_process:
      utils.cloud_logging(
          "Saved result set list is empty after parsing. Skipping ingestion.",
          severity="WARNING",
      )
      return

    saved_label_list = utility.get_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_LABEL_LIST,
    )
    saved_current_label = utility.get_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_CURRENT_LABEL,
    )

    utils.cloud_logging(
        "Parsed %s saved result set(s) from input: %s" % (
            len(labels_to_process), labels_to_process
        ),
        severity="INFO",
    )

    if saved_label_list != current_label_list:
      utils.cloud_logging(
          "Saved result set list in checkpoint: %s, from "
          "input:%s. Starting fresh ingestion run." % (
              saved_label_list, current_label_list
          ),
          severity="DEBUG",
      )
      self._clear_label_error_checkpoints()
    else:
      if (
          saved_current_label in labels_to_process
          or saved_current_label is None
      ):
        if saved_current_label is None:
          current_label_index = 0
        else:
          current_label_index = labels_to_process.index(saved_current_label)
        utils.cloud_logging(
            "Resuming ingestion from label: %s" % (
                labels_to_process[current_label_index],
            ),
            severity="INFO",
        )
        labels_to_process = labels_to_process[current_label_index:]
        utils.cloud_logging(
            "Resuming with %s remaining saved result set(s): "
            "%s" % (len(labels_to_process), labels_to_process),
            severity="INFO",
        )
      else:
        utils.cloud_logging(
            "Saved current tag '%s' not found in new saved "
            "result set list. Starting fresh." % (
                saved_current_label,
            ),
            severity="WARNING",
        )
        self._clear_label_error_checkpoints()

    from_timestamp, to_timestamp, _ = self._get_checkpoints_and_timestamps()
    utils.cloud_logging(
        "Using from_timestamp=%s, to_timestamp=%s for %s "
        "label(s)." % (
            from_timestamp, to_timestamp, len(labels_to_process)
        ),
        severity="INFO",
    )
    utility.set_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_LABEL_LIST,
        current_label_list,
    )
    utils.cloud_logging(
        "Saved label list to checkpoint: %s" % (
            current_label_list,
        ),
        severity="DEBUG",
    )

    for label in labels_to_process:
      utils.cloud_logging("Processing label: '%s'" % label, severity="INFO")

      utility.set_last_checkpoint(
          self.tenant_name,
          self.bucket_name,
          constant.CHECKPOINT_KEY_CURRENT_LABEL,
          label,
      )
      utils.cloud_logging(
          "Updated current_label checkpoint to: '%s'" % (label,),
          severity="DEBUG",
      )

      self.label_name = label

      try:
        self.fetch_indicator_data(
            from_timestamp=from_timestamp, to_timestamp=to_timestamp
        )
        utils.cloud_logging(
            "Successfully completed ingestion for label: '%s'" % (
                label,
            ),
            severity="INFO",
        )
      except exception_handler.RunTimeExceeded as e:
        utils.cloud_logging(
            "RunTimeExceeded while processing label '%s'. "
            "Checkpoint saved for resume. Error: %s\n"
            "Traceback: %s" % (
                label, repr(e), traceback.format_exc()
            ),
            severity="WARNING",
        )
        raise
      except Exception as e:
        utils.cloud_logging(
            "Error processing label '%s': %s\nTraceback: %s" % (
                label, repr(e), traceback.format_exc()
            ),
            severity="ERROR",
        )
        raise

    utility.set_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
        to_timestamp,
    )
    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_TO_TIMESTAMP,
        "to_timestamp",
        self.tenant_name,
        self.bucket_name,
    )
    utils.cloud_logging(
        "Updated from_timestamp to %s for next run. Cleared "
        "to_timestamp." % (to_timestamp,),
        severity="INFO",
    )

    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_CURRENT_LABEL,
        "current_label",
        self.tenant_name,
        self.bucket_name,
    )
    utils.cloud_logging(
        "All labels processed successfully. Cleared label checkpoints.",
        severity="INFO",
    )

  def _clear_label_error_checkpoints(self) -> None:
    """Clear label-related checkpoints after successful completion."""
    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_LABEL_LIST,
        "label_list",
        self.tenant_name,
        self.bucket_name,
    )
    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_CURRENT_LABEL,
        "current_label",
        self.tenant_name,
        self.bucket_name,
    )
    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
        "from_timestamp",
        self.tenant_name,
        self.bucket_name,
    )
    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_TO_TIMESTAMP,
        "to_timestamp",
        self.tenant_name,
        self.bucket_name,
    )
    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_CTIX_MODIFIED,
        "ctix_modified",
        self.tenant_name,
        self.bucket_name,
    )
    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_PAGE_NUMBER,
        "page_number",
        self.tenant_name,
        self.bucket_name,
    )

  def fetch_indicator_data(
      self, from_timestamp: int, to_timestamp: int
  ) -> None:
    """Prepare complete indicator data response from CTIX.

    Fetches saved result set data page by page with enrichment
    data (if enabled), merges enrichment relations into indicators,
    adds tenant_name to each, and ingests them. Manages checkpoints
    for resumability.

    Args:
        from_timestamp: Start timestamp for data fetch (mandatory).
        to_timestamp: End timestamp for data fetch (mandatory).

    This function is called from fetch_indicators_by_labels() which
    calculates the timestamps once for all labels.
    """
    utils.cloud_logging("Fetching indicator data from CTIX.")

    last_page_number = utility.get_last_checkpoint(
        self.tenant_name,
        self.bucket_name,
        constant.CHECKPOINT_KEY_PAGE_NUMBER,
    )
    if last_page_number:
      try:
        page = int(last_page_number)
        utils.cloud_logging("Resuming from page %s" % page, severity="INFO")
      except (ValueError, TypeError):
        page = 1
    else:
      page = 1

    utils.cloud_logging(
        "Using timestamps: from=%s, to=%s" % (
            from_timestamp, to_timestamp
        ),
        severity="INFO",
    )
    total_indicators_processed = 0

    while True:
      try:
        utils.cloud_logging(
            "Fetching saved result set page %s with page_size "
            "%s" % (page, constant.PAGE_SIZE_FOR_SAVED_RESULT)
        )

        data = self.get_saved_result_set_page(
            from_timestamp, to_timestamp, page
        )

        indicators_list = self._extract_indicators_from_page_data(data)

        if not indicators_list:
          utils.cloud_logging(
              "No indicators found on page %s." % (page,)
          )
          if not data.get("next"):
            break
          page += 1
          continue

        utils.cloud_logging(
            "Page %s: found %s indicators." % (
                page, len(indicators_list)
            )
        )

        page_ingested_count = self._enrich_and_ingest_by_chunks(
            indicators_list, from_timestamp, to_timestamp, page
        )
        total_indicators_processed += page_ingested_count

        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_CTIX_MODIFIED,
            "ctix_modified",
            self.tenant_name,
            self.bucket_name,
        )
        utility.set_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_PAGE_NUMBER,
            page,
        )

        if not data.get("next"):
          utils.cloud_logging(
              "Reached last page %s. All data processed." % (page,)
          )
          break

        page += 1

      except exception_handler.RunTimeExceeded as e:
        utils.cloud_logging(
            "RunTimeExceeded exception caught in "
            "fetch_indicator_data. Total indicators processed: "
            "%s\nTraceback: %s" % (
                total_indicators_processed, traceback.format_exc()
            ),
            severity="WARNING",
        )
        self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
        raise
      except Exception as e:
        utils.cloud_logging(
            "Exception in fetch_indicator_data: %s\nTraceback: "
            "%s" % (repr(e), traceback.format_exc()),
            severity="ERROR",
        )
        self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
        raise

    utility.clear_checkpoint_if_exists(
        constant.CHECKPOINT_KEY_PAGE_NUMBER,
        "page_number",
        self.tenant_name,
        self.bucket_name,
    )

    utils.cloud_logging(
        "Completed ingestion for current label: %s. Total "
        "indicators processed: %s" % (
            self.label_name, total_indicators_processed
        )
    )
