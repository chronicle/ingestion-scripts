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
"""Main script for GreyNoise ingestion."""

import datetime
import ipaddress
import math
import re
from typing import Any

import secops

from common import ingest_v1
from common import utils
import constant
import exception_handler
import greynoise_client
import utility


def add_seven_days(date_str: str) -> str:
  """Add 7 days to the given date string.

  Handles date strings with or without time components and timezone info.
  Primary format: YYYY-MM-DD (as per GreyNoise documentation)
  All outputs are in UTC with 'Z' suffix.

  Args:
      date_str: Date string

  Returns:
      Date + 7 days in format 'YYYY-MM-DDTHH:MM:SSZ' (UTC)

  Raises:
      ValueError: If date format is not recognized
  """
  if not date_str or not date_str.strip():
    raise ValueError("Empty date string provided")

  formats = [
      "%Y-%m-%d",  # 2025-11-19 (primary format per docs)
      "%Y-%m-%dT%H:%M:%S.%fZ",  # 2025-11-19T13:00:27.123456Z
      "%Y-%m-%dT%H:%M:%SZ",  # 2025-12-03T02:19:00Z
      "%Y-%m-%d %H:%M:%S.%f",  # 2025-12-09 16:10:22.948129
      "%Y-%m-%d %H:%M:%S",  # 2025-11-19 13:00:27
  ]

  for fmt in formats:
    try:
      dt = datetime.datetime.strptime(date_str.strip(), fmt)
      # Ensure UTC timezone for naive datetime objects
      if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
      # Convert to UTC if timezone-aware
      dt_utc = dt.astimezone(datetime.timezone.utc)
      dt_plus_7 = dt_utc + datetime.timedelta(days=7)
      return dt_plus_7.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
      continue

  raise ValueError(f"Unsupported date format: {date_str}")


def create_end_time(item: dict[str, Any]) -> None:
  """Create end time by adding 7 days to the most recent timestamp in the item.

  The calculated end time is added to the item under the key
  `constant.END_TIME_FIELD_NAME`.

  Priority order for finding the base timestamp:
  1. internet.last_seen_timestamp
  2. internet.last_seen
  3. current_time (fallback)

  Args:
      item (dict[str, Any]): Data item containing internet intelligence data.
        This dictionary is modified in place.
  """
  internet_data = item.get("internet_scanner_intelligence", {})

  if internet_data:
    # Try last_seen_timestamp first
    last_seen_timestamp = internet_data.get("last_seen_timestamp")
    if last_seen_timestamp:
      try:
        item[constant.END_TIME_FIELD_NAME] = add_seven_days(last_seen_timestamp)
        return
      except ValueError:
        pass  # Fall through to next option

    # Try last_seen as fallback
    last_seen = internet_data.get("last_seen")
    if last_seen:
      try:
        item[constant.END_TIME_FIELD_NAME] = add_seven_days(last_seen)
        return
      except ValueError:
        pass  # Fall through to current time

  # Final fallback: current time + 7 days
  current_time = datetime.datetime.now(datetime.timezone.utc)
  end_time = current_time + datetime.timedelta(days=7)
  item[constant.END_TIME_FIELD_NAME] = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
  return


def get_run_gnql_query(
    query: str,
    greynoise_instance: greynoise_client.GreyNoiseUtility,
    default_ingestion: bool = True,
    is_live_investigation: bool = False,
) -> None:
  """Fetch GNQL query result from GreyNoise.

  Args:
      query: GNQL query string
      greynoise_instance: GreyNoise client instance
      default_ingestion: Whether to use checkpointing (default: True)
      is_live_investigation: Whether the ingestion is from live
        investigation (default: False)

  Raises:
      Exception: If there is an error fetching the data
  """
  last_seen_cutoff = None
  max_last_seen = None
  checkpoint_file = constant.CHECKPOINT_FILE_NAME

  # Load checkpoint at start
  if default_ingestion:
    try:
      state = utility.load_state_from_gcs(checkpoint_file)
      if state:
        last_seen_cutoff = state.get("last_seen_time")
        utils.cloud_logging(f"Loaded checkpoint cutoff: {last_seen_cutoff}")
    except Exception as e:
      utils.cloud_logging(
          f"Failed to load GNQL state from GCS: {str(e)}",
          severity="ERROR",
      )
      raise

  complete = False
  scroll = None
  total_indicators = 0
  skipped_indicators = 0
  processing_successful = False

  try:
    while not complete:
      response = greynoise_instance.gnql_query(query, scroll)
      if isinstance(response, dict) and "request_metadata" in response:
        data = response.get("data", [])
        complete = response.get("request_metadata", {}).get("complete", True)
        scroll = response.get("request_metadata", {}).get("scroll", "")

        filtered_data = []
        for item in data:
          # Cache nested dictionary references
          internet_scanner = item.get("internet_scanner_intelligence", {})

          item_last_seen = internet_scanner.get("last_seen_timestamp")

          # Skip items already processed based on checkpoint
          if (
              default_ingestion
              and last_seen_cutoff
              and item_last_seen
              and item_last_seen <= last_seen_cutoff
          ):
            skipped_indicators += 1
            continue

          # This item will be processed
          if item_last_seen and (
              max_last_seen is None or item_last_seen > max_last_seen
          ):
            max_last_seen = item_last_seen

          # Remove raw_data if present
          if "raw_data" in internet_scanner:
            internet_scanner.pop("raw_data", None)

          # Add live investigation indicator if applicable
          if is_live_investigation:
            item[constant.LIVE_INVESTIGATION_FIELD_NAME] = True
          create_end_time(item)
          filtered_data.append(item)

        ingest_v1.ingest(filtered_data, constant.GOOGLE_SECOPS_DATA_TYPE)
        total_indicators += len(filtered_data)

      elif isinstance(response, dict):
        message = response.get("request_metadata", {}).get("message", "")
        query = response.get("request_metadata", {}).get("adjusted_query", "")
        utils.cloud_logging(
            "No results returned for GreyNoise query: {}, message: {}".format(
                str(query), str(message)
            ),
            severity="WARNING",
        )
        break

    # Mark processing as successful only if we complete the loop
    processing_successful = True

  finally:
    # Save checkpoint ONLY if processing completed successfully
    if (
        processing_successful
        and default_ingestion
        and max_last_seen
        and ((last_seen_cutoff is None) or (max_last_seen > last_seen_cutoff))
    ):
      try:
        utils.cloud_logging(
            "Saving checkpoint after successful processing: "
            f"{max_last_seen} "
            f"(previous cutoff: {last_seen_cutoff})"
        )
        state = {"last_seen_time": max_last_seen}
        utility.save_state_to_gcs(checkpoint_file, state)
        utils.cloud_logging(f"Successfully saved checkpoint: {max_last_seen}")
      except Exception as e:  # pylint: disable=broad-exception-caught
        utils.cloud_logging(
            f"Failed to save checkpoint: {str(e)}", severity="ERROR"
        )
    elif not processing_successful and default_ingestion:
      utils.cloud_logging(
          "Processing failed - checkpoint NOT updated to prevent data loss",
          severity="WARNING",
      )

  utils.cloud_logging(
      f"Total Indicators fetched and ingested: {total_indicators}"
  )
  if default_ingestion and skipped_indicators > 0:
    utils.cloud_logging(
        f"Total Indicators skipped (already processed): {skipped_indicators}"
    )


def lookup_ips_and_ingest(ip_list: list[str], greynoise_instance) -> None:
  """Lookup IPs in batches and ingest results to Chronicle.

  Args:
      ip_list: List of IP addresses to lookup
      greynoise_instance: GreyNoise client instance
  """
  ip_list_chunks = [
      ip_list[i : i + constant.IP_BATCH_SIZE]
      for i in range(0, len(ip_list), constant.IP_BATCH_SIZE)
  ]
  for ip_list_chunk in ip_list_chunks:
    response = greynoise_instance.lookup_ips(ip_list_chunk)
    filtered_response = []
    for item in response:
      # Cache nested dictionary references to avoid redundant lookups
      internet_scanner = item.get("internet_scanner_intelligence", {})
      business_service = item.get("business_service_intelligence", {})

      # Remove raw_data if present
      if "raw_data" in internet_scanner:
        internet_scanner.pop("raw_data", None)

      # Filter out items not found in GreyNoise
      is_not_found = not business_service.get(
          "found", False
      ) and not internet_scanner.get("found", False)
      if is_not_found:
        utils.cloud_logging(
            f"IP : {item.get('ip')} not found in GreyNoise.",
            severity="WARNING",
        )
      else:
        # Add live investigation indicator
        item[constant.LIVE_INVESTIGATION_FIELD_NAME] = True
        create_end_time(item)
        filtered_response.append(item)
    ingest_v1.ingest(filtered_response, constant.GOOGLE_SECOPS_DATA_TYPE)
    utils.cloud_logging(
        f"Total Indicators fetched and ingested: {len(filtered_response)}"
    )


def _parse_last_seen_window(query: str) -> tuple[str, int | None]:
  """Parse last_seen time window from GNQL query.

  Args:
      query: GNQL query string

  Returns:
      (base_query, days) where base_query is the query without
             time filter and days is the number of days
  """
  pattern = r"last_seen:(\d+)([dwmy])"
  match = re.search(pattern, query)
  if not match:
    return query, None
  days = int(match.group(1))
  unit = match.group(2)
  if unit == "w":
    days *= 7
  elif unit == "m":
    days *= 30
  elif unit == "y":
    days *= 365
  base_query = re.sub(pattern, "", query).strip()
  return base_query, days


def _build_last_seen_clause(days: int) -> str:
  """Build last_seen clause for GNQL query.

  Args:
      days: Number of days for the time window

  Returns:
      Formatted last_seen clause
  """
  if days <= 1:
    return "last_seen:1d"
  return f"last_seen:{days}d"


def _compute_dynamic_window_days(configured_days: int | None) -> int | None:
  """Compute dynamic window days based on last checkpoint.

  Args:
      configured_days: Maximum configured days

  Returns:
      Computed number of days for the window
  """
  if not configured_days:
    return None
  try:
    state = utility.load_state_from_gcs(constant.CHECKPOINT_FILE_NAME)
  except Exception as e:  # pylint: disable=broad-exception-caught
    utils.cloud_logging(
        f"Failed to load GNQL state for window calc: {str(e)}",
        severity="ERROR",
    )
    return configured_days
  if not state:
    return configured_days
  last_seen_str = state.get("last_seen_time")
  if not last_seen_str:
    return configured_days
  try:
    value = last_seen_str.replace("Z", "+00:00")
    last_seen_dt = datetime.datetime.fromisoformat(value)
    # If the datetime object is naive, assume UTC.
    if last_seen_dt.tzinfo is None:
      last_seen_dt = last_seen_dt.replace(tzinfo=datetime.timezone.utc)
  except (ValueError, TypeError, AttributeError) as e:
    utils.cloud_logging(
        f"Failed to parse last_seen timestamp '{last_seen_str}': {e}",
        severity="WARNING",
    )
    return configured_days
  now_dt = datetime.datetime.now(datetime.timezone.utc)
  delta = now_dt - last_seen_dt
  if delta.total_seconds() <= 0:
    return 1
  days = math.ceil(delta.total_seconds() / 86_400)
  return min(days, configured_days)


def generate_gnql_query(greynoise_query: str | None) -> tuple[str, bool]:
  """Generate and validate GNQL query.

  Args:
      greynoise_query: Raw query string

  Returns:
      (final_query, has_custom_query) where final_query is the
             processed query and has_custom_query indicates if custom query
  """
  if isinstance(greynoise_query, str):
    greynoise_query = greynoise_query.strip()

  if not greynoise_query:
    default_query = constant.DEFAULT_TIME_QUERY
    utils.cloud_logging(
        f"No GNQL query provided. Using default query: {default_query}"
    )
    return default_query, False

  # If the user already has a time filter, don't add default
  if "last_seen:" in greynoise_query:
    final_query = greynoise_query
  else:
    final_query = f"{greynoise_query} {constant.DEFAULT_TIME_QUERY}"

  utils.cloud_logging(f"Using GNQL query: {final_query}")
  return final_query, True


def validate_live_investigation_inputs(
    args: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
  """Validate inputs for live investigation.

  Args:
      args: Dictionary containing query and datatable parameters

  Returns:
      (query, datatable_name) validated parameters

  Raises:
      LiveInvestigationError: If inputs are invalid
  """
  if not isinstance(args, dict):
    utils.cloud_logging(
        "Invalid live investigation inputs: request body is "
        "not valid JSON or is empty.",
        severity="ERROR",
    )
    raise exception_handler.LiveInvestigationError(
        "Invalid inputs provided. Please provide the right ones and try again."
    )

  missing_or_empty = []
  datatable_name = None
  query = None

  raw_query = args.get(constant.QUERY_FIELD_NAME)
  if raw_query is None or (
      isinstance(raw_query, str) and not raw_query.strip()
  ):
    missing_or_empty.append(constant.QUERY_FIELD_NAME)
  else:
    query, _ = generate_gnql_query(raw_query)

  raw_datatable_name = args.get(constant.DATATABLE_FIELD_NAME)
  if raw_datatable_name is None or (
      isinstance(raw_datatable_name, str) and not raw_datatable_name.strip()
  ):
    missing_or_empty.append(constant.DATATABLE_FIELD_NAME)
  else:
    datatable_name = str(raw_datatable_name).strip()

  if len(missing_or_empty) == 2:
    utils.cloud_logging(
        "Invalid live investigation inputs. "
        f"Missing/empty fields: {missing_or_empty}",
        severity="ERROR",
    )
    raise exception_handler.LiveInvestigationError(
        "Invalid inputs provided. Please provide the right ones and try again."
    )
  return query, datatable_name


def get_ip_list_from_datatable(datatable_name: str) -> list[str]:
  """Retrieve IP addresses from Chronicle datatable.

  Args:
      datatable_name: Name of the datatable to query

  Returns:
      List of IP addresses from the datatable
  """
  client = secops.SecOpsClient()

  chronicle = client.chronicle(
      customer_id=ingest_v1.CUSTOMER_ID,
      project_id=ingest_v1.PROJECT_ID,
      region=ingest_v1.REGION,
  )

  data_table_rows = chronicle.list_data_table_rows(datatable_name)

  ip_list = []
  for row in data_table_rows:
    ip_list.extend(row.get("values", []))

  return ip_list


def validate_ip_list(ip_list: list[str] | None) -> list[str]:
  """Validate a list of IP addresses.

  Args:
      ip_list: List of IP addresses to validate

  Returns:
      List of valid IP addresses

  Raises:
      ValueError: If ip_list is None or not a list
  """
  if ip_list is None:
    raise ValueError("IP list cannot be None")
  if not isinstance(ip_list, list):
    raise ValueError("IP list must be a list")

  valid_ip_list, invalid_ip_list = [], []
  for ip in ip_list:
    try:
      ipaddress.ip_address(ip)
      valid_ip_list.append(ip)
    except (ValueError, TypeError):
      invalid_ip_list.append(ip)
  if invalid_ip_list:
    utils.cloud_logging(
        f"Invalid IP addresses found from the DataTable: {invalid_ip_list}",
        severity="WARNING",
    )
  return valid_ip_list


def live_investigation(
    query: str | None, datatable_name: str | None, greynoise_instance
) -> None:
  """Execute live investigation based on query and/or datatable.

  Args:
      query: GNQL query string (optional)
      datatable_name: Name of the datatable containing IPs (optional)
      greynoise_instance: GreyNoise client instance
  """
  if datatable_name:
    ip_list = get_ip_list_from_datatable(datatable_name)
    valid_ip_list = validate_ip_list(ip_list)
    if query:
      for ip in valid_ip_list:
        ip_query = f"{query} ip:{ip}"
        get_run_gnql_query(
            ip_query,
            greynoise_instance,
            default_ingestion=False,
            is_live_investigation=True,
        )
    else:
      lookup_ips_and_ingest(valid_ip_list, greynoise_instance)
  elif query:
    get_run_gnql_query(
        query,
        greynoise_instance,
        default_ingestion=False,
        is_live_investigation=True,
    )


def main(request) -> tuple[str, int]:
  """Drives the GreyNoise ingestion process.

  Args:
      request: HTTP request object

  Returns:
      (message, status_code)
  """
  try:
    utility.check_sufficient_permissions_on_service_account()
    greynoise_api_key = utility.get_environment_variable(
        constant.ENV_VAR_GREYNOISE_API_KEY, is_required=True, is_secret=True
    )
    args = request.get_json(silent=True)
    headers = request.headers
    try:
      if constant.SCHEDULER_HEADER_KEY in headers:
        greynoise_query, _ = generate_gnql_query(
            utility.get_environment_variable(constant.ENV_VAR_QUERY)
        )
        # extracts days and separates the query
        base_query, configured_days = _parse_last_seen_window(greynoise_query)
        # calculate the dynamic days from which data to collect
        dynamic_days = _compute_dynamic_window_days(configured_days)
        if dynamic_days:
          last_seen_clause = _build_last_seen_clause(dynamic_days)
          if base_query:
            greynoise_query = f"{base_query} {last_seen_clause}"
          else:
            greynoise_query = last_seen_clause
          utils.cloud_logging(f"Using dynamic GNQL query: {greynoise_query}")

        greynoise_client_instance = greynoise_client.GreyNoiseUtility(
            greynoise_api_key
        )
        get_run_gnql_query(greynoise_query, greynoise_client_instance)
      else:
        query, datatable = validate_live_investigation_inputs(args)
        utils.cloud_logging("Starting the Live investigation.")
        greynoise_client_instance = greynoise_client.GreyNoiseUtility(
            greynoise_api_key
        )
        live_investigation(query, datatable, greynoise_client_instance)
      utils.cloud_logging("Execution completed.")
      return "Execution completed.", 200
    except exception_handler.LiveInvestigationError as e:
      utils.cloud_logging(
          "Error occurred while executing live investigation."
          f" Error message: {str(e)}",
          severity="ERROR",
      )
      return (
          "Invalid inputs provided. Please provide the right ones "  # pylint: disable=implicit-str-concat
          "and try again.",
          400,
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      utils.cloud_logging(
          "Unknown exception occurred while executing GNQL query."
          f" Error message: {str(e)}",
          severity="ERROR",
      )
      return f"Error executing methods: {str(e)}", 500

  except exception_handler.GCPPermissionDeniedError as e:
    utils.cloud_logging(
        "The service account does not have sufficient permissions for live"
        f" investigation. Error message: {str(e)}",
        severity="ERROR",
    )
    return (
        "The service account does not have sufficient permissions "   # pylint: disable=implicit-str-concat
        "for live investigation.",
        403,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    utils.cloud_logging(
        "Unknown exception occurred while retrieving the environment "
        f"credentials. Error message: {e}",
        severity="ERROR",
    )
    return f"Error initializing: {str(e)}", 500
