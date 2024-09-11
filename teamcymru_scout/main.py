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
"""Enrich and Ingest data into Chronicle."""

import datetime
import ipaddress
import json
import re
from typing import Any, Dict, List, Optional

from google.cloud import storage
import redis

from common import env_constants
from common import ingest
from common import utils
import fetch_logs
import teamcymru_scout_client
import teamcymru_scout_constants
import teamcymru_scout_env_constants


redis_client = redis.StrictRedis(
    host=utils.get_env_var(env_constants.ENV_REDIS_HOST, default="").strip(),
    port=utils.get_env_var(env_constants.ENV_REDIS_PORT, default="").strip(),
    decode_responses=True,
)


def add_ips_to_redis(redis_ips_list: List[Dict[str, str]]):
  """Add IPs to Redis with a provisional TTL.

  Args:
    redis_ips_list (List[Dict[str, str]]):
    A list of dictionaries where each dictionary
    contains IP information to be stored in Redis.

  Raises:
    Exception: If there is an error while storing IP information in Redis.

  The function retrieves the provisional TTL from environment variables
  and defaults to 30 days
  if an invalid value is provided. It then iterates through the list of IPs,
  stores each IP's information in Redis using the HMSET command,
  and sets the TTL for each key.
  """
  try:
    provisional_ttl = utils.get_env_var(
        teamcymru_scout_env_constants.ENV_PROVISIONAL_TTL,
        required=False,
        default="30",
    ).strip()
    provisional_ttl = int(provisional_ttl)
    if provisional_ttl <= 0:
      raise ValueError
  except Exception:   # pylint: disable=broad-except
    utils.cloud_logging(
        "Invalid value provided for the PROVISIONAL_TTL environment "
        "variable. A PROVISIONAL_TTL should be a non-zero positive "
        "integer value. Default value will be considered as 30 days.",
        severity="WARNING",
    )
    provisional_ttl = 30

  # Use the Redis HMSET command to set the dictionary in the Redis Hash
  for data_to_cache in redis_ips_list:
    ip = data_to_cache.get("value")
    try:
      redis_client.hset(ip, mapping=data_to_cache)
      ttl = (
          int(provisional_ttl) * 86400
      )  # no of seconds in a day = 86400  # noqa:E501

      # Set the TTL for the key
      redis_client.expire(ip, ttl)
    except Exception as e:   # pylint: disable=broad-except
      utils.cloud_logging(
          f"Error occurred while storing enriched ip in the memory "
          f"store. Error: {e}",
          severity="ERROR",
      )
      raise e


def check_valid_arguments(argument_name: str, argument_value: str) -> bool:
  """Check valid arguments for adhoc mode.

  Args:
    argument_name (str): argument name to check
    argument_value (str): argument value given by user

  Returns:
    bool: return True or False
  """
  if str(argument_value).lower() == "true":
    return True
  if str(argument_value).lower() == "false":
    return False
  utils.cloud_logging(
      f"Please provide boolean value for {argument_name} argument. "
      "Default value will be considered as False.",
      severity="ERROR",
  )
  return False


def ingest_into_chronicle(
    enriched_events: List[Dict[str, Any]],
    event_type: str,
    redis_ip_list: Optional[List[Dict[str, str]]] = None,
) -> str:
  """Ingests enriched events into Chronicle.

  Args:
    enriched_events (List[Dict[str, Any]]): List
    of enriched events.
    event_type (str): Type of event.
    redis_ip_list (Optional[List[Dict[str, str]]]):
    List of IPs to store in Redis.

  Returns:
    str: Status of ingestion for the event type.
  """
  try:
    if enriched_events:
      ingest.ingest(
          enriched_events,
          teamcymru_scout_env_constants.CHRONICLE_DATA_TYPE,
      )
      utils.cloud_logging(
          f"Enriched {event_type} data successfully "
          "ingested into Chronicle."  # noqa:E501
      )

      if redis_ip_list:
        try:
          add_ips_to_redis(redis_ip_list)
        except Exception:  # pylint: disable=broad-except
          return (
              f"Ingestion for {event_type} is completed but error "
              f"occurred while storing enriched IPs in Redis.\n"
          )
      return f"Ingestion for {event_type} is completed\n"
    else:
      utils.cloud_logging(
          f"No enriched {event_type} data to ingest into Chronicle.",
          severity="INFO",
      )
      return (
          f"Ingestion for {event_type} is completed "
          "with no enriched data\n"
      )  # noqa:E501
  except Exception as error:    # pylint: disable=broad-except
    utils.cloud_logging(
        f"Error occurred while ingesting enriched {event_type} data: {error}",
        severity="ERROR",
    )
    return f"Ingestion for {event_type} is not completed.\n"


def is_valid_indicator(indicator, indicator_type):
  """Check if the input indicator is a valid IP address or domain name based on the indicator type.

  Args:
    indicator (str): The indicator value to validate.
    indicator_type (str): The type of indicator ("IP" or "DOMAIN").

  Returns:
    bool: True if the indicator is valid for the given type, False otherwise.
  """  # noqa:E501
  if indicator_type == "IP":
    return (
        re.fullmatch(teamcymru_scout_constants.IPV4_REGEX, indicator)
        is not None  # noqa:E501
        or re.fullmatch(teamcymru_scout_constants.IPV6_REGEX, indicator)
        is not None  # noqa:E501
    )
  elif indicator_type == "DOMAIN":
    return (
        re.fullmatch(teamcymru_scout_constants.DOMAIN_REGEX, indicator)
        is not None  # noqa:E501
    )  # noqa:E501
  else:
    return False


def extract_ips_and_domains(data_list: List[str]):
  """Extracts IP addresses and domain names from a list of data.

  Args:
    data_list (list): List of data to extract IP addresses and domain
    names from.

  Returns:
    tuple: A tuple containing two lists - ips_list and domain_list.
      ips_list (list): List of IP addresses extracted from the data.
      domain_list (list): List of domain names extracted from the data.
  """
  ips_list = []
  domain_list = []

  for indicator in data_list:
    # Check if the indicator is an IP address
    if is_valid_indicator(indicator, "IP"):
      ips_list.append(indicator)
    # Check if the indicator is a domain name
    elif is_valid_indicator(indicator, "DOMAIN"):
      domain_list.append(indicator)
    else:
      utils.cloud_logging(
          f"Skipping invalid indicator {indicator} "
          "from live investigation which is not an IP or Domain",
          severity="WARNING",
      )

  return ips_list, domain_list


def get_and_ingest_events(
    client: teamcymru_scout_client.TeamCymruScoutClient,
    data_list: List[str],
    event_type: str,
    function_mode: str,
    account_usage_details: Dict[str, Any],
    ip_enrichment_tags: Optional[List[str]] = None,
) -> str:
  """Retrieves and ingests events.

  Args:
    client: Client instance.
    data_list: List of data to process.
    event_type: Type of event.
    function_mode: Mode of the function ('scheduled' or 'adhoc').
    account_usage_details: Account usage details.
    ip_enrichment_tags: Tags for IP enrichment. Defaults to None.

  Returns:
    str: Status message.
  """
  try:
    status_msg = ""
    if function_mode == "scheduled":
      if event_type == "ip_enrichment":
        status_msg = enrich_and_ingest_ips(
            client,
            data_list,
            event_type,
            account_usage_details,
            ip_enrichment_tags,
        )
      elif event_type == "domain_search":
        status_msg = enrich_and_ingest_domains(
            client, data_list, event_type
        )  # noqa:E501
    elif function_mode == "adhoc":
      if event_type == "ip_enrichment":
        enrichment_flag = utils.get_env_var(
            teamcymru_scout_env_constants.ENV_FORCE_IP_ENRICHMENT_DETAIL,
            required=False,
            default="false",
        ).strip()  # noqa:E501
        enrichment_flag = check_valid_arguments(
            "enrichment_flag", enrichment_flag
        )
        status_msg = enrich_and_ingest_ips(
            client,
            data_list,
            event_type,
            account_usage_details,
            ip_enrichment_tags,
            enrichment_flag=enrichment_flag,
            is_called_for_adhoc=True,
        )
      elif event_type == "domain_search":
        status_msg = enrich_and_ingest_domains(
            client, data_list, event_type
        )  # noqa:E501
      elif event_type == "live_investigation":
        status_msg = live_investigation(
            client,
            data_list,
            event_type,
            account_usage_details,
            ip_enrichment_tags,
        )
    return status_msg
  except Exception as error:  # pylint: disable=broad-except
    error_message = (
        f"Error occurred while enriching and ingesting data for "
        f"{event_type} in {function_mode}, Error: {error}"
    )
    utils.cloud_logging(error_message, severity="ERROR")
    return f"Ingestion for {event_type} is not completed.\n"


def live_investigation(
    client: teamcymru_scout_client.TeamCymruScoutClient,
    data_list: List[str],
    event_type: str,
    account_usage_details: Dict[str, Any],
    ip_enrichment_tags: List[str],
) -> str:
  """Extracts IP addresses and domain names from data, enriches them and ingests in Chronicle.

  Args:
    client (teamcymru_scout_client.TeamCymruScoutClient): Client instance.
    data_list (List[str]): List of data to extract IP addresses and
    domain names from.
    event_type (str): Type of event.
    account_usage_details (Dict[str, Any]): Account usage details.
    ip_enrichment_tags (List[str]): Tags for IP enrichment.

  Returns:
    str: Status of ingestion.
  """
  extracted_ips, extracted_domains = extract_ips_and_domains(data_list)

  if not extracted_ips and not extracted_domains:
    return (
        f"Skipping {event_type} as no valid indicators are provided "
        "for live investigation.\n"
    )

  status_message = ""

  if extracted_ips:
    status_message += enrich_and_ingest_ips(
        client,
        extracted_ips,
        event_type,
        account_usage_details,
        ip_enrichment_tags,
        enrichment_flag=True,  # noqa:E501
        is_live_investigation=True,
        is_called_for_adhoc=True,
    )

  if extracted_domains:
    status_message += enrich_and_ingest_domains(
        client, extracted_domains, event_type
    )

  if "not completed" not in status_message:
    status_message = f"Ingestion for {event_type} is completed.\n"
  else:
    status_message = f"Ingestion for {event_type} is not completed.\n"

  return status_message


def is_ip_present_in_cache(ip_address: str) -> bool:
  """Checks if an IP address is present in the cache.

  Args:
    ip_address (str): The IP address to check.

  Returns:
    bool: True if the IP address is in the cache, False otherwise.
  """
  try:
    if redis_client.exists(ip_address):
      utils.cloud_logging(
          f"Skipping Detail enrichment for {ip_address} as "
          "it is already present in cache."
          " Only Foundation enrichment will be done.",
      )
      return True
    else:
      return False
  except Exception as error:  # pylint: disable=broad-except
    raise RuntimeError(f"Error in Connecting to Redis: {error}") from error


def fetch_ip_detail(
    client,
    ip_list,
    current_timestamp,
    is_live_investigation=False
):
  """Fetches IP details from the client and enriches them.

  Args:
    client (teamcymru_scout_client.TeamCymruScoutClient): Client instance.
    ip_list (List[str]): List of IP addresses.
    current_timestamp (str): Current timestamp.
    is_live_investigation (bool): Flag for live investigation.

  Returns:
    Tuple[List[dict], List[dict]]: Enriched events and data to cache.
  """
  enriched_events = []
  redis_ips_list = []
  event_type = "live_investigation" if is_live_investigation else "ip_detail"

  for ip_detail in client.get_details_ip_data(ip_list, is_live_investigation):
    data_to_cache = {
        "value": ip_detail.get("ip"),
        "created_timestamp": current_timestamp,
    }
    enriched_events.append(enrich_ip(ip_detail, event_type))
    redis_ips_list.append(data_to_cache)

  return enriched_events, redis_ips_list


def filter_public_ips(ip_list: List[str]) -> List[str]:
  """Takes a list of IP addresses and returns a list of public unicast IPs.

  Args:
    ip_list (list): A list of IP addresses as strings

  Returns:
    list: A list of public unicast IPs
  """
  public_ips = []
  for ip in ip_list:
    try:
      ip_obj = ipaddress.ip_address(ip)
      if (
          ip_obj.is_global and
          not ip_obj.is_private and
          not ip_obj.is_multicast and
          not ip_obj.is_link_local and
          not ip_obj.is_reserved and
          not ip_obj.is_loopback and
          not ip_obj.is_unspecified
      ):
        public_ips.append(ip)
      else:
        utils.cloud_logging(
            f"Skipping {ip} from enrichment as "
            "it is not a public IP address.",
            severity="INFO"
        )
    except Exception as error:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Skipping {ip} from enrichment as "
          f"it is not a valid IP address: {error}",
          severity="ERROR"
      )
  return public_ips


def enrich_and_ingest_ips(
    client: teamcymru_scout_client.TeamCymruScoutClient,
    ip_list: List[str],
    event_type: str,
    account_usage_details: Dict[str, Any],
    enrichment_tags: List[str],
    enrichment_flag: Optional[bool] = False,
    is_live_investigation: Optional[bool] = False,
    is_called_for_adhoc: Optional[bool] = False,
) -> str:
  """Enriches IP addresses and ingests into Chronicle.

  Args:
    client: Client instance.
    ip_list: List of IP addresses.
    event_type: Type of event.
    account_usage_details: Account usage details.
    enrichment_tags: Tags for enrichment.
    enrichment_flag: Flag for enrichment.
    is_live_investigation: Flag for live investigation.
    is_called_for_adhoc: Flag for adhoc call.

  Returns:
    Status message.
  """
  try:
    enriched_events = []
    redis_ips_list = []

    ip_list = validate_indicators(ip_list, "IP")
    ip_list = filter_public_ips(ip_list)
    current_timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")

    if ip_list:
      if enrichment_flag or is_live_investigation:
        utils.cloud_logging(
            "Ingesting IP details for ip_enrichment as "
            "FORCE_IP_ENRICHMENT_DETAIL environment variable is set to true "
            "or it is invoked as part of live investigation.",
            severity="INFO",
        )
        enriched_events, redis_ips_list = fetch_ip_detail(
            client, ip_list, current_timestamp, is_live_investigation
        )
      else:
        if is_rate_limit_exceeded(account_usage_details, "foundation"):
          utils.cloud_logging(
              "Skipping IP enrichment as rate limit is exceeded. "
              f"latest usage details: {account_usage_details}",
              severity="WARNING",
          )
          return f"Ingestion for {event_type} is not completed.\n"
        for ip_foundation in client.get_foundation_ip_data(
            ip_list=ip_list
        ):  # noqa:E501
          overall_rating = ip_foundation.get("insights", {}).get(
              "overall_rating", ""
          )
          ip = ip_foundation.get("ip", "")

          redis_cache_check = False

          if not is_called_for_adhoc:
            redis_cache_check = is_ip_present_in_cache(ip)

          if overall_rating in enrichment_tags and not redis_cache_check:
            utils.cloud_logging(
                f"Getting enrichment details for {ip} as "
                f"overall rating {overall_rating} is matched "
                f"with one of the {enrichment_tags} enrichment tags",
                severity="DEBUG",
            )
            enriched_ip_events, redis_ips_list = fetch_ip_detail(
                client, [ip], current_timestamp
            )
            if enriched_ip_events:
              enriched_events.extend(enriched_ip_events)
          else:
            utils.cloud_logging(
                f"Getting foundation details for {ip} as "
                f"overall rating {overall_rating} is not matched "
                f"with one of the {enrichment_tags} enrichment tags "
                f"or {ip} is already exists in Redis cache.",  # noqa:E501
                severity="DEBUG",
            )
            enriched_events.append(
                enrich_ip(ip_foundation, "ip_foundation")
            )  # noqa:E501

    return ingest_into_chronicle(
        enriched_events, event_type, redis_ips_list
    )  # noqa:E501

  except Exception as error:    # pylint: disable=broad-except
    utils.cloud_logging(
        f"Error occurred while getting details for {event_type}: {error}",
        severity="ERROR",
    )
    return f"Ingestion for {event_type} is not completed.\n"


def enrich_and_ingest_domains(
    client: teamcymru_scout_client.TeamCymruScoutClient,
    domain_list: List[str],
    event_type: str,
) -> str:
  """Enriches domain names and ingests into Chronicle.

  Args:
    client (teamcymru_scout_client.TeamCymruScoutClient): Client instance.
    domain_list (List[str]): List of domain names.
    event_type (str): Type of event.

  Returns:
    str: Status message.
  """
  try:
    enriched_events = []
    domain_list = validate_indicators(domain_list, "DOMAIN")

    if domain_list:
      for domain_foundation in client.get_details_domain_data(
          domain_list=domain_list
      ):
        enriched_events.append(
            enrich_domain(domain_foundation, event_type)
        )  # noqa:E501

    return ingest_into_chronicle(enriched_events, event_type)
  except Exception as error:  # pylint: disable=broad-except
    utils.cloud_logging(
        f"Error occurred while getting details for {event_type}: {error}",
        severity="ERROR",
    )
    return f"Ingestion for {event_type} is not completed.\n"


def enrich_ip(ip_detail, event_type):
  """Enriches IP detail."""
  now = datetime.datetime.now()
  one_month_ago = now - datetime.timedelta(days=30)

  ip_detail["event_type"] = event_type
  ip_detail["indicator_type"] = "IP"
  ip_detail["indicator"] = ip_detail.get("ip", "")
  ip_detail["interval_start"] = one_month_ago.strftime("%Y-%m-%d")
  ip_detail["interval_end"] = now.strftime("%Y-%m-%d")
  return ip_detail


def enrich_domain(domain_detail, event_type):
  """Enriches Domain detail."""
  now = datetime.datetime.now()
  one_month_ago = now - datetime.timedelta(days=30)

  domain_detail["event_type"] = event_type
  domain_detail["indicator_type"] = "DOMAIN"
  domain_detail["indicator"] = domain_detail.get("query", "")
  domain_detail["interval_start"] = one_month_ago.strftime("%Y-%m-%d")
  domain_detail["interval_end"] = now.strftime("%Y-%m-%d")
  return domain_detail


def is_rate_limit_exceeded(
    account_usage_details, api_type="*"
) -> bool:
  """Check if the rate limit is exceeded.

  Args:
    account_usage_details (dict): Dictionary containing
    account usage details.
    api_type (str): Type of API to check rate limit for.

  Returns:
    bool: True if the rate limit is exceeded, False otherwise.
  """
  foundation_api_usage = account_usage_details.get(
      "foundation_api_usage", {}
  )  # noqa:E501
  foundation_remaining_queries = foundation_api_usage.get(
      "remaining_queries", 0
  )  # noqa:E501
  foundation_query_limit = foundation_api_usage.get("query_limit", 0)
  remaining_queries = account_usage_details.get("remaining_queries", 0)
  query_limit = account_usage_details.get("query_limit", 0)

  if api_type == "foundation":
    return (
        foundation_remaining_queries <= 0 and foundation_query_limit != 0
    )  # noqa:E501
  elif api_type == "search":
    return remaining_queries <= 0 and query_limit != 0
  else:
    return (
        foundation_remaining_queries <= 0 and foundation_query_limit != 0
    ) or (  # noqa:E501
        remaining_queries <= 0 and query_limit != 0
    )


def ingest_updated_usage_details(
    client: teamcymru_scout_client.TeamCymruScoutClient,
    account_name: str,
    auth_type: str,
) -> str:
  """Ingests the updated usage details of the Team Cymru Scout account.

  Args:
    client (TeamCymruScoutClient): Instance of TeamCymruScoutClient.
    account_name (str): Name of the account.
    auth_type (str): Authentication type of the account.

  Returns:
    str: Status of ingestion for account usage details.
  """
  try:
    data = client.get_usage()
    percentage_used_queries = (
        round((data["used_queries"] / data["query_limit"]) * 100, 3)
        if data["query_limit"] != 0
        else 0.0
    )
    percentage_foundation_used_queries = (
        round((data["foundation_api_usage"]["used_queries"]
               / data["foundation_api_usage"]["query_limit"]) * 100, 3)
        if data["foundation_api_usage"]["query_limit"] != 0 else 0.0
    )
    account_details = {
        "account_name": account_name,
        "account_type": auth_type,
        "used_queries": data["used_queries"],
        "remaining_queries": data["remaining_queries"],
        "used_queries_percentage": percentage_used_queries,
        "query_limit": data["query_limit"],
        "used_foundation_queries": data["foundation_api_usage"][
            "used_queries"
        ],  # noqa:E501
        "remaining_foundation_queries": data["foundation_api_usage"][
            "remaining_queries"
        ],
        "foundation_query_limit": data["foundation_api_usage"][
            "query_limit"
        ],  # noqa:E501
        "used_foundation_queries_percentage": percentage_foundation_used_queries,  # pylint: disable=line-too-long
        "event_type": "account_usage",
    }
    return ingest_into_chronicle(
        [account_details], "account_usage_details"
    )  # noqa:E501
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        f"Failed to the get/ingest latest account usage details. Error: {e}",  # pylint: disable=line-too-long
        severity="ERROR",
    )
    return "Ingestion for account_usage_details is not completed.\n"


def scheduled_function(
    client: teamcymru_scout_client.TeamCymruScoutClient,
    account_usage_details: Dict[str, Any],
    auth_type: str,
    ip_enrichment_tags: List[str],
) -> str:
  """Scheduled function to enrich and ingest data.

  Args:
    client (teamcymru_scout_client.TeamCymruScoutClient): Client instance.
    account_usage_details (Dict[str, Any]): Account usage details.
    auth_type (str): Authentication type.
    ip_enrichment_tags (List[str]): Tags for IP enrichment.

  Returns:
    str: Status message.
  """
  try:
    utils.cloud_logging(
        "Running in Scheduled Enrichment Mode", severity="INFO"
    )  # noqa:E501
    utils.cloud_logging("Fetching events from Chronicle.")
    ingestion_status = ""
    gcp_bucket_name = utils.get_env_var(
        env_constants.ENV_GCP_BUCKET_NAME, default=""
    ).strip()
    if not gcp_bucket_name:
      error_msg = (
          f"Empty value is provided for the {env_constants.ENV_GCP_BUCKET_NAME}"
          " environment variable."
      )
      utils.cloud_logging(error_msg, severity="ERROR")
      return "Ingestion not completed.\n"
    storage_client = storage.Client()
    current_bucket = storage_client.get_bucket(gcp_bucket_name)
    try:
      blob = current_bucket.blob(
          utils.get_env_var(
              teamcymru_scout_env_constants.ENV_LOG_TYPE_FILE_PATH,
              required=False,
              default="file_does_not_exists",
          ).strip()
      )
      log_types = blob.download_as_text() if blob.exists() else ""
      if not log_types:
        warning_msg = (
            "Log type file is not provided or invalid value is provided. "
            "Considering all log type to fetch events from Chronicle."
        )
        utils.cloud_logging(warning_msg, severity="WARNING")
    except Exception as e:  # pylint: disable=broad-except
      error_msg = f"An error occurred: {e}"
      utils.cloud_logging(error_msg, severity="ERROR")
      return "Ingestion not completed.\n"
    object_fetch_log = fetch_logs.FetchEvents(log_types)
    try:
      ip_list, domain_list, checkpoint_blob, new_checkpoint = (
          object_fetch_log.fetch_data_and_checkpoint()
      )
    except ValueError:
      return "Ingestion not completed.\n"
    except Exception as err:  # pylint: disable=broad-except
      error_msg = f"Error in fetching events: {err}"
      utils.cloud_logging(error_msg, severity="ERROR")
      return "Ingestion not completed.\n"
    utils.cloud_logging("Completed fetching events from Chronicle.")
    if not ip_list and not domain_list:
      with checkpoint_blob.open(mode="w", encoding="utf-8") as json_file:
        json.dump(new_checkpoint, json_file)
      utils.cloud_logging(
          "No data found in Chronicle for configured log types in "
          "given time range. "  # noqa:E501
          f"The start time for next execution is updated to"
          f" {new_checkpoint.get('time')}."  # noqa:E501
      )
      return "Ingestion not completed.\n"
    if ip_list:
      utils.cloud_logging(f"Enriching {len(ip_list)} IP addresses.")
      ingestion_status += get_and_ingest_events(
          client,
          ip_list,
          "ip_enrichment",
          "scheduled",
          account_usage_details,
          ip_enrichment_tags,
      )
    if domain_list:
      utils.cloud_logging(f"Enriching {len(domain_list)} domain names.")
      ingestion_status += get_and_ingest_events(
          client,
          domain_list,
          "domain_search",
          "scheduled",
          account_usage_details
      )
    if "not completed" not in ingestion_status:
      with checkpoint_blob.open(mode="w", encoding="utf-8") as json_file:
        json.dump(new_checkpoint, json_file)
      utils.cloud_logging(
          f"The start time for next execution is updated to "
          f"{new_checkpoint.get('time')}."  # noqa:E501
      )
    ingestion_status += ingest_updated_usage_details(
        client, account_usage_details["account_name"], auth_type
    )
    return ingestion_status
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        f"Error while executing scheduled function. Error: {e}",  # noqa:E501
        severity="ERROR",
    )
    return "Ingestion is not completed.\n"


def get_reference_list(list_name_env_var):
  """Get the reference list from the environment variable.

  Args:
    list_name_env_var (str): The name of the environment
    variable containing the list name.

  Raises:
    Exception: If the environment variable is not set or has an empty value.

  Returns:
    list: The reference list.
  """  # noqa:E501
  list_name = utils.get_env_var(
      list_name_env_var, required=False, default=""
  )  # noqa:E501

  if not list_name:
    utils.cloud_logging(
        f"Environment variable {list_name_env_var} for the reference "
        "list name is not set or "  # noqa:E501
        "empty value is provided.",
        severity="ERROR",
    )
    raise Exception(  # pylint: disable=broad-exception-raised
        f"Environment variable {list_name_env_var} is not set or "
        "empty value is provided."  # noqa:E501
    )

  list_name = list_name.strip()

  try:
    data_list = ingest.get_reference_list(list_name)

    if not data_list:
      utils.cloud_logging(
          f"No data found in reference list {list_name}",
          severity="WARNING",  # noqa:E501
      )
    return data_list
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        f"An error occurred while fetching reference list {list_name}, "
        f"Error : {e}",  # noqa:E501
        severity="ERROR",
    )
    raise e


def adhoc_function(
    teamcymru_scout_client,  # pylint: disable=redefined-outer-name
    account_usage_details,
    auth_type,
    ip_enrichment_enabled,
    domain_search_enabled,
    live_investigation_enabled,
    ip_enrichment_tags,
):
  """Enriches and ingests data based on the provided flags.

  Args:
    teamcymru_scout_client (teamcymru_scout_client.TeamCymruScoutClient):
    The client instance.
    account_usage_details (dict): The account usage details.
    auth_type (str): The authentication type.
    ip_enrichment_enabled (bool): Indicates if IP enrichment is enabled.
    domain_search_enabled (bool): Indicates if domain search is enabled.
    live_investigation_enabled (bool): Indicates if live investigation
    is enabled.
    ip_enrichment_tags (list): The tags for IP enrichment.

  Returns:
    str: The status message.
  """
  utils.cloud_logging(
      "Running in Adhoc Enrichment Mode", severity="INFO"
  )  # noqa:E501
  ingestion_status = ""

  if ip_enrichment_enabled:
    try:
      data_list = get_reference_list(
          teamcymru_scout_env_constants.ENV_IP_ENRICHMENT_LIST
      )
      ingestion_status += get_and_ingest_events(
          teamcymru_scout_client,
          data_list,
          "ip_enrichment",
          "adhoc",
          account_usage_details,
          ip_enrichment_tags,
      )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"An error occurred while fetching reference list "
          f"{teamcymru_scout_env_constants.ENV_IP_ENRICHMENT_LIST},Error : {e}",
          severity="ERROR",
      )
      ingestion_status += (
          "Ingestion for ip_enrichment is not completed.\n"  # noqa:E501
      )

  if domain_search_enabled:
    try:
      data_list = get_reference_list(
          teamcymru_scout_env_constants.ENV_DOMAIN_SEARCH_LIST
      )
      ingestion_status += get_and_ingest_events(
          teamcymru_scout_client,
          data_list,
          "domain_search",
          "adhoc",
          account_usage_details,
      )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"An error occurred while fetching reference list "
          f"{teamcymru_scout_env_constants.ENV_DOMAIN_SEARCH_LIST},Error : {e}",
          severity="ERROR",
      )
      ingestion_status += (
          "Ingestion for domain_search is not completed.\n"  # noqa:E501
      )

  if live_investigation_enabled:
    try:
      data_list = get_reference_list(
          teamcymru_scout_env_constants.ENV_LIVE_INVESTIGATION_LIST
      )
      ingestion_status += get_and_ingest_events(
          teamcymru_scout_client,
          data_list,
          "live_investigation",
          "adhoc",  # noqa:E501
          account_usage_details,
      )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"An error occurred while fetching reference list "
          f"{teamcymru_scout_env_constants.ENV_LIVE_INVESTIGATION_LIST},Error: "
          f"{e}",
          severity="ERROR",
      )
      ingestion_status += (
          "Ingestion for live_investigation is not completed.\n"  # noqa:E501
      )

  ingestion_status += ingest_updated_usage_details(
      teamcymru_scout_client,
      account_usage_details["account_name"],
      auth_type,  # noqa:E501
  )
  return ingestion_status


def validate_indicators(indicators, indicator_type):
  """Validate the given indicators.

  This function filters out invalid indicators based on the indicator type.
  It logs a warning message for each invalid indicator.

  Args:
    indicators (dict): A dictionary containing the list of indicators.
    indicator_type (str): The type of the indicator.

  Returns:
    list: A list of valid indicators.
  """

  valid_indicators = []

  for indicator in indicators:
    if indicator_type == "IP":
      if is_valid_indicator(indicator, "IP"):
        valid_indicators.append(indicator)
      else:
        utils.cloud_logging(
            f"Skipping invalid IP indicator: {indicator}",
            severity="WARNING",
        )
    elif indicator_type == "DOMAIN":
      if is_valid_indicator(indicator, "DOMAIN"):
        valid_indicators.append(indicator)
      else:
        utils.cloud_logging(
            f"Skipping invalid domain indicator: {indicator}",
            severity="WARNING",
        )
  return valid_indicators


def get_scout_client_and_usage_details(scout_config, account_name):
  """Creates a TeamCymruScoutClient object and returns the account usage details.

  Args:
    scout_config (dict): Configuration for the TeamCymruScoutClient.
    account_name (str): Name of the account.

  Returns:
    tuple: A tuple containing the account usage details and the
    TeamCymruScoutClient object.
  """  # noqa:E501
  client = teamcymru_scout_client.TeamCymruScoutClient(scout_config)
  usage_details = client.get_usage()
  usage_details["account_name"] = account_name

  return usage_details, client


def main(request) -> str:
  """Parse the request body and run scheduled or adhoc function.

  Args:
    request: Request to execute the cloud function.

  Returns:
    str: whether the ingestion is completed or not
  """
  try:
    account_name, auth_type, user_name, password, api_key = (  # pylint: disable=unused-variable
        None,
        None,
        None,
        None,
        None,
    )
    # Get environment variables
    account_name = utils.get_env_var(
        teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_ACCOUNT_NAME
    )
    if not account_name:
      utils.cloud_logging(
          "Empty value is provided for the "
          f"{teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_ACCOUNT_NAME} "
          "environment variable.",
          severity="ERROR",
      )  # noqa:E501
      return "Ingestion not completed due to empty account name.\n"
    account_name = account_name.strip()

    auth_type = utils.get_env_var(
        teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_AUTH_TYPE
    )
    if not auth_type:
      utils.cloud_logging(
          "Empty value is provided for the"
          f" {teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_AUTH_TYPE} "
          "environment variable.",
          severity="ERROR",
      )
      return "Ingestion not completed due to empty auth type.\n"
    auth_type = auth_type.strip()

    teamcymru_scout_config = {
        "auth_type": auth_type,
        "account_name": account_name,
    }
    if auth_type == "basic_auth":
      user_name = utils.get_env_var(
          teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_API_USERNAME,
          is_secret=True,  # noqa:E501
      )
      if not user_name:
        utils.cloud_logging(
            "Empty value is provided for the"
            f" {teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_API_USERNAME}"
            " environment variable.",
            severity="ERROR",
        )
        return "Ingestion not completed due to empty username.\n"
      user_name = user_name.strip()

      password = utils.get_env_var(
          teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_API_PASSWORD,
          is_secret=True,  # noqa:E501
      )
      if not password:
        utils.cloud_logging(
            "Empty value is provided for the"
            f" {teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_API_PASSWORD}"
            " environment variable.",
            severity="ERROR",
        )
        return "Ingestion not completed due to empty password.\n"
      password = password.strip()

      teamcymru_scout_config["username"] = user_name
      teamcymru_scout_config["password"] = password
    elif auth_type == "api_key":
      api_key = utils.get_env_var(
          teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_API_KEY,
          is_secret=True,  # noqa:E501
      )
      if not api_key:
        utils.cloud_logging(
            "Empty value is provided for the"
            f" {teamcymru_scout_env_constants.ENV_TEAMCYMRU_SCOUT_API_KEY}"
            " environment variable.",
            severity="ERROR",
        )
        return "Ingestion not completed due to empty api key.\n"
      api_key = api_key.strip()
      teamcymru_scout_config["api_key"] = api_key
    else:
      utils.cloud_logging(
          f"Invalid auth type: {auth_type} configured in environment variable. "
          "Supported auth types: basic_auth, api_key",
          severity="ERROR",
      )
      return "Ingestion not completed due to invalid auth type.\n"

    threshold_size = utils.get_env_var(
        teamcymru_scout_env_constants.ENV_IP_ENRICHMENT_SIZE,
        required=False,
        default="200",
    )
    try:
      threshold_size = int(threshold_size.strip())
      if threshold_size <= 0 or threshold_size > 1000:
        raise ValueError
      teamcymru_scout_config["threshold_size"] = threshold_size
    except Exception:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Invalid value provided for the "
          f"{teamcymru_scout_env_constants.ENV_IP_ENRICHMENT_SIZE} "
          "environment variable. A valid value should be an integer "
          "greater than 0 and less than or equal to 1000.",
          severity="ERROR",
      )
      return "Ingestion not completed due to invalid threshold size.\n"

    ip_enrichment_tags = utils.get_env_var(
        teamcymru_scout_env_constants.ENV_IP_ENRICHMENT_TAGS,
        required=False,
        default="suspicious,malicious",
    )
    ip_enrichment_tags = [
        item.strip() for item in ip_enrichment_tags.split(",")
    ]  # noqa:E501
    teamcymru_scout_client_object = None  # pylint: disable=unused-variable
    account_usage_details = {}  # pylint: disable=unused-variable
    # Parse request body
    if request.data:
      try:
        request_body = json.loads(request.data)
      except json.decoder.JSONDecodeError:
        utils.cloud_logging(
            "Please pass a valid json in the request body.",
            severity="ERROR",  # noqa:E501
        )
        return (
            "Ingestion not completed due to "
            "invalid json in request body.\n"
        )  # noqa:E501

      ip_enrichment = False
      domain_search = False
      live_investigation = False  # pylint: disable=redefined-outer-name
      for key in request_body.keys():
        if key == "ip_enrichment":
          ip_enrichment = request_body.get("ip_enrichment")
          ip_enrichment = check_valid_arguments(
              "ip_enrichment", ip_enrichment
          )
        elif key == "domain_search":
          domain_search = request_body.get("domain_search")
          domain_search = check_valid_arguments(
              "domain_search", domain_search
          )
        elif key == "live_investigation":
          live_investigation = request_body.get("live_investigation")
          live_investigation = check_valid_arguments(
              "live_investigation", live_investigation
          )
        else:
          utils.cloud_logging(
              f"Skipping invalid configured feature: {key}: "
              f"{request_body.get(key)}.",  # noqa:E501
              severity="WARNING",
          )

      if ip_enrichment or domain_search or live_investigation:
        account_usage_details, teamcymru_scout_client_object = (
            get_scout_client_and_usage_details(
                teamcymru_scout_config, account_name
            )
        )
        if is_rate_limit_exceeded(account_usage_details, "search"):
          utils.cloud_logging(
              "Stopping Enrichment due to rate limit exceeded. "
              f"latest usage details: {account_usage_details}",
              severity="WARNING",
          )
          return "Ingestion not completed due to rate limit exceeded.\n"
        return adhoc_function(
            teamcymru_scout_client_object,
            account_usage_details,
            auth_type,
            ip_enrichment,
            domain_search,
            live_investigation,
            ip_enrichment_tags,
        )
      else:
        utils.cloud_logging(
            "Not a single valid feature set to True in the request body."
            " valid features: ip_enrichment, domain_search, live_investigation",
            severity="ERROR",
        )
        return (
            "Ingestion not completed due to error in"
            " request body parameter.\n"
        )
    account_usage_details, teamcymru_scout_client_object = (
        get_scout_client_and_usage_details(
            teamcymru_scout_config, account_name
        )  # noqa:E501
    )
    if is_rate_limit_exceeded(account_usage_details, "search"):
      utils.cloud_logging(
          "Stopping Enrichment due to rate limit exceeded. "
          f"latest usage details: {account_usage_details}",
          severity="WARNING",
      )
      return "Ingestion not completed due to rate limit exceeded.\n"
    return scheduled_function(
        teamcymru_scout_client_object,
        account_usage_details,
        auth_type,
        ip_enrichment_tags,
    )
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        f"Unexpected error occurred. Error: {e}", severity="ERROR"
    )  # noqa:E501
    return "Ingestion not completed.\n"
