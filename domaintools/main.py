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
"""Fetch the logs from Chronicle platform, enrich the domains and ingest them into Chronicle."""

import datetime
import json
import time
from typing import Any, Dict, List, Optional

import domaintools
from google.cloud import storage
import redis
import requests

from common import env_constants
from common import ingest
from common import utils
import domaintool_client
import fetch_logs
import domaintools_env_constants


client = redis.StrictRedis(
    host=utils.get_env_var(env_constants.ENV_REDIS_HOST, default="").strip(),
    port=utils.get_env_var(env_constants.ENV_REDIS_PORT, default="").strip(),
    decode_responses=True,
)


def get_and_ingest_events(
    chronicle_label: str,
    domain_list: List[str],
    function_mode: str,
    reference_list_name: Optional[str] = None,
) -> None:
  """Fetch enriched domains from the DomainTools platform and ingest it to Chronicle.

  Args:
      chronicle_label (str): Chronicle label by which data will be ingested.
      domain_list (List[str]): List of domains to enrich from DomainTools
      function_mode (str): Type of function mode
      reference_list_name (str): The name of the reference list. Defaults to "".

  Raises:
      RuntimeError: Unable to push the data to Chronicle
      Exception: Any other Exception raised
  """

  domaintool_user = utils.get_env_var(
      domaintools_env_constants.ENV_DOMAINTOOLS_API_USERNAME, is_secret=True
  ).strip()
  domaintool_password = utils.get_env_var(
      domaintools_env_constants.ENV_DOMAINTOOLS_API_KEY, is_secret=True
  ).strip()

  dnsdb_api = utils.get_env_var(
      domaintools_env_constants.ENV_DNSDB_API_KEY, required=False, default=""
  ).strip()
  dnsdb_api_exists = False
  if dnsdb_api:
    dnsdb_api = utils.get_value_from_secret_manager(dnsdb_api).strip()
    dnsdb_api_exists = True
  domain_tool_client_object = domaintool_client.DomainToolClient(
      domaintool_user, domaintool_password
  )
  if function_mode == "scheduler":
    # skip domains which are present in allow_list
    allow_list_name = utils.get_env_var(
        domaintools_env_constants.ENV_ALLOW_LIST, required=False, default=""
    ).strip()
    if allow_list_name:
      try:
        allow_list_domains = ingest.get_reference_list(allow_list_name)
      except Exception as error:  # pylint: disable=broad-except
        utils.cloud_logging(
            domaintools_env_constants.ERROR_MSG.format(error),
            severity="ERROR",
        )
        allow_list_domains = []
    else:
      allow_list_domains = []

    utils.cloud_logging("Validating domains in the memorystore.")
    temp_domains_list = domain_list.copy()
    # skip domains which is already present in redis
    try:
      for domain in domain_list:
        data = client.hget(domain, "value")
        if data or (domain in allow_list_domains):
          temp_domains_list.remove(domain)
    except Exception as error:
      raise RuntimeError(f"Error in Connecting to Redis: {error}") from error
    domain_list = temp_domains_list
    utils.cloud_logging("Domains validation completed in the memorystore.")

  utils.cloud_logging("Enriching domains from the DomainTools.")
  all_responses = []

  if len(domain_list) > 100:
    start_len = 0
    end_len = 100
    queue_len = len(domain_list)
    while queue_len > 0:
      queued_domains_part = domain_list[start_len:end_len]
      enriched_domains = get_enriched_domains(
          domain_tool_client_object, queued_domains_part
      )
      if enriched_domains:
        all_responses.append(enriched_domains)
      queue_len -= end_len - start_len
      start_len = end_len

      if queue_len > 100:
        end_len = start_len + 100
      else:
        end_len = start_len + queue_len
  else:
    enriched_domains = get_enriched_domains(
        domain_tool_client_object, domain_list
    )
    if enriched_domains:
      all_responses.append(enriched_domains)
  utils.cloud_logging("Domains enrichment completed.")

  if function_mode == "monitoring_domain":
    timestamp_monitoring_list = datetime.datetime.now().strftime(
        domaintools_env_constants.TIMESTAMP_FORMAT
    )

  dnsdb_domains_limit = utils.get_env_var(
      domaintools_env_constants.ENV_FETCH_SUBDOMAINS_FOR_MAX_DOMAINS,
      required=False,
      default="2000",
  ).strip()
  dnsdb_domains_limit = int(dnsdb_domains_limit)
  if dnsdb_api_exists and function_mode == "scheduler":
    utils.cloud_logging(
        "Fetching subdomains of the enriched domain(s) from DNSDB."
    )
    if dnsdb_domains_limit > 2000:
      utils.cloud_logging(
          "Provided greater value than the maximum value for"
          " FETCH_SUBDOMAINS_FOR_MAX_DOMAINS. Considering the default maximum"
          " value as 2000.",
          severity="WARNING",
      )
      dnsdb_domains_limit = 2000
  events = []
  redis_domain_list = []
  count_domains_for_dnsdb = 0
  for response in all_responses:
    for val in response.get("results"):
      events.append(val)
      if function_mode == "bulk_enrichment":
        continue
      if function_mode == "monitoring_domain":
        val["monitor_domain"] = True
        val["timestamp"] = timestamp_monitoring_list  # pylint: disable=undefined-variable
        val["monitoring_domain_list_name"] = reference_list_name
      principal_hostname = val.get("domain")
      if (
          dnsdb_api_exists
          and function_mode == "scheduler"
          and count_domains_for_dnsdb < dnsdb_domains_limit
      ):
        try:
          subdomains_list = get_subdomains(dnsdb_api, principal_hostname)
        except Exception as e:
          raise e
        val["subdomains"] = subdomains_list
        count_domains_for_dnsdb += 1
      components_array = val.get("domain_risk", {}).get("components", [])
      evidence = ""
      if components_array:
        for val in components_array:
          if "provisional" in val.get("evidence", []):
            evidence = "provisional"
            break
      current_timestamp = datetime.datetime.now().strftime(
          "%Y-%m-%dT%H:%M:%S.%f"
      )
      # Prepare a dictionary to store in the Redis Hash
      data_to_cache = {
          "value": principal_hostname,
          "created_timestamp": str(current_timestamp),
          "evidence": evidence,
      }
      redis_domain_list.append(data_to_cache)

  if dnsdb_api_exists and function_mode == "scheduler":
    utils.cloud_logging("Subdomains fetched successfully.")

  utils.cloud_logging(
      f"Total {len(events)} domain(s) enriched from DomainTools."
  )

  if events:
    try:
      utils.cloud_logging("Ingesting enriched domain events into Chronicle.")
      ingest.ingest(events, chronicle_label)
      utils.cloud_logging(
          "Enriched domains ingested successfully into Chronicle."
      )
    except Exception as error:
      raise RuntimeError(
          f"Unable to push data to Chronicle. {error}"
      ) from error

  if redis_domain_list:
    add_domains_to_redis(redis_domain_list)
    utils.cloud_logging("Domains added in the memorystore.")


def get_enriched_domains(
    domain_tool_client_object: Any, domains: List[str]
) -> Optional[List[Dict[str, str]]]:
  """Enrich the domains and return them.

  Args:
      domain_tool_client_object (ANY): DomainTools object to enrich domains
      domains (List[str]): Domains to enrich

  Raises:
      NotAuthorizedException: When request in unauthorized
      ServiceUnavailableException: When the Query limits are exhausted
      Exception: Any other Exception raised

  Returns:
      List: Enriched domains if the count of domains are greater than 0
      None: If the count of domains are not greater than 0
  """
  if domains:
    try_count = 0
    max_retries = 3
    while try_count < max_retries:
      try:
        response = domain_tool_client_object.enrich(domains)
        return response
      except domaintools.exceptions.NotAuthorizedException as e:
        raise e
      except domaintools.exceptions.ServiceUnavailableException as e:
        utils.cloud_logging(
            f"Attempt {try_count + 1} failed: {e}", severity="WARNING"
        )
        try_count += 1
        if try_count < max_retries:
          utils.cloud_logging("Retrying in 30 seconds...")
          time.sleep(30)
        else:
          utils.cloud_logging(
              "API call to DomainTools failed. Rate limit exceeded.",
              severity="ERROR",
          )
          raise e
      except Exception as e:
        raise e
  return None


def add_domains_to_redis(redis_domain_list: List[Dict[str, str]]):
  """Add the domains to redis for caching.

  Args:
      redis_domain_list (List[Dict[str, str]]): List of domains to add in redis

  Raises:
      Exception: Any Exception occured while adding domains to redis
  """
  provisional_ttl = utils.get_env_var(
      domaintools_env_constants.ENV_PROVISIONAL_TTL, required=False, default="1"
  ).strip()
  provisional_ttl = int(provisional_ttl)
  non_provisional_ttl = utils.get_env_var(
      domaintools_env_constants.ENV_NON_PROVISIONAL_TTL,
      required=False,
      default="30",
  ).strip()
  non_provisional_ttl = int(non_provisional_ttl)

  # Use the Redis HMSET command to set the dictionary in the Redis Hash
  for data_to_cache in redis_domain_list:
    domain = data_to_cache.get("value")
    evidence = data_to_cache.get("evidence")
    if data_to_cache.get("evidence"):
      del data_to_cache["evidence"]
    try:
      client.hmset(domain, data_to_cache)
      if evidence == "provisional":
        ttl = int(provisional_ttl) * 86400  # no of seconds in a day = 86400
      else:
        ttl = int(non_provisional_ttl) * 86400

      # Set the TTL for the key
      client.expire(domain, ttl)
    except Exception as e:
      utils.cloud_logging(
          "Error occurred while storing domains in the memory store."
      )
      raise e


def get_subdomains(dnsdb_api_key: str, domain: str):
  """Return a maximum of 10 subdomain for a domain.

  Args:
      dnsdb_api_key (str): API key for DNSDB
      domain (str): domain fetched from Chronicle

  Raises:
      Exception: Any Error from DNSDB API

  Returns:
      list: A list of subdomains
  """
  headers = {"X-API-KEY": dnsdb_api_key}
  dnsdb_response = requests.get(
      domaintools_env_constants.DNSDB_URL.format(domain),
      headers=headers,
      timeout=30,
  )
  if dnsdb_response.status_code == 200:
    unique_domains = []
    # Request was successful
    for line in dnsdb_response.iter_lines():
      if line:
        data = json.loads(line)  # If the response contains JSON data
        if data.get("cond"):
          continue
        data = data.get("obj")
        subdomain_name = data.get("rrname").rstrip(".")
        first_seen = data.get("time_first")
        last_seen = data.get("time_last")
        count = data.get("count")
        if subdomain_name != domain:
          if subdomain_name not in {
              domain_dict.get("subdomain") for domain_dict in unique_domains
          }:
            unique_domains.append({
                "subdomain": subdomain_name,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "count": count,
            })
            if len(unique_domains) == 10:
              break
    return unique_domains
  # Request was not successful
  utils.cloud_logging(
      f"Request failed with status code {dnsdb_response.status_code}",
      severity="ERROR",
  )
  raise Exception(dnsdb_response.text.replace("Error: ", ""))  # pylint: disable=broad-exception-raised


def generate_dummy_events(
    domains_tags: List[str], param_type: str, reference_list_name: str
) -> List[Dict[str, Any]]:
  """Generte dummy events for allow list and monitor tags.

  Args:
      domains_tags (List[str]): List of domains or tags
      param_type (str): flag to distinguish between allow_list and
        monitoring_tags
      reference_list_name (str): reference list name of allow list or monitoring
        tags

  Returns:
      List[Dict[str, Any]]: List of dummy events
  """
  dummy_event_list = []
  current_timestamp = datetime.datetime.now().strftime(
      domaintools_env_constants.TIMESTAMP_FORMAT
  )
  for field in domains_tags:
    temp_event = {"timestamp": current_timestamp}
    if param_type == "allow_list":
      temp_event["domain"] = field
      temp_event["allow_domain"] = True
      temp_event["allow_list_name"] = reference_list_name
    elif param_type == "monitoring_tags":
      temp_event["tag_name"] = field
      temp_event["monitor_tag"] = True
      temp_event["monitoring_tag_list_name"] = reference_list_name
    dummy_event_list.append(temp_event)
  return dummy_event_list


def adhoc_function(
    allow_list: bool = False,
    monitoring_list: bool = False,
    monitoring_tags: bool = False,
    bulk_enrichment: bool = False,
) -> str:
  """Process the given arguments to adhoc function and ingest the data into Chronicle.

  Args:
      allow_list (bool, optional): Value of Allow List Parameter. Defaults to
        False.
      monitoring_list (bool, optional): Value of Monitoring List Parameter.
        Defaults to False.
      monitoring_tags (bool, optional): Value of Monitoring Tags Parameter.
        Defaults to False.
      bulk_enrichment (bool, optional): Value of Bulk Enrichment Parameter.
        Defaults to False.

  Returns:
      str: whether the ingestion is completed or not
  """

  if monitoring_list:
    monitoring_list_name = utils.get_env_var(
        domaintools_env_constants.ENV_MONITORING_LIST,
        required=False,
        default="",
    ).strip()
    if monitoring_list_name:
      ingestion_status = monitoring_bulk_ingest(
          monitoring_list_name, "monitoring_domain"
      )
      if ingestion_status:
        return ingestion_status
    else:
      utils.cloud_logging(
          "Monitoring List reference list name is not provided in environment"
          " variable.",
          severity="ERROR",
      )
  if bulk_enrichment:
    bulk_enrichment_name = utils.get_env_var(
        domaintools_env_constants.ENV_BULK_ENRICHMENT,
        required=False,
        default="",
    ).strip()
    if bulk_enrichment_name:
      ingestion_status = monitoring_bulk_ingest(
          bulk_enrichment_name, "bulk_enrichment"
      )
      if ingestion_status:
        return ingestion_status
    else:
      utils.cloud_logging(
          "Bulk Enrichment reference list name is not provided in environment"
          " variable.",
          severity="ERROR",
      )
  if allow_list:
    allow_list_name = utils.get_env_var(
        domaintools_env_constants.ENV_ALLOW_LIST, required=False, default=""
    ).strip()
    if allow_list_name:
      ingestion_status = allow_tags_dummy_ingest(allow_list_name, "allow_list")
      if ingestion_status:
        return ingestion_status
    else:
      utils.cloud_logging(
          "Allow List reference list name is not provided in environment"
          " variable.",
          severity="ERROR",
      )
  if monitoring_tags:
    monitoring_tags_name = utils.get_env_var(
        domaintools_env_constants.ENV_MONITORING_TAGS,
        required=False,
        default="",
    ).strip()
    if monitoring_tags_name:
      ingestion_status = allow_tags_dummy_ingest(
          monitoring_tags_name, "monitoring_tags"
      )
      if ingestion_status:
        return ingestion_status
    else:
      utils.cloud_logging(
          "Monitoring Tag reference list name is not provided in environment"
          " variable.",
          severity="ERROR",
      )
  return "Ingestion Completed"


def scheduled_cloud_function() -> str:
  """Get the events from Chronicle, extract the domains and ingest the enriched domains into Chronicle.

  Returns:
      str: returns whether ingestion is completed or not
  """
  utils.cloud_logging("Fetching events from Chronicle.")
  gcp_bucket_name = utils.get_env_var(
      env_constants.ENV_GCP_BUCKET_NAME, default=""
  ).strip()
  if not gcp_bucket_name:
    utils.cloud_logging(
        "Empty value is provided for the"
        f" {env_constants.ENV_GCP_BUCKET_NAME} environment variable.",
        severity="ERROR",
    )
    return "Ingestion not Completed"
  storage_client = storage.Client()
  current_bucket = storage_client.get_bucket(gcp_bucket_name)
  try:
    blob = current_bucket.blob(
        utils.get_env_var(
            domaintools_env_constants.ENV_LOG_TYPE_FILE_PATH,
            required=False,
            default="file_does_not_exists",
        ).strip()
    )
    if blob.exists():
      log_types = blob.download_as_text()
    else:
      log_types = ""
      utils.cloud_logging(
          "Log type file is not provided or invalid value is provided. "
          "Considering all log type to fetch events from Chronicle.",
          severity="WARNING",
      )
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(f"An error occurred: {e}", severity="ERROR")
    return "Ingestion not Completed"
  object_fetch_log = fetch_logs.FetchEvents(log_types)
  try:
    (
        domain_list,
        checkpoint_blob,
        new_checkpoint,
    ) = object_fetch_log.fetch_data_and_checkpoint()
  except ValueError:
    return "Ingestion not Completed"
  except Exception as err:  # pylint: disable=broad-except
    utils.cloud_logging(f"Error in fetching events: {err}", severity="ERROR")
    return "Ingestion not Completed"
  utils.cloud_logging("Completed fetching events from Chronicle.")

  if not domain_list:
    utils.cloud_logging(
        "No domains found in the fetched events from Chronicle."
    )
    with checkpoint_blob.open(mode="w", encoding="utf-8") as json_file:
      json_file.write(json.dumps(new_checkpoint))
    utils.cloud_logging(
        "The start time for next execution is updated to"
        f" {new_checkpoint.get('time')}."
    )
    return "Ingestion not Completed"
  try:
    get_and_ingest_events(
        domaintools_env_constants.CHRONICLE_DATA_TYPE, domain_list, "scheduler"
    )
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(f"Error: {e}", severity="ERROR")
    return "Ingestion not Completed"
  with checkpoint_blob.open(mode="w", encoding="utf-8") as json_file:
    json_file.write(json.dumps(new_checkpoint))
  utils.cloud_logging(
      "The start time for next execution is updated to"
      f" {new_checkpoint.get('time')}."
  )
  return "Ingestion Completed"


def monitoring_bulk_ingest(list_name: str, list_type: str) -> Optional[str]:
  """Get the domains of monitoring list or bulk enrichment, enrich them and ingest in Chronicle.

  Args:
      list_name (str): name of monitoring or bulk enrichment reference list
      list_type (str): to identify monitoring_domain or bulk_enrichment type

  Returns:
      Optional[str]: str if ingestion is not completed, else None
  """
  try:
    list_domains = ingest.get_reference_list(list_name)
    if not list_domains:
      utils.cloud_logging(f"No domain found in the {list_name}.")
    else:
      get_and_ingest_events(
          domaintools_env_constants.CHRONICLE_DATA_TYPE,
          list_domains,
          list_type,
          list_name,
      )
  except RuntimeError as error:
    utils.cloud_logging(f"{error}", severity="ERROR")
    return "Ingestion not completed."
  except Exception as error:  # pylint: disable=broad-except
    utils.cloud_logging(f"Error: {error}", severity="ERROR")
  return None


def allow_tags_dummy_ingest(list_name: str, list_type: str) -> Optional[str]:
  """Ingest dummy events of allow list or monitorings tags into Chronicle.

  Args:
      list_name (str): name of allow or monitoring tags reference list
      list_type (str): to identify allow_list or monitoring_tags type

  Returns:
      Optional[str]: str if ingestion is not completed, else None
  """
  try:
    list_domains = ingest.get_reference_list(list_name)
    if not list_domains:
      utils.cloud_logging(f"No domain found in the {list_name}.")
      list_dummy_events = []
    else:
      list_dummy_events = generate_dummy_events(
          list_domains, list_type, list_name
      )
    if list_dummy_events:
      try:
        utils.cloud_logging(
            f"Ingesting {list_type} dummy event(s) into Chronicle."
        )
        ingest.ingest(
            list_dummy_events, domaintools_env_constants.CHRONICLE_DATA_TYPE
        )
        utils.cloud_logging(
            f"{list_type} dummy event(s) ingested successfully into Chronicle."
        )
      except Exception as error:  # pylint: disable=broad-except
        utils.cloud_logging(
            f"Unable to push data to Chronicle. Error: {error}",
            severity="ERROR",
        )
        return "Ingestion not completed"
  except Exception as error:  # pylint: disable=broad-except
    utils.cloud_logging(
        domaintools_env_constants.ERROR_MSG.format(error), severity="ERROR"
    )
  return None


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
      f"Please provide boolean value for {argument_name} argument.",
      severity="ERROR",
  )
  return False


def main(request) -> str:
  """Parse the request body and run scheduled or adhoc function.

  Args:
    request: Request to execute the cloud function.

  Returns:
      str: whether the ingestion is completed or not
  """
  try:
    int(
        utils.get_env_var(
            domaintools_env_constants.ENV_PROVISIONAL_TTL,
            required=False,
            default="1",
        ).strip()
    )
    int(
        utils.get_env_var(
            domaintools_env_constants.ENV_NON_PROVISIONAL_TTL,
            required=False,
            default="30",
        ).strip()
    )
  except ValueError:
    utils.cloud_logging(
        "An invalid value is provided for the TTL in the environment variable.",
        severity="ERROR",
    )
    return "Ingestion not Completed"
  try:
    int(
        utils.get_env_var(
            domaintools_env_constants.ENV_FETCH_SUBDOMAINS_FOR_MAX_DOMAINS,
            required=False,
            default="2000",
        ).strip()
    )
  except ValueError:
    utils.cloud_logging(
        "An invalid value is provided for the FETCH_SUBDOMAINS_FOR_MAX_DOMAINS"
        " in the environment variable.",
        severity="ERROR",
    )
    return "Ingestion not Completed"

  res = utils.get_env_var(env_constants.ENV_REDIS_HOST)
  if not res:
    utils.cloud_logging(
        "Empty value is provided for the"
        f" {env_constants.ENV_REDIS_HOST} environment variable.",
        severity="ERROR",
    )
    return "Ingestion not Completed"

  res = utils.get_env_var(env_constants.ENV_REDIS_PORT)
  if not res:
    utils.cloud_logging(
        "Empty value is provided for the"
        f" {env_constants.ENV_REDIS_PORT} environment variable.",
        severity="ERROR",
    )
    return "Ingestion not Completed"

  res = utils.get_env_var(
      domaintools_env_constants.ENV_DOMAINTOOLS_API_USERNAME
  )
  if not res:
    utils.cloud_logging(
        "Empty value is provided for the"
        f" {domaintools_env_constants.ENV_DOMAINTOOLS_API_USERNAME} environment"
        " variable.",
        severity="ERROR",
    )
    return "Ingestion not Completed"
  res = utils.get_env_var(domaintools_env_constants.ENV_DOMAINTOOLS_API_KEY)
  if not res:
    utils.cloud_logging(
        "Empty value is provided for the"
        f" {domaintools_env_constants.ENV_DOMAINTOOLS_API_KEY} environment"
        " variable.",
        severity="ERROR",
    )
    return "Ingestion not Completed"

  if request.data:
    try:
      request_body = json.loads(request.data)
    except json.decoder.JSONDecodeError:
      utils.cloud_logging(
          "Please pass a valid json as parameter.", severity="ERROR"
      )
      return "Ingestion not completed due to error in parameter.\n"
    if request_body:
      utils.cloud_logging("Running in Adhoc mode.")
      allow_list = False
      monitoring_list = False
      monitoring_tags = False
      bulk_enrichment = False
      for key in request_body.keys():
        if key == "allow_list":
          allow_list = request_body.get("allow_list")
          allow_list = check_valid_arguments("allow_list", allow_list)
        elif key == "monitoring_list":
          monitoring_list = request_body.get("monitoring_list")
          monitoring_list = check_valid_arguments(
              "monitoring_list", monitoring_list
          )
        elif key == "monitoring_tags":
          monitoring_tags = request_body.get("monitoring_tags")
          monitoring_tags = check_valid_arguments(
              "monitoring_tags", monitoring_tags
          )
        elif key == "bulk_enrichment":
          bulk_enrichment = request_body.get("bulk_enrichment")
          bulk_enrichment = check_valid_arguments(
              "bulk_enrichment", bulk_enrichment
          )
        else:
          utils.cloud_logging(
              f"Provided invalid key: {key}: {request_body[key]}.",
              severity="ERROR",
          )
      if allow_list or monitoring_list or monitoring_tags or bulk_enrichment:
        return adhoc_function(
            allow_list, monitoring_list, monitoring_tags, bulk_enrichment
        )
      utils.cloud_logging(
          "Provide valid parameters for adhoc.", severity="ERROR"
      )
      return "Provide valid parameters for adhoc.\n"
  utils.cloud_logging("Running in Scheduler mode.")
  return scheduled_cloud_function()
