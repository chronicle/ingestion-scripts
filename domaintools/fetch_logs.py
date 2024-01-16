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
"""Fetch the events from Chronicle and return the domains."""

import datetime
import json
import math
from typing import Any, List, Tuple

from google.cloud import storage
from google.oauth2 import service_account
from googleapiclient import _auth
import tldextract

from common import env_constants
from common import utils

# Environment variable constants.
BACKSTORY_API_V1_URL = "https://backstory.googleapis.com/v1"
SCOPES = ["https://www.googleapis.com/auth/chronicle-backstory"]
SERVICE_ACCOUNT_FILE = env_constants.ENV_CHRONICLE_SERVICE_ACCOUNT
ENV_CHECKPOINT_FILE_PATH = "CHECKPOINT_FILE_PATH"
ENV_LOG_FETCH_DURATION = "LOG_FETCH_DURATION"
ENV_FETCH_URL_EVENTS = "FETCH_URL_EVENTS"


class FetchEvents:
  """Fetch the events from Chronicle."""

  def __init__(self, log_types: str) -> None:
    self.log_types = log_types

  def fetch_data_and_checkpoint(self):
    """Fetch the checkpoint and fetch the data from Chronicle.

    Raises:
        ValueError: If invalid enivronment variables is provided
        Exception: Error in fetching file from bucket

    Returns:
        list, object, dict: list of domains, checkpoint object in bucket,
        updated checkpoint to store
    """
    try:
      end_time_duration = int(
          utils.get_env_var(ENV_LOG_FETCH_DURATION, default="").strip()
      )
    except ValueError as e:
      utils.cloud_logging(
          "Please provide integer value for LOG_FETCH_DURATION.",
          severity="ERROR",
      )
      raise e
    labels = self.divide_lable()
    parse_url = utils.get_env_var(
        ENV_FETCH_URL_EVENTS, required=False, default=""
    ).strip()
    parse_url_bool = self.convert_str_to_bool(parse_url)
    parse_query = self.get_parse_query(labels, parse_url_bool)
    gcp_bucket_name = utils.get_env_var(
        env_constants.ENV_GCP_BUCKET_NAME, default=""
    ).strip()
    if not gcp_bucket_name:
      raise ValueError(
          "Empty value is provided for the"
          f" {env_constants.ENV_GCP_BUCKET_NAME} environment variable."
      )
    current_bucket = storage.Client().get_bucket(gcp_bucket_name)
    checkpoint_blob = current_bucket.blob(
        utils.get_env_var(
            ENV_CHECKPOINT_FILE_PATH, required=False, default="checkpoint.json"
        ).strip()
    )
    try:
      if checkpoint_blob.exists():
        with checkpoint_blob.open(mode="r") as json_file:
          checkpoint_data = json.load(json_file)
          if (
              checkpoint_data.get("time") is None
              or not checkpoint_data.get("time")
          ):
            end_time = datetime.datetime.now()
            start_time = end_time - datetime.timedelta(seconds=1)
          else:
            try:
              start_time = datetime.datetime.strptime(
                  checkpoint_data.get("time"), "%Y-%m-%d %H:%M:%S"
              )
            except ValueError as e:
              utils.cloud_logging(
                  "Error occurred while fetching events from the Chronicle."
                  " Checkpoint time is not in the valid format.",
                  severity="ERROR",
              )
              raise e
            end_time = start_time + datetime.timedelta(
                seconds=end_time_duration
            )
      else:
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(seconds=1)
    except ValueError as e:
      raise e
    except Exception as err:
      utils.cloud_logging(
          f"Unable to get the file from bucket {err}", severity="ERROR"
      )
      raise err
    try:
      return self.fetch_data(
          parse_query,
          start_time,
          end_time,
          end_time_duration,
          checkpoint_blob,
          parse_url_bool,
      )
    except RuntimeError as e:
      utils.cloud_logging(
          f"Error in Chronicle service account. {e}",
          severity="ERROR",
      )
      raise e
    except Exception as e:
      raise e

  def fetch_data(
      self,
      parse_query: str,
      start_time: datetime.datetime,
      end_time: datetime.datetime,
      end_time_duration: int,
      checkpoint_blob: storage.Blob,
      parse_url_bool: bool,
  ):
    """Fetch the events from Chronicle and extract the domains.

    Args:
        parse_query (str): query to fetch events from Chronicle
        start_time (datetime): datetime object with the start time information
          for Chronicle
        end_time (datetime): datetime object with the end time information for
          Chronicle
        end_time_duration (int): duration to fetch the logs
        checkpoint_blob (storage.Blob): object of the checkpoint file
        parse_url_bool (bool): flag to parse url fields from Chronicle events

    Raises:
        RuntimeError: Error in fetching events from Chronicle

    Returns:
        list: list of domains
        checkpoint_blob: blob of the checkpoint file
        dict: new checkpoint
    """
    response = self.fetch_events(parse_query, start_time, end_time)
    if response[0].status == 200:
      aliases = response[1]
      # List of aliases returned for further processing
      domains_set = set()
      data = json.loads(aliases.decode("utf-8"))
      temp_event_count = 0
      if data.get("events"):
        if data.get("moreDataAvailable"):
          if (start_time + datetime.timedelta(minutes=1)) >= end_time:
            utils.cloud_logging(
                "Getting more than 10k events from Chronicle for 1 minute.",
                severity="WARNING",
            )
          else:
            new_end_time_duration = math.ceil(end_time_duration / 2)
            new_end_time = start_time + datetime.timedelta(
                seconds=new_end_time_duration
            )
            utils.cloud_logging(
                "Getting more than 10k events from Chronicle. We will "
                f"consider new end time as {new_end_time}"
            )
            return self.fetch_data(
                parse_query,
                start_time,
                new_end_time,
                new_end_time_duration,
                checkpoint_blob,
                parse_url_bool,
            )
          utils.cloud_logging(
              "Fetching domains from events fetched from the Chronicle."
          )
        for val in data.get("events", []):
          temp_event_count += 1
          principal_hostname = (
              val.get("udm", {}).get("principal", {}).get("hostname")
          )
          src_hostname = val.get("udm", {}).get("src", {}).get("hostname")
          target_hostname = val.get("udm", {}).get("target", {}).get("hostname")
          intermediary_hostname = []
          for value in val.get("udm", {}).get("intermediary", [{}]):
            if value.get("hostname"):
              intermediary_hostname.append(value.get("hostname"))
          observer_hostname = (
              val.get("udm", {}).get("observer", {}).get("hostname")
          )
          principal_asset_hostname = (
              val.get("udm", {})
              .get("principal", {})
              .get("asset", {})
              .get("hostname")
          )
          src_asset_hostname = (
              val.get("udm", {}).get("src", {}).get("asset", {}).get("hostname")
          )
          target_asset_hostname = (
              val.get("udm", {})
              .get("target", {})
              .get("asset", {})
              .get("hostname")
          )

          network_dns_domain = (
              val.get("udm", {}).get("network", {}).get("dnsDomain")
          )
          network_dns_questions_name = []
          for value in (
              val.get("udm", {})
              .get("network", {})
              .get("dns", {})
              .get("questions", [{}])
          ):
            if value.get("name"):
              network_dns_questions_name.append(value.get("name"))
          principal_administrative_domain = (
              val.get("udm", {})
              .get("principal", {})
              .get("administrativeDomain")
          )
          target_administrative_domain = (
              val.get("udm", {}).get("target", {}).get("administrativeDomain")
          )
          about_administrative_domain = []
          for value in val.get("udm", {}).get("about", [{}]):
            if value.get("administrativeDomain"):
              about_administrative_domain.append(
                  value.get("administrativeDomain")
              )
          about_hostname = []
          for value in val.get("udm", {}).get("about", [{}]):
            if value.get("hostname"):
              about_hostname.append(value.get("hostname"))
          principal_asset_network_domain = (
              val.get("udm", {})
              .get("principal", {})
              .get("asset", {})
              .get("networkDomain")
          )
          target_asset_network_domain = (
              val.get("udm", {})
              .get("target", {})
              .get("asset", {})
              .get("networkDomain")
          )
          about_asset_network_domain = []
          for value in val.get("udm", {}).get("about", [{}]):
            if value.get("asset", {}).get("networkDomain"):
              about_asset_network_domain.append(
                  value.get("asset", {}).get("networkDomain")
              )
          about_domain_name = []
          for value in val.get("udm", {}).get("about", [{}]):
            if value.get("domain", {}).get("name"):
              about_domain_name.append(value.get("domain", {}).get("name"))
          about_asset_hostname = []
          for value in val.get("udm", {}).get("about", [{}]):
            if value.get("asset", {}).get("hostname"):
              about_asset_hostname.append(
                  value.get("asset", {}).get("hostname")
              )
          about_network_dns_questions_name = []
          for value in val.get("udm", {}).get("about", [{}]):
            for value2 in (
                value.get("network", {}).get("dns", {}).get("questions", [{}])
            ):
              if value2.get("name"):
                about_network_dns_questions_name.append(value2.get("name"))
          about_network_dns_domain = []
          for value in val.get("udm", {}).get("about", [{}]):
            if value.get("network", {}).get("dnsDomain"):
              about_network_dns_domain.append(
                  value.get("network", {}).get("dnsDomain")
              )
          intermediary_administrative_domain = []
          for value in val.get("udm", {}).get("intermediary", [{}]):
            if value.get("administrativeDomain"):
              intermediary_administrative_domain.append(
                  value.get("administrativeDomain")
              )
          intermediary_domain_name = []
          for value in val.get("udm", {}).get("intermediary", [{}]):
            if value.get("domain", {}).get("name"):
              intermediary_domain_name.append(
                  value.get("domain", {}).get("name")
              )
          intermediary_network_dns_questions_name = []
          for value in val.get("udm", {}).get("intermediary", [{}]):
            for value2 in (
                value.get("network", {}).get("dns", {}).get("questions", [{}])
            ):
              if value2.get("name"):
                intermediary_network_dns_questions_name.append(
                    value2.get("name")
                )
          intermediary_network_dns_domain = []
          for value in val.get("udm", {}).get("intermediary", [{}]):
            if value.get("network", {}).get("dnsDomain"):
              intermediary_network_dns_domain.append(
                  value.get("network", {}).get("dnsDomain")
              )
          intermediary_asset_hostname = []
          for value in val.get("udm", {}).get("intermediary", [{}]):
            if value.get("asset", {}).get("hostname"):
              intermediary_asset_hostname.append(
                  value.get("asset", {}).get("hostname")
              )
          intermediary_asset_network_domain = []
          for value in val.get("udm", {}).get("intermediary", [{}]):
            if value.get("asset", {}).get("networkDomain"):
              intermediary_asset_network_domain.append(
                  value.get("asset", {}).get("networkDomain")
              )
          observer_administrative_domain = (
              val.get("udm", {}).get("observer", {}).get("administrativeDomain")
          )
          observer_domain_name = (
              val.get("udm", {})
              .get("observer", {})
              .get("domain", {})
              .get("name")
          )
          observer_network_dns_questions_name = []
          for value in (
              val.get("udm", {})
              .get("observer", {})
              .get("network", {})
              .get("dns", {})
              .get("questions", [{}])
          ):
            if value.get("name"):
              observer_network_dns_questions_name.append(value.get("name"))
          observer_network_dns_domain = (
              val.get("udm", {})
              .get("observer", {})
              .get("network", {})
              .get("dnsDomain")
          )
          observer_asset_hostname = (
              val.get("udm", {})
              .get("observer", {})
              .get("asset", {})
              .get("hostname")
          )
          observer_asset_network_domain = (
              val.get("udm", {})
              .get("observer", {})
              .get("asset", {})
              .get("networkDomain")
          )
          principal_domain_name = (
              val.get("udm", {})
              .get("principal", {})
              .get("domain", {})
              .get("name")
          )
          principal_network_dns_questions_name = []
          for value in (
              val.get("udm", {})
              .get("principal", {})
              .get("network", {})
              .get("dns", {})
              .get("questions", [{}])
          ):
            if value.get("name"):
              principal_network_dns_questions_name.append(value.get("name"))
          principal_network_dns_domain = (
              val.get("udm", {})
              .get("principal", {})
              .get("network", {})
              .get("dnsDomain")
          )
          src_administrative_domain = (
              val.get("udm", {}).get("src", {}).get("administrativeDomain")
          )
          src_domain_name = (
              val.get("udm", {}).get("src", {}).get("domain", {}).get("name")
          )
          src_network_dns_questions_name = []
          for value in (
              val.get("udm", {})
              .get("src", {})
              .get("network", {})
              .get("dns", {})
              .get("questions", [{}])
          ):
            if value.get("name"):
              src_network_dns_questions_name.append(value.get("name"))
          src_network_dns_domain = (
              val.get("udm", {})
              .get("src", {})
              .get("network", {})
              .get("dnsDomain")
          )
          src_asset_network_domain = (
              val.get("udm", {})
              .get("src", {})
              .get("asset", {})
              .get("networkDomain")
          )
          target_domain_name = (
              val.get("udm", {}).get("target", {}).get("domain", {}).get("name")
          )
          target_network_dns_questions_name = []
          for value in (
              val.get("udm", {})
              .get("target", {})
              .get("network", {})
              .get("dns", {})
              .get("questions", [{}])
          ):
            if value.get("name"):
              target_network_dns_questions_name.append(value.get("name"))
          target_network_dns_domain = (
              val.get("udm", {})
              .get("target", {})
              .get("network", {})
              .get("dnsDomain")
          )

          fields = [
              principal_hostname,
              src_hostname,
              target_hostname,
              *intermediary_hostname,
              observer_hostname,
              principal_asset_hostname,
              src_asset_hostname,
              target_asset_hostname,
              network_dns_domain,
              *network_dns_questions_name,
              principal_administrative_domain,
              target_administrative_domain,
              *about_administrative_domain,
              *about_hostname,
              principal_asset_network_domain,
              target_asset_network_domain,
              *about_asset_network_domain,
              *about_domain_name,
              *about_asset_hostname,
              *about_network_dns_questions_name,
              *about_network_dns_domain,
              *intermediary_administrative_domain,
              *intermediary_domain_name,
              *intermediary_network_dns_questions_name,
              *intermediary_network_dns_domain,
              *intermediary_asset_hostname,
              *intermediary_asset_network_domain,
              observer_administrative_domain,
              observer_domain_name,
              *observer_network_dns_questions_name,
              observer_network_dns_domain,
              observer_asset_hostname,
              observer_asset_network_domain,
              principal_domain_name,
              *principal_network_dns_questions_name,
              principal_network_dns_domain,
              src_administrative_domain,
              src_domain_name,
              *src_network_dns_questions_name,
              src_network_dns_domain,
              src_asset_network_domain,
              target_domain_name,
              *target_network_dns_questions_name,
              target_network_dns_domain,
          ]
          if parse_url_bool:
            principal_url = val.get("udm", {}).get("principal", {}).get("url")
            about_url = []
            for value in val.get("udm", {}).get("about", [{}]):
              if value.get("url"):
                about_url.append(value.get("url"))
            src_url = val.get("udm", {}).get("src", {}).get("url")
            target_url = val.get("udm", {}).get("target", {}).get("url")
            intermediary_url = []
            for value in val.get("udm", {}).get("intermediary", [{}]):
              if value.get("url"):
                intermediary_url.append(value.get("url"))
            observer_url = val.get("udm", {}).get("observer", {}).get("url")
            metadata_url_back_to_product = (
                val.get("udm", {}).get("metadata", {}).get("urlBackToProduct")
            )
            security_result_url_back_to_product = []
            for value in val.get("udm", {}).get("securityResult", [{}]):
              if value.get("urlBackToProduct"):
                security_result_url_back_to_product.append(
                    value.get("urlBackToProduct")
                )
            url_fields = [
                principal_url,
                *about_url,
                src_url,
                target_url,
                *intermediary_url,
                observer_url,
                metadata_url_back_to_product,
                *security_result_url_back_to_product,
            ]
            fields.extend(url_fields)
          for field in fields:
            if field is not None:
              domain_result = tldextract.extract(field.replace("\\", ""))
              registered_domain = domain_result.registered_domain
              if registered_domain:
                domains_set.add(registered_domain)
      utils.cloud_logging(
          f"Total {temp_event_count} events fetched from Chronicle."
      )

      utils.cloud_logging("Domains extracted from Chronicle events.")

      new_checkpoint_time = end_time.strftime("%Y-%m-%d %H:%M:%S")
      new_checkpoint = {"time": new_checkpoint_time}
      domains_list = list(domains_set)
      if domains_list:
        utils.cloud_logging(f"Extracted Domains: {str(domains_list)}")
      return domains_list, checkpoint_blob, new_checkpoint
    # An error occurred. See the response for details.
    err = response[1]
    raise RuntimeError(err)

  def fetch_events(
      self,
      parse_query: str,
      start_time: datetime.datetime,
      end_time: datetime.datetime,
  ) -> Tuple[Any, ...]:
    """Fetch the events from Chronicle and return the events.

    Args:
        parse_query (str): query to fetch events from Chronicle
        start_time (datetime): datetime object with the start time information
          for Chronicle
        end_time (datetime): datetime object with the end time information for
          Chronicle

    Raises:
        RuntimeError: Invalid service account JSON
        ValueError: Invalid Service account
        Exception: Any exception from Chronicle

    Returns:
        Tuple[Any]: query status code and events from Chronicle
    """
    query_start_time = (
        f"{start_time.year}-{start_time.month}-{start_time.day}T{start_time.hour}"
        f"%3A{start_time.minute}%3A{start_time.second}Z"
    )
    query_end_time = (
        f"{end_time.year}-{end_time.month}-{end_time.day}T{end_time.hour}"
        f"%3A{end_time.minute}%3A{end_time.second}Z"
    )

    list_user_aliases_url = (
        f"{BACKSTORY_API_V1_URL}/events:udmSearch?query={parse_query}"
        f"&time_range.start_time={query_start_time}&time_range.end_time={query_end_time}"
    )
    service_account_json = utils.get_env_var(
        SERVICE_ACCOUNT_FILE, is_secret=True
    ).strip()
    try:
      service_account_json = json.loads(service_account_json)
    except json.JSONDecodeError as error:
      raise RuntimeError("Invalid Service Account JSON provided.") from error
    try:
      credentials = service_account.Credentials.from_service_account_info(
          service_account_json, scopes=SCOPES
      )
    except ValueError as e:
      raise e
    http_client = _auth.authorized_http(credentials)
    try:
      response = http_client.request(list_user_aliases_url, "GET")
    except Exception as e:
      raise e
    return response

  def convert_str_to_bool(self, value: str) -> bool:
    """Convert string to boolean.

    Args:
        value (str): any string value

    Returns:
        bool: parse the value field and return the boolean value
    """
    if str(value).lower() == "true":
      return True
    if str(value).lower() == "false" or not str(value):
      return False
    utils.cloud_logging(
        f"Please provide boolean value for {ENV_FETCH_URL_EVENTS} environment"
        " variable. Considering default value as false.",
        severity="WARNING",
    )
    return False

  def divide_lable(self) -> List[str]:
    """This function takes the string of log types, which are comma seperated, and convert that to a list.

    Returns:
        List[str]: List of all the log types to consider for fetching
    """
    if not self.log_types:
      return []
    log_types_list = [label.strip() for label in self.log_types.split(",")]
    return log_types_list

  def get_parse_query(self, labels: List[str], parse_url_bool: bool) -> str:
    """Return the parse query for Chronicle.

    Args:
        labels (List[str]): list of labels to parse
        parse_url_bool (bool): flag to parse url fields from Chronicle

    Returns:
        str: parse query for Chronicle to fetch events
    """
    label_size = len(labels)
    if label_size > 0:
      parse_query = "("
    else:
      parse_query = ""
    for val, data in enumerate(labels):
      parse_query += f'metadata.log_type+%3D+"{data}"'
      if val < label_size - 1:
        parse_query += "+or+"
    if label_size > 0:
      parse_query += ")%20AND%20("

    parse_query += (
        "about.hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www"
        "%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F"
        "(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20domain%20%3D"
        "%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%"
        "2F%3F%5Cn%5D%2B)%2F%20or%20about.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E"
        "@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20about.asset.hostname%20"
        "%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%"
        "5C%2F%3F%5Cn%5D%2B)%2F%20or%20about.network.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C"
        "%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20about"
        ".network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3"
        "F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.administrative_domain%20%3D%20%2F%5"
        "E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5C"
        "n%5D%2B)%2F%20or%20intermediary.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@"
        "%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.network.dns"
        ".questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:ww"
        "w%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.network.dns_domain%20%3D%20%2F%5E(%3F:h"
        "ttps%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B"
        ")%2F%20or%20intermediary.asset.hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%"
        "2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.asset.network_d"
        "omain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F("
        "%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.administrative_domain%20%3D%20%2F%5E(%3F:https%3F:%5C"
        "%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%2"
        "0observer.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F("
        "%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.network.dns.questions.name%20%3D%20%2"
        "F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F"
        "%5Cn%5D%2B)%2F%20or%20observer.network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%"
        "5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.asset.hos"
        "tname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F("
        "%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20observer.asset.network_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%"
        "2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20"
        "principal.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F("
        "%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20principal.network.dns.questions.name%20%3D%20%"
        "2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3"
        "F%5Cn%5D%2B)%2F%20or%20principal.network.dns_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F"
        ":%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.administrati"
        "ve_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)"
        "%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.domain.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%"
        "3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.networ"
        "k.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%"
        "3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src.network.dns_domain%20%3D%20%2F%5E(%3F:https"
        "%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F"
        "%20or%20src.asset.network_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%"
        "5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20target.domain.name%20%3D%20%2F%5E(%"
        "3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5"
        "D%2B)%2F%20or%20target.network.dns.questions.name%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%"
        "5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20target.network.dns"
        "_domain%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3"
        "F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F"
    )
    if parse_url_bool:
      url_query = (
          "%20or%20principal.url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F("
          "%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20about.url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5"
          "C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20src."
          "url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5"
          "B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20target.url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%"
          "5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20intermediary.url%20%3"
          "D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C"
          "%2F%3F%5Cn%5D%2B)%2F%20or%20observer.url%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C"
          "%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20metadata.url_back_to_produc"
          "t%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%"
          "5E:%5C%2F%3F%5Cn%5D%2B)%2F%20or%20security_result.url_back_to_product%20%3D%20%2F%5E(%3F:https%3F:%5"
          "C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www%5C.)%3F(%5B%5E:%5C%2F%3F%5Cn%5D%2B)%2F"
      )
      parse_query += url_query
    if label_size > 0:
      parse_query += ")"

    return parse_query
