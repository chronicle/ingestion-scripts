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
ENV_FETCH_DOMAIN_EVENTS = "FETCH_DOMAIN_EVENTS"


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
          utils.get_env_var(
              ENV_LOG_FETCH_DURATION, required=False, default="60"
          ).strip()
      )
      if end_time_duration <= 0:
        raise ValueError
    except ValueError as e:
      utils.cloud_logging(
          "Please provide non-zero positive integer value for "
          "LOG_FETCH_DURATION.",
          severity="ERROR",
      )
      raise e
    labels = self.divide_labels()
    parse_domain = utils.get_env_var(
        ENV_FETCH_DOMAIN_EVENTS, required=False, default="false"
    ).strip()
    parse_domain_bool = self.convert_str_to_bool(parse_domain)
    parse_query = self.get_parse_query(labels, parse_domain_bool)
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
          if checkpoint_data.get("time") is None or not checkpoint_data.get(
              "time"
          ):
            end_time = datetime.datetime.now()
            start_time = end_time - datetime.timedelta(seconds=60)
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
        start_time = end_time - datetime.timedelta(seconds=60)
    except ValueError as e:
      raise e
    except Exception as err:
      utils.cloud_logging(
          f"Unable to get the file from bucket {err}", severity="ERROR"
      )
      raise err
    try:
      current_time = datetime.datetime.now()
      if end_time > current_time:
        end_time = current_time
        utils.cloud_logging(
            "End time is greater than the current time. "
            f"Setting end time as the current time {current_time}.",
            severity="INFO",
        )
      utils.cloud_logging(
          f"Events will be fetched in between from {start_time} to {end_time}",
          severity="INFO",
      )
      return self.fetch_data(
          parse_query,
          start_time,
          end_time,
          end_time_duration,
          checkpoint_blob,
          parse_domain_bool,
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
      parse_domain_bool: bool,
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
      parse_domain_bool (bool): flag to parse url fields from Chronicle events

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
      ip_set = set()
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
                parse_domain_bool,
            )
          utils.cloud_logging(
              "Fetching domains from events fetched from the Chronicle."
          )

        for val in data.get("events", []):
          temp_event_count += 1

          ip_fields = self.extract_ips(val)
          ip_set.update(ip_fields)

          if parse_domain_bool:
            fields = self.extract_domains(val)
            for field in fields:
              domain_result = tldextract.extract(field.replace("\\", ""))
              registered_domain = domain_result.registered_domain
              if registered_domain:
                domains_set.add(registered_domain)

      utils.cloud_logging(
          f"Total {temp_event_count} events fetched from Chronicle."
      )

      new_checkpoint_time = end_time.strftime("%Y-%m-%d %H:%M:%S")
      new_checkpoint = {"time": new_checkpoint_time}
      domains_list = list(domains_set)
      if domains_list:
        utils.cloud_logging(f"Extracted Domains: {str(domains_list)}")
      ip_list = list(ip_set)
      if ip_list:
        utils.cloud_logging(f"Extracted IPs: {str(ip_list)}")
      return ip_list, domains_list, checkpoint_blob, new_checkpoint
    # An error occurred. See the response for details.
    err = response[1]
    raise RuntimeError(err)

  def extract_domains(self, value):
    """Extract domains from the data structure.

    Args:
      value (dict): Dictionary containing the data.

    Returns:
      list: List of domains.
    """
    udm = value.get("udm")

    fields = [
        udm.get("principal", {}).get("hostname"),
        udm.get("src", {}).get("hostname"),
        udm.get("target", {}).get("hostname"),
        *[
            intermediate.get("hostname")
            for intermediate in udm.get("intermediary", [{}])
        ],
        udm.get("observer", {}).get("hostname"),
        udm.get("principal", {}).get("asset", {}).get("hostname"),
        udm.get("src", {}).get("asset", {}).get("hostname"),
        udm.get("target", {}).get("asset", {}).get("hostname"),
        udm.get("network", {}).get("dnsDomain"),
        *[
            question.get("name")
            for question in udm.get("network", {})
            .get("dns", {})
            .get("questions", [{}])
        ],
        udm.get("principal", {}).get("administrativeDomain"),
        udm.get("target", {}).get("administrativeDomain"),
        *[
            about.get("administrativeDomain")
            for about in udm.get("about", [{}])
            ],
        *[about.get("hostname") for about in udm.get("about", [{}])],
        udm.get("principal", {}).get("asset", {}).get("networkDomain"),
        udm.get("target", {}).get("asset", {}).get("networkDomain"),
        *[
            about.get("asset", {}).get("networkDomain")
            for about in udm.get("about", [{}])
        ],
        *[
            about.get("domain", {}).get("name")
            for about in udm.get("about", [{}])
            ],
        *[
            about.get("asset", {}).get("hostname")
            for about in udm.get("about", [{}])
        ],
        *[
            question.get("name")
            for question in [
                question    # pylint: disable=g-complex-comprehension
                for about in udm.get("about", [{}])
                for question in about.get("network", {})
                .get("dns", {})
                .get("questions", [{}])
            ]
        ],
        *[
            about.get("network", {}).get("dnsDomain")
            for about in udm.get("about", [{}])
        ],
        *[
            intermediate.get("administrativeDomain")
            for intermediate in udm.get("intermediary", [{}])
        ],
        *[
            intermediate.get("domain", {}).get("name")
            for intermediate in udm.get("intermediary", [{}])
        ],
        *[
            question.get("name")
            for question in [
                question    # pylint: disable=g-complex-comprehension
                for intermediate in udm.get("intermediary", [{}])
                for question in intermediate.get("network", {})
                .get("dns", {})
                .get("questions", [{}])
            ]
        ],
        *[
            intermediate.get("network", {}).get("dnsDomain")
            for intermediate in udm.get("intermediary", [{}])
        ],
        *[
            intermediate.get("asset", {}).get("hostname")
            for intermediate in udm.get("intermediary", [{}])
        ],
        *[
            intermediate.get("asset", {}).get("networkDomain")
            for intermediate in udm.get("intermediary", [{}])
        ],
        udm.get("observer", {}).get("administrativeDomain"),
        udm.get("observer", {}).get("domain", {}).get("name"),
        *[
            question.get("name")
            for question in udm.get("observer", {})
            .get("network", {})
            .get("dns", {})
            .get("questions", [{}])
        ],
        udm.get("observer", {}).get("network", {}).get("dnsDomain"),
        udm.get("observer", {}).get("asset", {}).get("hostname"),
        udm.get("observer", {}).get("asset", {}).get("networkDomain"),
        udm.get("principal", {}).get("domain", {}).get("name"),
        *[
            question.get("name")
            for question in udm.get("principal", {})
            .get("network", {})
            .get("dns", {})
            .get("questions", [{}])
        ],
        udm.get("principal", {}).get("network", {}).get("dnsDomain"),
        udm.get("src", {}).get("administrativeDomain"),
        udm.get("src", {}).get("domain", {}).get("name"),
        *[
            question.get("name")
            for question in udm.get("src", {})
            .get("network", {})
            .get("dns", {})
            .get("questions", [{}])
        ],
        udm.get("src", {}).get("network", {}).get("dnsDomain"),
        udm.get("src", {}).get("asset", {}).get("networkDomain"),
        udm.get("target", {}).get("domain", {}).get("name"),
        *[
            question.get("name")
            for question in udm.get("target", {})
            .get("network", {})
            .get("dns", {})
            .get("questions", [{}])
        ],
        udm.get("target", {}).get("network", {}).get("dnsDomain"),
    ]

    domain_fields = [field for field in fields if field]

    return domain_fields

  def extract_ips(self, value):
    """Extract IPs from the data structure.

    Args:
      value (dict): Dictionary containing the data.

    Returns:
      list: List of IPs.
    """
    udm = value.get("udm", {})
    about = udm.get("about", [{}])
    intermediary = udm.get("intermediary", [{}])
    observer = udm.get("observer", {})
    principal = udm.get("principal", {})
    target = udm.get("target", {})
    src = udm.get("src", {})

    def get_artifact_ip_values(data, key="artifact", sub_key="ip"):
      if isinstance(data, list):
        return [
            item.get(key, {}).get(sub_key, "")
            for item in data
            if item.get(key, {}).get(sub_key, "")
        ]
      elif isinstance(data, dict):
        return [data.get(key, {}).get(sub_key, "")]
      return []

    def get_ip_values(data, key="ip"):
      if isinstance(data, list):
        return [ip for item in data for ip in item.get(key, []) if ip]    # pylint: disable=g-complex-comprehension
      elif isinstance(data, dict):
        return [ip for ip in data.get(key, []) if ip]
      return []

    def get_nat_ip_values(data, key="nat_ip"):
      if isinstance(data, list):
        return [ip for item in data for ip in item.get(key, []) if ip]    # pylint: disable=g-complex-comprehension
      elif isinstance(data, dict):
        return [ip for ip in data.get(key, []) if ip]
      return []

    def get_asset_ip_values(data, key="asset", sub_key="ip"):
      if isinstance(data, list):
        return [
            ip    # pylint: disable=g-complex-comprehension
            for item in data
            for ip in item.get(key, {}).get(sub_key, [])
            if ip
        ]
      elif isinstance(data, dict):
        return [ip for ip in data.get(key, {}).get(sub_key, []) if ip]
      return []

    def get_asset_nat_ip_values(data, key="asset", sub_key="nat_ip"):
      if isinstance(data, list):
        return [
            ip    # pylint: disable=g-complex-comprehension
            for item in data
            for ip in item.get(key, {}).get(sub_key, [])
            if ip
        ]
      elif isinstance(data, dict):
        return [ip for ip in data.get(key, {}).get(sub_key, []) if ip]
      return []

    # Collect IP fields
    ip_fields = (
        get_artifact_ip_values(about)
        + get_artifact_ip_values(intermediary)
        + get_artifact_ip_values(observer)
        + get_artifact_ip_values(principal)
        + get_artifact_ip_values(target)
        + get_artifact_ip_values(src)
        + get_ip_values(about)
        + get_ip_values(intermediary)
        + get_ip_values(observer)
        + get_ip_values(principal)
        + get_ip_values(target)
        + get_ip_values(src)
        + get_nat_ip_values(about)
        + get_nat_ip_values(intermediary)
        + get_nat_ip_values(observer)
        + get_nat_ip_values(principal)
        + get_nat_ip_values(target)
        + get_nat_ip_values(src)
        + get_asset_ip_values(about)
        + get_asset_ip_values(intermediary)
        + get_asset_ip_values(observer)
        + get_asset_ip_values(principal)
        + get_asset_ip_values(target)
        + get_asset_ip_values(src)
        + get_asset_nat_ip_values(about)
        + get_asset_nat_ip_values(intermediary)
        + get_asset_nat_ip_values(observer)
        + get_asset_nat_ip_values(principal)
        + get_asset_nat_ip_values(target)
        + get_asset_nat_ip_values(src)
    )

    # Flatten the list and remove None values
    ip_fields = [ip for ip in ip_fields if ip]

    return ip_fields

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
        f"Please provide boolean value for {ENV_FETCH_DOMAIN_EVENTS} "
        "environment variable. Considering default value as false.",
        severity="WARNING",
    )
    return False

  def divide_labels(self) -> List[str]:
    """This function takes the string of log types, which are comma seperated, and convert that to a list.

    Returns:
      List[str]: List of all the log types to consider for fetching
    """
    if not self.log_types:
      return []
    log_types_list = [label.strip() for label in self.log_types.split(",")]
    return log_types_list

  def get_parse_query(self, labels: List[str], parse_domain_bool: bool) -> str:
    """Return the parse query for Chronicle.

    Args:
      labels (List[str]): list of labels to parse
      parse_domain_bool (bool): flag to parse url fields from Chronicle

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
        'about.ip%20!%3D%20""%20OR%20about.nat_ip%20!%3D%20""%20OR%20about.asset.ip%20!%3D%20""%20'
        'OR%20about.asset.nat_ip%20!%3D%20""%20OR%20about.artifact.ip%20!%3D%20""%20OR%20'
        'intermediary.ip%20!%3D%20""%20OR%20intermediary.nat_ip%20!%3D%20""%20OR%20'
        'intermediary.asset.ip%20!%3D%20""%20OR%20intermediary.asset.nat_ip%20!%3D%20""%20OR%20'
        'intermediary.artifact.ip%20!%3D%20""%20OR%20observer.ip%20!%3D%20""%20OR%20'
        'observer.nat_ip%20!%3D%20""%20OR%20observer.asset.ip%20!%3D%20""%20OR%20'
        'observer.asset.nat_ip%20!%3D%20""%20OR%20observer.artifact.ip%20!%3D%20""%20OR%20'
        'principal.ip%20!%3D%20""%20OR%20principal.nat_ip%20!%3D%20""%20OR%20'
        'principal.asset.ip%20!%3D%20""%20OR%20principal.asset.nat_ip%20!%3D%20""%20OR%20'
        'principal.artifact.ip%20!%3D%20""%20OR%20target.ip%20!%3D%20""%20OR%20'
        'target.nat_ip%20!%3D%20""%20OR%20target.asset.ip%20!%3D%20""%20OR%20'
        'target.asset.nat_ip%20!%3D%20""%20OR%20target.artifact.ip%20!%3D%20""%20OR%20'
        'src.ip%20!%3D%20""%20OR%20src.nat_ip%20!%3D%20""%20OR%20src.asset.ip%20!%3D%20""%20OR%20'
        'src.asset.nat_ip%20!%3D%20""%20OR%20src.artifact.ip%20!%3D%20""%20'
    )
    if parse_domain_bool:
      parse_query += (
          "OR%20about.hostname%20%3D%20%2F%5E(%3F:https%3F:%5C%2F%5C%2F)%3F(%3F:%5B%5E@%5C%2F%5Cn%5D%2B@)%3F(%3F:www"
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
    if label_size > 0:
      parse_query += ")"

    return parse_query
