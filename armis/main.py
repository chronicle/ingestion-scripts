# Copyright 2022 Google LLC
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
"""Fetch logs from the Armis platform and ingest it to Chronicle."""

import datetime
import multiprocessing
from typing import Any, Dict, List
from urllib import parse

import armis_client
from common import ingest
from common import utils

# Environment variable constants.
ENV_ARMIS_SERVER_URL = "ARMIS_SERVER_URL"
ENV_ARMIS_API_SECRET_KEY = "ARMIS_API_SECRET_KEY"
ENV_POLL_INTERVAL = "POLL_INTERVAL"
ENV_CHRONICLE_DATA_TYPE = "CHRONICLE_DATA_TYPE"

# Dateformat supported by Armis API.
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

# Key which contains link to the Armis vulnerability overview.
VULNERABILITY_MATCHES = "vulnerabilities_matches"

# Labels supported by Chronicle.
SUPPORTED_LABELS = {
    "ARMIS_ALERTS": "alerts",
    "ARMIS_ACTIVITIES": "activity",
    "ARMIS_DEVICES": "devices",
    "ARMIS_VULNERABILITIES": "vulnerabilities",
}

# Label displayed in logs.
PRINT_LABEL = {"activity": "activities"}

# Dictionary for order by value for Armis labels.
GET_ORDER_BY = {
    "alerts": "time",
    "activity": "time",
    "devices": "id",
    "vulnerabilities": "publishedDate",
}

# Initial value of expiration time.
INITIAL_EXPIRATION_TIME = ""

# Error message for invalid Chronicle label.
INVALID_CHRONICLE_LABEL_PROVIDED = lambda invalid_chronicle_labels: (  # pylint: disable=g-long-lambda
    f"Invalid Chronicle data type(s) {invalid_chronicle_labels} provided. "
    "Supported Labels: ARMIS_ALERTS, ARMIS_ACTIVITIES, "
    "ARMIS_DEVICES, ARMIS_VULNERABILITIES"
)

# Error message for duplicate Chronicle label.
DUPLICATE_CHRONICLE_LABEL_PROVIDED = lambda duplicate_chronicle_labels: (  # pylint: disable=g-long-lambda
    f"Chronicle data type(s) {duplicate_chronicle_labels} provided more "
    "than once."
)


def filter_and_add_link_in_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
    start_time: datetime.datetime,
    server_url: str,
) -> List[Dict[str, Any]]:
  """Filter vulnerabilities response by `publishedDate` parameter and add Armis vulnerability overview link in the log.

  Args:
   vulnerabilities (Dict[str, Any]): API response.
   start_time (datetime.datetime): Epoch time to filter vulnerabilities data.
   server_url (str): Server URL of Armis platform.

  Returns:
  Dict[str, Any]: Filtered response from vulnerabilities.
  """
  vulnerabilities = vulnerabilities[::-1]

  for i, vulnerability in enumerate(vulnerabilities):
    try:
      # Get the published date from the response.
      published_date = datetime.datetime.strptime(
          vulnerability.get("publishedDate"), TIME_FORMAT
      ).timestamp()
    except Exception:  # pylint: disable=broad-except
      continue

    # Get cve id from the response.
    cve_uid = vulnerability.get("cveUid")

    # Add Armis vulnerability overview link in the log.
    vulnerability[VULNERABILITY_MATCHES] = parse.urljoin(
        server_url, f"/entities/vulnerabilities/{cve_uid}/overview"
    )

    if published_date < start_time.timestamp():
      return vulnerabilities[:i]
  return vulnerabilities


def get_and_ingest_logs(
    server_url: str,
    secret_key: str,
    armis_label: str,
    chronicle_label: str,
    access_token_info: Dict[str, Any],
) -> None:
  """Fetch logs from the Armis platform and ingest it to Chronicle.

  Args:
    server_url (str): Server URL of Armis platform.
    secret_key (str): Secret key to authenticate with Armis platform.
    armis_label (str): Armis label from which data will be fetched.
    chronicle_label (str): Chronicle label in which data will be ingested.
    access_token_info (Dict[str, Any]): Access token information of Armis API.

  Raises:
    RuntimeError: When logs could not be pushed to the Chronicle.
  """
  # Calculate start time from the poll interval.
  start_time = utils.get_last_run_at()

  # Create a client object for Armis class.
  armis_client_object = armis_client.ArmisClient(
      server_url=server_url,
      secret_key=secret_key,
      start_time=start_time,
  )
  order_by = GET_ORDER_BY[armis_label]

  # Initialize offset to 0 for first iteration.
  offset = 0

  # Total logs fetched from Armis platform.
  total_logs = 0
  logs_need_to_fetch = float("inf")

  print(
      f"Started collecting {PRINT_LABEL.get(armis_label,armis_label)} "
      f"from {start_time}."
  )

  # Fetch logs from the Armis platform and ingest them into Chronicle.
  first_run = True

  while offset is not None and (first_run or total_logs < logs_need_to_fetch):
    response = armis_client_object.search_armis_api(
        armis_label, offset, access_token_info, order_by
    )

    data = response.get("data", {})

    if first_run:
      logs_need_to_fetch = data.get("total", 0)
      first_run = False

    offset = data.get("next")
    logs = data.get("results")

    if armis_label == "vulnerabilities":
      logs = filter_and_add_link_in_vulnerabilities(
          logs, start_time, server_url
      )

    total_logs += len(logs)
    if total_logs > logs_need_to_fetch:
      logs_need_to_remove = total_logs - logs_need_to_fetch
      total_logs -= logs_need_to_remove
      logs = logs[0 : (len(logs) - logs_need_to_remove)]

    print(
        f"Total {len(logs)} {PRINT_LABEL.get(armis_label,armis_label)} "
        "collected from Armis."
    )

    # Ingest result into the Chronicle.
    if logs:
      try:
        ingest.ingest(logs, chronicle_label)
      except Exception as error:
        raise RuntimeError(
            f"Unable to push data to Chronicle. {error}"
        ) from error

  print(
      f"A total of {total_logs} {PRINT_LABEL.get(armis_label,armis_label)} were"
      " successfully ingested into Chronicle."
  )


def check_duplicate_chronicle_label(chronicle_labels: List[str]):
  """Check for duplicate Chronicle data type provided.

  Args:
    chronicle_labels (List[str]): Chronicle labels provided by user.

  Raises:
    ValueError: Raised when duplicate Chronicle label(s) provided.
    RuntimeError: When duplicate Chronicle label(s) provided.
  """
  try:
    duplicate_chronicle_labels = set()
    chronicle_labels_set = set()
    for chronicle_label in chronicle_labels:
      if chronicle_label in chronicle_labels_set:
        duplicate_chronicle_labels.add(chronicle_label)
      else:
        chronicle_labels_set.add(chronicle_label)
    if duplicate_chronicle_labels:
      raise ValueError(", ".join(duplicate_chronicle_labels))
  except ValueError as error:
    raise RuntimeError(DUPLICATE_CHRONICLE_LABEL_PROVIDED(error)) from error


def get_and_validate_labels() -> List[str]:
  """Gets Chronicle label(s) from environment variable and validates them.

  Raises:
    ValueError: Raised when invalid Chronicle label provided.
    RuntimeError: When invalid Chronicle label provided.

  Returns:
    list: Chronicle labels.
  """
  try:
    env_chronicle_labels = utils.get_env_var(ENV_CHRONICLE_DATA_TYPE)
    chronicle_labels = [
        chronicle_label.strip()
        for chronicle_label in env_chronicle_labels.split(",")
    ]
    invalid_chronicle_labels = []
    for chronicle_label in chronicle_labels:
      if not SUPPORTED_LABELS.get(chronicle_label, ""):
        invalid_chronicle_labels.append(chronicle_label)
    if invalid_chronicle_labels:
      raise ValueError(", ".join(invalid_chronicle_labels))
  except ValueError as error:
    raise RuntimeError(INVALID_CHRONICLE_LABEL_PROVIDED(error)) from error
  check_duplicate_chronicle_label(chronicle_labels)
  return chronicle_labels


def execute_script(
    server_url: str,
    secret_key: str,
    chronicle_label: str,
    access_token_info: Dict[str, Any],
) -> None:
  """Invoke function that fetch logs from the Armis platform and ingest it to Chronicle.

  Args:
    server_url (str): Server URL of Armis platform.
    secret_key (str): Secret key to authenticate with Armis platform.
    chronicle_label (str): Chronicle label in which data will be ingested.
    access_token_info (Dict[str, Any]): Access token information of Armis API.
  """
  armis_label = SUPPORTED_LABELS[chronicle_label]

  print(
      f"Started execution of {PRINT_LABEL.get(armis_label,armis_label)} "
      "ingestion script."
  )

  # Fetch logs from the Armis platform and ingest it to Chronicle.
  get_and_ingest_logs(
      server_url, secret_key, armis_label, chronicle_label, access_token_info
  )

  print(
      f"Completed execution of {PRINT_LABEL.get(armis_label,armis_label)} "
      "ingestion script."
  )


def main(request) -> str:  # pylint: disable=unused-argument
  """Entry point for the script.

  Args:
    request: Request to execute the cloud function.

  Returns:
    str: "Ingestion completed."
  """
  print("Started execution of ingestion scripts.")

  chronicle_labels = get_and_validate_labels()
  server_url = utils.get_env_var(ENV_ARMIS_SERVER_URL)
  secret_key = utils.get_env_var(ENV_ARMIS_API_SECRET_KEY, is_secret=True)

  manager = multiprocessing.Manager()

  # The dictionary shared between processes. It contains the
  # access token and its expiration time.
  access_token_info = manager.dict({
      "access_token": armis_client.INITIAL_ACCESS_TOKEN,
      "expiration_time": INITIAL_EXPIRATION_TIME,
  })

  processes = []
  for chronicle_label in chronicle_labels:
    process = multiprocessing.Process(
        target=execute_script,
        args=(
            server_url,
            secret_key,
            chronicle_label,
            access_token_info,
        ),
    )
    processes.append(process)
    process.start()

  for process in processes:
    process.join()

  print("Completed execution of ingestion scripts.")

  return "Ingestion completed."
