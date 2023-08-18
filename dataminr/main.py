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
"""Fetch logs from the Dataminr platform and ingest it to Chronicle."""

import json
from typing import Any, Dict

from google.cloud import storage

from common import ingest
from common import utils
import dataminr_client

# Environment variable constants.
ENV_DATAMINR_CLIENT_ID = "DATAMINR_CLIENT_ID"
ENV_DATAMINR_CLIENT_SECRET = "DATAMINR_CLIENT_SECRET"
ENV_DATAMINR_ALERT_TYPE = "DATAMINR_ALERT_TYPE"
ENV_DATAMINR_ALERT_LIMIT = "DATAMINR_ALERT_LIMIT"
ENV_DATAMINR_WATCHLIST_NAMES = "DATAMINR_WATCHLIST_NAMES"
ENV_DATAMINR_ALERT_QUERY = "DATAMINR_ALERT_QUERY"
ENV_DATAMINR_CHECK_POINT = "DATAMINR_CHECKPOINT"
ENV_GCP_BUCKET_NAME = "GCP_BUCKET_NAME"


# Error message for Invalid alert limit.
INVALID_ALERT_LIMIT_ERROR = "Invalid alert limit provided. "

# chronicle label
CHRONICLE_LABEL = "DATAMINR_ALERT"


def get_page_size() -> int:
  """Validating value of  DATAMINR_ALERT_LIMIT environment variable.

  Returns:
  int : Int value of DATAMINR_ALERT_LIMIT environment variable.

  Raises:
  RuntimeError: If the value of the DATAMINR_ALERT_LIMIT is negative or zero.
  """
  try:
    # If the DATAMINR_ALERT_LIMIT is not passed, the default value is 40
    num = utils.get_env_var(
        ENV_DATAMINR_ALERT_LIMIT, required=False, default="40"
    )
    if int(num) <= 0:
      raise ValueError
    return int(num)
  except ValueError as error:
    raise RuntimeError(INVALID_ALERT_LIMIT_ERROR) from error


def get_alert_parameters(watch_list_objects: Dict[str, Any]) -> Dict[str, Any]:
  """Prepare parameters to fetch Alerts from the Dataminr.

  Args:
      watch_list_objects (Dict[str,Any]): Watch lists response from the
        Dataminr.

  Returns:
      Dict[str,Any]: Param dict to pass into fetch Alerts API call.
  """
  env_watch_list_names = utils.get_env_var(
      ENV_DATAMINR_WATCHLIST_NAMES, required=False, default=""
  )
  query = utils.get_env_var(
      ENV_DATAMINR_ALERT_QUERY, required=False, default=""
  )

  alert_parameters = {"num": get_page_size()}
  watch_list_names = [
      watch_list_name.strip()
      for watch_list_name in env_watch_list_names.split(",")
      if watch_list_name.strip()
  ]
  watch_lists = watch_list_objects.get("watchlists", {})
  watch_list_all_objects = (
      watch_lists.get("TOPIC", [])
      + watch_lists.get("CUSTOM", [])
      + watch_lists.get("COMPANY", [])
      + watch_lists.get("CYBER", [])
  )
  if not watch_list_names and query:
    alert_parameters["query"] = query
    return alert_parameters
  watch_list_all_objects_dict = {}
  for watch_list_dict in watch_list_all_objects:
    watch_list_all_objects_dict[watch_list_dict.get("name").lower()] = str(
        watch_list_dict.get("id")
    )
  if watch_list_names:
    present_watch_list_ids = []
    absent_watch_list_names = []
    for watch_list_name in watch_list_names:
      if watch_list_name.lower() in watch_list_all_objects_dict.keys():
        present_watch_list_ids.append(
            watch_list_all_objects_dict[watch_list_name.lower()]
        )
      else:
        absent_watch_list_names.append(watch_list_name)
    if absent_watch_list_names:
      all_absent_watch_list = ",".join(absent_watch_list_names)
      print(
          f"Skipping data collection for {all_absent_watch_list} as the"
          " watchlist was not found on Dataminr"
      )
    alert_parameters["lists"] = ",".join(present_watch_list_ids)
  else:
    alert_parameters["lists"] = ",".join(watch_list_all_objects_dict.values())
  return alert_parameters


def get_and_ingest_logs(client_id: str, client_secret: str) -> None:
  """Fetch logs from the Dataminr platform and ingest it to Chronicle.

  Args:
    client_id (str): Client ID to authenticate with Dataminr platform.
    client_secret (str): Client Secret to authenticate with Dataminr platform.

  Raises:
    RuntimeError: When logs could not be pushed to the Chronicle.
  """

  # Create a client object for Dataminr class.
  dataminr_client_object = dataminr_client.DataminrClient(
      client_id, client_secret
  )
  alert_parameters = get_alert_parameters(
      dataminr_client_object.get_lists_api()
  )
  # fetch last checkpoint
  gcp_bucket_name = utils.get_env_var(ENV_GCP_BUCKET_NAME)
  storage_client = storage.Client()
  current_bucket = storage_client.get_bucket(gcp_bucket_name)
  blob = current_bucket.blob("Dataminr/checkpoint.json")
  try:
    with blob.open(mode="r") as json_file:
      data = json.load(json_file)
      alert_parameters["from"] = data.get("to", "")
  except Exception:  # pylint: disable=broad-except
    pass

  print("Started collecting Alerts ")
  # Fetch logs from the Dataminr platform and ingest them into Chronicle.
  update_checkpoint = 1
  total_alerts = 0
  while True:
    alerts_response = dataminr_client_object.get_alerts_api(alert_parameters)
    alerts_data = alerts_response.get("data", {})
    alerts = alerts_data.get("alerts")
    total_alerts = total_alerts + len(alerts)
    print(f"Total {len(alerts)}  alerts collected from Dataminr.")
    if alerts:
      alert_parameters["from"] = alerts_data.get("to")
      # Ingest result into the Chronicle.
      try:
        ingest.ingest(alerts, CHRONICLE_LABEL)
      except Exception as error:
        new_checkpoint = {"to": alert_parameters["from"]}
        with blob.open(mode="w", encoding="utf-8") as json_file:
          json_file.write(json.dumps(new_checkpoint))
        raise RuntimeError(
            f"Unable to push data to Chronicle. {error}"
        ) from error
      if update_checkpoint % 5 == 0:
        new_checkpoint = {"to": alert_parameters["from"]}
        with blob.open(mode="w", encoding="utf-8") as json_file:
          json_file.write(json.dumps(new_checkpoint))
      print("Completed execution of ingestion scripts")
    else:
      break
    update_checkpoint += 1
  if total_alerts:
    new_checkpoint = {"to": alert_parameters["from"]}
    with blob.open(mode="w", encoding="utf-8") as json_file:
      json_file.write(json.dumps(new_checkpoint))
    print(
        f"A total of {total_alerts} alerts were successfully ingested ",
        "into Chronicle.",
    )


def main(unused_request) -> str:
  """Entry point for the script.

  Args:
    unused_request: Request to execute the cloud function.

  Returns:
    str: "Ingestion completed."
  """

  client_id = utils.get_env_var(ENV_DATAMINR_CLIENT_ID)
  client_secret = utils.get_env_var(ENV_DATAMINR_CLIENT_SECRET, is_secret=True)

  print("Started execution of ingestion scripts.")
  get_and_ingest_logs(client_id, client_secret)
  print("Completed execution of ingestion scripts.")

  return "Ingestion completed."
