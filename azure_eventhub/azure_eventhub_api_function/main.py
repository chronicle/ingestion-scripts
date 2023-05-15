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
"""Fetch the logs from Azure Event Hub and ingest them into Chronicle."""
import json
import logging
from typing import List

import azure.functions as func
from common import ingest
from common import utils

# Environment variable constants.
ENV_CHRONICLE_DATA_TYPE = "CHRONICLE_DATA_TYPE"


def main(events: List[func.EventHubEvent]) -> None:
  """Entrypoint.

  Args:
      events: Events from the Azure Event Hub.
  """
  # Fetch environment variables.
  chronicle_data_type = utils.get_env_var(ENV_CHRONICLE_DATA_TYPE)
  events_to_send = []

  # Iterating over the list of EventHub logs to decode and JSON serialize them.
  for event in events:
    try:
      records = json.loads(event.get_body().decode("utf-8"))["records"]
    # Raise error if the event received from the Azure EventHub is not JSON
    # serializable.
    except json.JSONDecodeError as error:
      print("Could not JSON serialize the Azure EventHub log.")
      raise RuntimeError(
          "The log data from Azure EventHub is not JSON serializable."
      ) from error

    # If events are nested in the list form in Eventhub log message.
    # Example: {"records": [event1, event2, event3, ...]}
    if isinstance(records, list):
      events_to_send.extend(records)
    else:
      events_to_send.append(records)

  events_count = len(events_to_send)
  logging.info(
      "Parsed %s events from Azure EventHub. Sending events to Chronicle.",
      events_count
  )

  try:
    # Ingest Azure EventHub logs to Chronicle.
    ingest.ingest(events_to_send, chronicle_data_type)
  except Exception as error:
    raise Exception(f"Unable to push the data to the Chronicle. Error: {error}"  # pylint: disable=broad-exception-raised
                    )  from error

  logging.info(
      "Total %s log(s) are successfully ingested to Chronicle.",
      events_count,
  )
