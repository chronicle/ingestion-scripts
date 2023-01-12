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
"""Fetch logs from PUBSUB."""

from concurrent import futures
import json
import sys
from typing import Any, Dict, List, Union

from google.cloud import pubsub_v1

from common import env_constants
from common import ingest

# Default initialization of variable.
PAYLOAD_SIZE = None
PAYLOAD = None
CHRONICLE_DATA_TYPE = None

# The threshold to use for ingesting the data to the Chronicle.
PAYLOAD_THRESHOLD = 500000

# Default timeout to wait for subscriber to send a message.
DEFAULT_TIMEOUT = 5


# Generate package to sent to Chronicle.
def build_and_ingest_payload(log: Union[Dict[Any, Any], List[Any]]) -> str:
  """Build payload from logs fetched from PUBSUB and ingest it to Chronicle.

  Args:
    log: Logs to be ingested in the Chronicle.

  Returns:
    str: OK if ingestion successful.
  """
  global PAYLOAD_SIZE, PAYLOAD

  if PAYLOAD_SIZE == 0:
    # Build a new object.
    PAYLOAD = []
    log = json.dumps(log)
    PAYLOAD.append(log)
    PAYLOAD_SIZE = PAYLOAD_SIZE + (sys.getsizeof(json.dumps(PAYLOAD)))
  else:
    log = json.dumps(log)
    logsize = sys.getsizeof(log)
    # Send when the payload hits a certain size.
    if PAYLOAD_SIZE + logsize > PAYLOAD_THRESHOLD:
      # Ingest collected payload data.
      ingest.ingest(PAYLOAD, CHRONICLE_DATA_TYPE)
      # Reset payload.
      PAYLOAD_SIZE = 0
      PAYLOAD = []
    # Append the event.
    PAYLOAD.append(log)
    PAYLOAD_SIZE = PAYLOAD_SIZE + (sys.getsizeof(log))

  return "OK"


def main(req):  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    req: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """
  global PAYLOAD_SIZE, PAYLOAD, CHRONICLE_DATA_TYPE
  PAYLOAD_SIZE = 0
  PAYLOAD = []

  # Expecting values during cloud schedule trigger.
  request_json = req.get_json(silent=True)

  if request_json:
    project_id = request_json.get("PROJECT_ID", "")
    subscription_id = request_json.get("SUBSCRIPTION_ID", "")
    CHRONICLE_DATA_TYPE = request_json.get(
        env_constants.ENV_CHRONICLE_DATA_TYPE)
  else:
    print("Did not get configuration parameters from request body.")

  subscriber = pubsub_v1.SubscriberClient()
  subscription_path = subscriber.subscription_path(project_id, subscription_id)

  def get_and_ingest_messages(
      message: pubsub_v1.subscriber.message.Message) -> None:
    """Get message from the subscription.

    Args:
      message: Message received from subscription.

    Raises:
      ValueError, TypeError: Error when received message is not in json format.
    """
    print(f"Received {message.data!r}.")
    message.ack()
    data = (message.data).decode("utf-8")
    try:
      data = json.loads(data)
    except (ValueError, TypeError) as error:
      print("ERROR: Unexpected data format received "
            "while collecting message details from subscription")
      raise error

    build_and_ingest_payload(data)

  future = subscriber.subscribe(
      subscription_path, callback=get_and_ingest_messages)

  with subscriber:
    try:
      future.result(timeout=DEFAULT_TIMEOUT)
    except futures.TimeoutError:
      future.cancel()  # Trigger the shutdown.
      future.result()  # Block until the shutdown is complete.

  if PAYLOAD_SIZE > 0:
    ingest.ingest(PAYLOAD, CHRONICLE_DATA_TYPE)

  return "Ingestion completed."
