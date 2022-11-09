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
from google.cloud import pubsub_v1
from concurrent import futures
import json
from chronicle import ingest
import sys

from chronicle.utils import get_env_var


def main(req):
    """Subscribe to subscription, receive message data
    and ingest data into chronicle."
    """
    global PAYLOAD_SIZE, PAYLOAD, CHRONICLE_DATA_TYPE
    PAYLOAD_SIZE = 0
    PAYLOAD = {}

    # Expecting values during cloud schedule trigger.
    request_json = req.get_json(silent=True)

    if request_json:
        project_id = request_json.get("PROJECT_ID", "")
        subscription_id = request_json.get("SUBSCRIPTION_ID", "")
        CHRONICLE_DATA_TYPE = request_json.get("CHRONICLE_DATA_TYPE")

    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(project_id, subscription_id)

    # get message data from subscription
    def callback(message: pubsub_v1.subscriber.message.Message) -> None:

        print(f"Received {message.data!r}.")
        message.ack()
        data = (message.data).decode("utf-8")
        try:
            data = json.loads(data)
        except (ValueError, TypeError) as e:
            print(
                "ERROR: Unexpected data format received while collecting \
                    message details from subscription"
            )
            print(f"Message: {data}")
            raise (e)

        build_payload(data)

    future = subscriber.subscribe(subscription_path, callback=callback)

    with subscriber:
        try:
            future.result(timeout=5)
        except futures.TimeoutError:
            future.cancel()  # Trigger the shutdown.
            future.result()  # Block until the shutdown is complete.

    if PAYLOAD_SIZE > 0:
        ingest(PAYLOAD, CHRONICLE_DATA_TYPE)

    return "OK"


# Generate package to sent to chronicle
def build_payload(log):
    """build payload from logs fetched and ingest it

    Args:
        log (_type_): _description_

    Returns:
        _type_: _description_
    """
    global PAYLOAD_SIZE, PAYLOAD, CHRONICLE_DATA_TYPE

    if PAYLOAD_SIZE == 0:
        # Build a new object
        PAYLOAD = []
        log = json.dumps(log)
        PAYLOAD.append(log)
        PAYLOAD_SIZE = PAYLOAD_SIZE + (sys.getsizeof(json.dumps(PAYLOAD)))
    else:
        log = json.dumps(log)
        logsize = sys.getsizeof(log)
        # send when the payload hits a certain size
        if PAYLOAD_SIZE + logsize > 500000:
            # Ingest collected payload data
            ingest(PAYLOAD, CHRONICLE_DATA_TYPE)
            # reset payload
            PAYLOAD_SIZE = 0
            PAYLOAD = []
        # Append the event
        PAYLOAD.append(log)
        PAYLOAD_SIZE = PAYLOAD_SIZE + (sys.getsizeof(log))

    return "ok"
