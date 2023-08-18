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
"""Unittest cases for Dataminr ingestion scripts."""

import sys
import time
import unittest
from unittest import mock

import requests

INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest"] = mock.Mock()

import main

# CONSTANTS
MOCK_RESPONSE_ACCESS_TOKEN = {
    "dmaToken": "test",
    "refreshToken": "test",
    "expire": 1888632914632,
}

MOCK_CURRENT_EPOCH = 1988632914632

MOCK_RESPONSE_WATCH_LISTS = {
    "watchlists": {
        "COMPANY": [{"id": 1, "name": "A"}],
        "TOPIC": [{"id": 2, "name": "B"}],
        "CUSTOM": [{"id": 3, "name": "C"}],
        "CYBER": [{"id": 4, "name": "D"}],
    }
}

MOCK_ALERTS_RESPONSE_EMPTY = {
    "data": {"alerts": [], "from": "xyz", "to": "abc"}
}
MOCK_ALERTS_RESPONSE_1 = {
    "data": {
        "alerts": [
            {"alertId": "1234", "eventTime": 1562857307558},
            {"alertId": "1235", "eventTime": 1562857307500},
        ],
        "from": "a",
        "to": "b",
    }
}
MOCK_ALERTS_RESPONSE_2 = {
    "data": {
        "alerts": [
            {"alertId": "1237", "eventTime": 1562857307700},
            {"alertId": "1236", "eventTime": 1562857307600},
        ],
        "from": "b",
        "to": "c",
    }
}

MOCK_ALERTS_RESPONSE_3 = {
    "data": {
        "alerts": [
            {"alertId": "1237", "eventTime": 1562857307700},
            {"alertId": "1236", "eventTime": 1562857307600},
        ],
        "from": "c",
        "to": "d",
    }
}

MOCK_ALERTS_RESPONSE_4 = {
    "data": {
        "alerts": [
            {"alertId": "1237", "eventTime": 1562857307700},
            {"alertId": "1236", "eventTime": 1562857307600},
        ],
        "from": "d",
        "to": "e",
    }
}

MOCK_ALERTS_RESPONSE_5 = {
    "data": {
        "alerts": [
            {"alertId": "1237", "eventTime": 1562857307700},
            {"alertId": "1236", "eventTime": 1562857307600},
        ],
        "from": "e",
        "to": "f",
    }
}

MOCK_ALERTS_RESPONSE_6 = {
    "data": {
        "alerts": [
            {"alertId": "1237", "eventTime": 1562857307700},
            {"alertId": "1236", "eventTime": 1562857307600},
        ],
        "from": "f",
        "to": "g",
    }
}


MOCK_MAIN_REQUEST = {"name": "Hello World"}

MOCK_SECRET_PATH = (
    "projects/dataminr_test/secrets/DATAMINR_CHECKPOINT/versions/latest"
)

MOCK_OS_ENVIRON = {
    "DATAMINR_CLIENT_ID": "dataminr_client_id",
    "DATAMINR_CLIENT_SECRET": MOCK_SECRET_PATH,
    "GCP_BUCKET_NAME": "dataminr_bucket",
    "DATAMINR_ALERT_LIMIT": "40",
}

MOCK_OS_ENVIRON_TEST_1 = {
    "DATAMINR_CLIENT_ID": "dataminr_client_id",
    "DATAMINR_CLIENT_SECRET": MOCK_SECRET_PATH,
    "GCP_BUCKET_NAME": "dataminr_bucket",
    "DATAMINR_ALERT_LIMIT": "test",
    "HTTPS_PROXY": "https://http_proxy_url",
}


MOCK_OS_ENVIRON_TEST_2 = {
    "DATAMINR_CLIENT_ID": "dataminr_client_id",
    "DATAMINR_CLIENT_SECRET": MOCK_SECRET_PATH,
    "GCP_BUCKET_NAME": "dataminr_bucket",
    "DATAMINR_ALERT_LIMIT": "50",
    "DATAMINR_ALERT_QUERY": "window",
    "HTTPS_PROXY": "http_proxy_url",
    "DATAMINR_WATCHLIST_NAMES": "A,B,T,E",
}

MOCK_DATAMINR_HEADERS = {
    "Authorization": "Dmauth test",
    "Accept": "application/json",
}

MOCK_CHECKPOINT_RESPONSE = {"to": "a"}


DATAMINR_CLIENT_SECRET = "client_secret"

MOCK_401_MESSAGE = {
    "errors": [{"code": 103, "message": "Authentication error. Invalid token"}]
}
MOCK_429_MESSAGE = {
    "errors": [{"code": 105, "message": "Rate limit exceeded!"}]
}

MOCK_500_MESSAGE = {"error": "Error fetching alerts..."}

MOCK_400_MESSAGE = {
    "errors": [{"code": 102, "message": "Invalid client Id or client secret"}]
}

main.dataminr_client.WAIT_TIME = 2


class MockResponse:
  """Class for initializing mock response."""

  def __init__(self, json_data, status_code, reason=None, headers=None):
    """Constructor for MockResponse class."""
    self.json_data = json_data
    self.status_code = status_code
    self.reason = reason
    self.headers = headers

  def json(self):
    """Function used to mock response.json() functionality."""
    return self.json_data


class Payload:

  def __init__(self, name):
    self.data = name.split("/")[3].lower().encode("UTF-8")


class SecretValue:

  def __init__(self, name):
    self.payload = Payload(name)


class SecretClient:
  """Class for creating secret manager client."""

  def access_secret_version(self, name):
    return SecretValue(name)


class MockWrite:

  def __enter__(self):
    return MockWrite()

  def __exit__(self, exc_type, exc_val, exc_tb):
    print("Exit from the file.")

  def write(self, checkpoint):
    print("Stored checkpoint :", checkpoint)


class MockRead:

  def __enter__(self):
    return MockRead()

  def __exit__(self, exc_type, exc_val, exc_tb):
    print("Exit from the file.")


class MockBlob:

  def open(self, mode="r", encoding="utf-8"):  # pylint: disable=unused-argument
    if mode == "w":
      return MockWrite()
    return MockRead()


class MockStorageBlob:

  def blob(self, unused_path):
    return MockBlob()


class MockStorageClient:

  def get_bucket(self, unused_bucket_name):
    return MockStorageBlob()


@mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
@mock.patch(f"{INGESTION_SCRIPTS_PATH}main.dataminr_client.requests.request")
@mock.patch(
    f"{INGESTION_SCRIPTS_PATH}main.utils.secretmanager.SecretManagerServiceClient"
)
@mock.patch(f"{INGESTION_SCRIPTS_PATH}main.storage.Client")
class TestDataminrLogsIngestion(unittest.TestCase):
  """Test cases for Dataminr logs ingestion script."""

  @mock.patch.dict(
      f"{INGESTION_SCRIPTS_PATH}main.utils.os.environ", MOCK_OS_ENVIRON_TEST_2
  )
  def test_no_logs_to_ingest(
      self,
      mocked_storage_client,
      mocked_secret_manager,
      mock_http_request,
      mocked_ingest,
  ):
    """Test case to verify that we do not call ingest function when there are no logs to ingest."""

    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        MOCK_RESPONSE_WATCH_LISTS,
        status_code=200,
    )
    mocked_response_3 = MockResponse(
        MOCK_ALERTS_RESPONSE_EMPTY,
        status_code=200,
    )
    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_3,
    ]
    mocked_secret_manager.return_value = SecretClient()
    mocked_storage_client.return_value = MockStorageClient()
    main.main(MOCK_MAIN_REQUEST)

    self.assertEqual(mocked_ingest.call_count, 0)
    self.assertEqual(
        main.utils.get_env_var("DATAMINR_CLIENT_SECRET", is_secret=True),
        "dataminr_checkpoint",
    )

    # Verify API request parameter for Watchlist API.
    self.assertEqual(
        mock_http_request.mock_calls[-2],
        mock.call(
            method="GET",
            url="https://gateway.dataminr.com/account/2/get_lists",
            headers=MOCK_DATAMINR_HEADERS,
        ),
    )

    self.assertEqual(
        main.get_alert_parameters(MOCK_RESPONSE_WATCH_LISTS),
        {"num": 50, "lists": "1,2"},
    )

    # Verify API request parameter for alerts API.
    self.assertEqual(
        mock_http_request.mock_calls[-1],
        mock.call(
            method="GET",
            url="https://gateway.dataminr.com/api/3/alerts",
            headers=MOCK_DATAMINR_HEADERS,
            params={
                "num": 50,
                "lists": "1,2",
                "alertversion": "14",
            },
        ),
    )
    self.assertEqual(
        main.utils.os.environ["HTTPS_PROXY"],
        "http://" + MOCK_OS_ENVIRON_TEST_2["HTTPS_PROXY"],
    )

    self.assertEqual(
        main.get_alert_parameters(MOCK_RESPONSE_WATCH_LISTS),
        {"num": 50, "lists": "1,2"},
    )

  @mock.patch.dict(
      f"{INGESTION_SCRIPTS_PATH}main.utils.os.environ", MOCK_OS_ENVIRON
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.json.load")
  @mock.patch("builtins.print")
  def test_successful_ingest(
      self,
      mocked_print,
      mocked_json_load,
      mocked_storage_client,
      mocked_secret_manager,
      mock_http_request,
      mocked_ingest,
  ):
    """Test case to verify that dataminr alerts logs are successfully ingested into chronicle."""

    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        MOCK_RESPONSE_WATCH_LISTS,
        status_code=200,
    )
    mocked_response_3 = MockResponse(
        MOCK_ALERTS_RESPONSE_1,
        status_code=200,
    )
    mocked_response_4 = MockResponse(
        MOCK_ALERTS_RESPONSE_2,
        status_code=200,
    )
    mocked_response_5 = MockResponse(
        MOCK_ALERTS_RESPONSE_3,
        status_code=200,
    )
    mocked_response_6 = MockResponse(
        MOCK_ALERTS_RESPONSE_4,
        status_code=200,
    )
    mocked_response_7 = MockResponse(
        MOCK_ALERTS_RESPONSE_5,
        status_code=200,
    )
    mocked_response_8 = MockResponse(
        MOCK_ALERTS_RESPONSE_6,
        status_code=200,
    )
    mocked_response_9 = MockResponse(
        MOCK_ALERTS_RESPONSE_EMPTY,
        status_code=200,
    )
    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_3,
        mocked_response_4,
        mocked_response_5,
        mocked_response_6,
        mocked_response_7,
        mocked_response_8,
        mocked_response_9,
    ]
    mocked_json_load.side_effect = [MOCK_CHECKPOINT_RESPONSE]
    mocked_secret_manager.return_value = SecretClient()
    mocked_storage_client.return_value = MockStorageClient()
    main.main(MOCK_MAIN_REQUEST)
    self.assertEqual(mocked_ingest.call_count, 6)
    mocked_print.assert_has_calls([
        mock.call(
            "A total of 12 alerts were successfully ingested ",
            "into Chronicle.",
        ),
    ])
    mocked_print.assert_has_calls([
        mock.call("Stored checkpoint :", '{"to": "g"}'),
    ])
    mocked_print.assert_has_calls([
        mock.call("Stored checkpoint :", '{"to": "f"}'),
    ])
    # Verify API request parameter for alerts API.
    self.assertEqual(
        mock_http_request.mock_calls[-1],
        mock.call(
            method="GET",
            url="https://gateway.dataminr.com/api/3/alerts",
            headers=MOCK_DATAMINR_HEADERS,
            params={
                "num": 40,
                "lists": "2,3,1,4",
                "from": "g",
                "alertversion": "14",
            },
        ),
    )

  @mock.patch.dict(
      f"{INGESTION_SCRIPTS_PATH}main.utils.os.environ", MOCK_OS_ENVIRON_TEST_1
  )
  def test_env_num_parameter(
      self,
      mocked_storage_client,
      mocked_secret_manager,
      mock_http_request,
      unused_mocked_ingest,
  ):
    """Test case to verify that provided env variables is as expected."""

    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        MOCK_RESPONSE_WATCH_LISTS,
        status_code=200,
    )
    mocked_secret_manager.return_value = SecretClient()
    mocked_storage_client.return_value = MockStorageClient()
    mock_http_request.side_effect = [mocked_response_1, mocked_response_2]
    with self.assertRaises(Exception) as error:
      main.main(MOCK_MAIN_REQUEST)
    self.assertEqual(
        str(error.exception),
        "Invalid alert limit provided. ",
    )

  @mock.patch.dict(
      f"{INGESTION_SCRIPTS_PATH}main.utils.os.environ", MOCK_OS_ENVIRON
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.dataminr_client.time.time")
  def test_401_http_error_from_dataminr_api(
      self,
      mocked_current_epoch,
      mocked_storage_client,
      mocked_secret_manager,
      mock_http_request,
      unused_mocked_ingest,
  ):
    """Test case scenario when 401 error is obtained from Dataminr API."""
    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        MOCK_RESPONSE_WATCH_LISTS,
        status_code=200,
    )
    mocked_response_3 = MockResponse(
        MOCK_401_MESSAGE,
        status_code=401,
    )
    mocked_current_epoch.return_value = MOCK_CURRENT_EPOCH
    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_3,
        mocked_response_1,
        mocked_response_3,
    ]
    mocked_secret_manager.return_value = SecretClient()
    mocked_storage_client.return_value = MockStorageClient()
    with self.assertRaises(Exception) as error:
      main.main(MOCK_MAIN_REQUEST)

    self.assertEqual(
        str(error.exception),
        (
            "API call failed. HTTP error. Error = 401: [{'code': 103,"
            " 'message': 'Authentication error. Invalid token'}]. "
        ),
    )

  @mock.patch.dict(
      f"{INGESTION_SCRIPTS_PATH}main.utils.os.environ", MOCK_OS_ENVIRON
  )
  def test_429_http_error_from_dataminr_api(
      self,
      mocked_storage_client,
      mocked_secret_manager,
      mock_http_request,
      unused_mocked_ingest,
  ):
    """Test case scenario when 429 error is obtained from Dataminr API."""
    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        MOCK_RESPONSE_WATCH_LISTS,
        status_code=200,
    )
    mocked_response_3 = MockResponse(
        MOCK_429_MESSAGE,
        status_code=429,
        headers={"x-rate-limit-reset": (time.time() + 2) * 1000},
    )
    mocked_response_4 = MockResponse(
        MOCK_429_MESSAGE,
        status_code=429,
        headers={"x-rate-limit-reset": (time.time() + 4) * 1000},
    )
    mocked_response_5 = MockResponse(
        MOCK_429_MESSAGE,
        status_code=429,
        headers={"x-rate-limit-reset": (time.time() + 6) * 1000},
    )
    mocked_response_6 = MockResponse(
        MOCK_429_MESSAGE,
        status_code=429,
        headers={"x-rate-limit-reset": (time.time() + 8) * 1000},
    )
    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_3,
        mocked_response_4,
        mocked_response_5,
        mocked_response_6,
    ]
    mocked_secret_manager.return_value = SecretClient()
    mocked_storage_client.return_value = MockStorageClient()
    with self.assertRaises(Exception) as error:
      main.main(MOCK_MAIN_REQUEST)

    self.assertEqual(
        str(error.exception),
        (
            "API call failed. HTTP error. Error = 429: [{'code': 105,"
            " 'message': 'Rate limit exceeded!'}]. "
        ),
    )

  @mock.patch.dict(
      f"{INGESTION_SCRIPTS_PATH}main.utils.os.environ", MOCK_OS_ENVIRON
  )
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.json.load")
  def test_500_http_error_from_dataminr_api(
      self,
      mocked_json_load,
      mocked_storage_client,
      mocked_secret_manager,
      mock_http_request,
      unused_mocked_ingest,
  ):
    """Test case scenario when 500 error is obtained from Dataminr API."""
    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        MOCK_RESPONSE_WATCH_LISTS,
        status_code=200,
    )
    mocked_response_3 = MockResponse(
        MOCK_500_MESSAGE,
        status_code=500,
    )
    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_3,
        mocked_response_3,
        mocked_response_3,
        mocked_response_3,
    ]
    mocked_secret_manager.return_value = SecretClient()
    mocked_storage_client.return_value = MockStorageClient()
    mocked_json_load.side_effect = [MOCK_CHECKPOINT_RESPONSE]

    with self.assertRaises(Exception) as error:
      main.main(MOCK_MAIN_REQUEST)

    self.assertEqual(
        str(error.exception),
        "API call failed. HTTP error. Error = 500: Error fetching alerts.... ",
    )
    self.assertEqual(
        mock_http_request.mock_calls[-1],
        mock.call(
            method="GET",
            url="https://gateway.dataminr.com/api/3/alerts",
            headers=MOCK_DATAMINR_HEADERS,
            params={
                "num": 40,
                "lists": "2,3,1,4",
                "from": "a",
                "alertversion": "14",
            },
        ),
    )

  @mock.patch.dict(
      f"{INGESTION_SCRIPTS_PATH}main.utils.os.environ", MOCK_OS_ENVIRON
  )
  def test_connection_error_from_dataminr_api(
      self,
      unused_mocked_storage_client,
      unused_mocked_secret_manager,
      mock_http_request,
      unused_mocked_ingest,
  ):
    """Test case scenario when connection error is obtained from Dataminr API."""
    mock_http_request.side_effect = requests.ConnectionError(
        "Failed to establish a connection."
    )
    with self.assertRaises(Exception) as error:
      main.main(MOCK_MAIN_REQUEST)
    self.assertEqual(
        str(error.exception),
        (
            "API call failed. Invalid Server URL. Failed to establish a"
            " connection."
        ),
    )

  @mock.patch.dict(
      f"{INGESTION_SCRIPTS_PATH}main.utils.os.environ", MOCK_OS_ENVIRON
  )
  def test_400_http_error_from_dataminr_api(
      self,
      unused_mocked_storage_client,
      mocked_secret_manager,
      mock_http_request,
      unused_mocked_ingest,
  ):
    """Test case scenario when 400 error is obtained from Dataminr API."""
    mocked_response_1 = MockResponse(
        MOCK_400_MESSAGE,
        status_code=400,
    )
    mock_http_request.side_effect = [mocked_response_1]
    mocked_secret_manager.return_value = SecretClient()
    with self.assertRaises(Exception) as error:
      main.main(MOCK_MAIN_REQUEST)
    self.assertEqual(
        str(error.exception),
        (
            "API call failed. HTTP error. Error = 400: [{'code': 102,"
            " 'message': 'Invalid client Id or client secret'}]. "
        ),
    )

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.get_and_ingest_logs")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var")
  def test_for_daminr_client_secret(
      self,
      mocked_get_env_var,
      unused_mocked_get_and_ingest_logs,
      unused_mocked_storage_client,
      unused_mocked_secret_manager,
      unused_mock_http_request,
      unused_mocked_ingest,
  ):
    """Test case scenario when DATAMINR_CLIENT_SECRET env variable is set and when is_scret is True."""
    main.main(MOCK_MAIN_REQUEST)
    mocked_get_env_var.assert_called_with(
        "DATAMINR_CLIENT_SECRET", is_secret=True
    )
