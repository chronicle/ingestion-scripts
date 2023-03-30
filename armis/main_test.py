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
"""Unittest cases for Armis ingestion scripts."""

import datetime
import os
import sys
import unittest
from unittest import mock

import requests

INGESTION_SCRIPTS_PATH = ""
sys.modules["common.ingest"] = mock.Mock()

import main


# CONSTANTS
MOCK_RESPONSE_ACCESS_TOKEN = {
    "data": {
        "access_token": "test",
        "expiration_utc": "2023-01-02T10:35:04.756203+00:00",
    }
}

INITIAL_ACCESS_TOKEN_INFO = {
    "access_token": "",
    "expiration_utc": "",
}

ARMIS_SECRET_KEY = "armis_secret_key"

ARMIS_SERVER_URL = "armis_server_url"

CHRONICLE_LABELS = ["ARMIS_ALERTS", "ARMIS_VULNERABILITIES"]

MOCK_RESPONSE_ALERTS = [
    {
        "alertId": 1,
        "activityUUIDs": ["test"],
        "time": "2023-02-20T10:05:04.756203+00:00",
    },
    {
        "alertId": 2,
        "activityUUIDs": ["test"],
        "time": "2023-02-20T10:05:04.756203+00:00",
    },
    {
        "alertId": 3,
        "activityUUIDs": ["test"],
        "time": "2023-02-21T10:05:04.756203+00:00",
    },
    {
        "alertId": 4,
        "activityUUIDs": ["test"],
        "time": "2023-02-21T10:05:04.756203+00:00",
    },
]

MOCK_RESPONSE_VULNERABILITIES = [
    {
        "affectedDeviceCount": 2,
        "cveUid": "CVE-2021-1111",
        "publishedDate": "2023-02-19T10:05:04+00:00",
    },
    {
        "affectedDeviceCount": 1,
        "cveUid": "CVE-2021-1112",
        "publishedDate": "2023-02-20T10:05:04+00:00",
    },
    {
        "affectedDeviceCount": 3,
        "cveUid": "CVE-2021-1113",
        "publishedDate": "2023-02-20T10:05:04+00:00",
    },
]

EXPECTED_RESPONSE_VULNERABILITIES = [
    {
        "affectedDeviceCount": 2,
        "cveUid": "CVE-2021-1111",
        "publishedDate": "2023-02-19T10:05:04+00:00",
        "vulnerabilities_matches": (
            "/entities/vulnerabilities/CVE-2021-1111/overview"
        ),
    },
    {
        "affectedDeviceCount": 1,
        "cveUid": "CVE-2021-1112",
        "publishedDate": "2023-02-20T10:05:04+00:00",
        "vulnerabilities_matches": (
            "/entities/vulnerabilities/CVE-2021-1112/overview"
        ),
    },
    {
        "affectedDeviceCount": 3,
        "cveUid": "CVE-2021-1113",
        "publishedDate": "2023-02-20T10:05:04+00:00",
        "vulnerabilities_matches": (
            "/entities/vulnerabilities/CVE-2021-1113/overview"
        ),
    },
]


class MockResponse:
  """Class for initializing mock response."""

  def __init__(self, json_data, status_code, reason=None):
    """Constructor for MockResponse class."""
    self.json_data = json_data
    self.status_code = status_code
    self.reason = reason

  def json(self):
    """Function used to mock response.json() functionality."""
    return self.json_data


class MockMultiProcessPool:
  """Class for initializing mock multiprocessing object."""

  def __init__(self, target, args):
    """Constructor for MockMultiProcessPool class."""
    self._func = target
    self._args = args

  def start(self):
    """Function used to mock process.start() functionality."""
    self._func(*self._args)

  def join(self):
    """Function used to mock process.join() functionality."""


@mock.patch(
    f"{INGESTION_SCRIPTS_PATH}main.utils.get_env_var",
)
@mock.patch(
    f"{INGESTION_SCRIPTS_PATH}main.utils.get_last_run_at",
)
@mock.patch(f"{INGESTION_SCRIPTS_PATH}main.ingest.ingest")
@mock.patch(f"{INGESTION_SCRIPTS_PATH}main.armis_client.time.sleep")
@mock.patch(f"{INGESTION_SCRIPTS_PATH}main.armis_client.requests.request")
@mock.patch.object(
    main.multiprocessing, "Process", side_effect=MockMultiProcessPool
)
class TestArmisLogsIngestion(unittest.TestCase):
  """Test cases for Armis logs ingestion script."""

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.armis_client.datetime")
  def test_no_logs_to_ingest(
      self,
      mocked_datetime,
      unused_mock_multiprocessing,
      mock_http_request,
      unused_mocked_sleep,
      mocked_ingest,
      mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case to verify that we do not call ingest function when there are no logs to ingest."""
    mocked_get_env_var.side_effect = [
        "http://http_proxy_url",
        "http://http_proxy_url",
        None,
        None,
    ]
    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        {"data": {"count": 0, "next": None, "results": []}},
        status_code=200,
    )

    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_1,
        mocked_response_2,
    ]

    mocked_get_last_run.return_value = datetime.datetime(
        2023, 2, 20, 10, 00, 00, tzinfo=datetime.timezone.utc
    )
    mocked_datetime.datetime.now.return_value = datetime.datetime(
        2023, 2, 20, 10, 10, 00, tzinfo=datetime.timezone.utc
    )
    mocked_datetime.datetime.strptime.side_effect = datetime.datetime.strptime
    os.environ["HTTPS_PROXY"] = "http://http_proxy_url"

    for chronicle_label in CHRONICLE_LABELS:
      main.execute_script(
          ARMIS_SERVER_URL,
          ARMIS_SECRET_KEY,
          chronicle_label,
          INITIAL_ACCESS_TOKEN_INFO,
      )

    self.assertEqual(mocked_ingest.call_count, 0)
    self.assertEqual(
        mocked_get_env_var.mock_calls[0],
        mock.call("HTTPS_PROXY", required=False),
    )

    # Verify API request parameter for vulnerability data type.
    self.assertEqual(
        mock_http_request.mock_calls[-1],
        mock.call(
            method="GET",
            url="api/v1/search/",
            headers={"Authorization": "test", "Accept": "application/json"},
            params={
                "aql": "in:vulnerabilities",
                "length": 1000,
                "from": 0,
                "orderBy": "publishedDate",
            },
        ),
    )

    # Verify API request parameter for alerts data type.
    self.assertEqual(
        mock_http_request.mock_calls[-3],
        mock.call(
            method="GET",
            url="api/v1/search/",
            headers={"Authorization": "test", "Accept": "application/json"},
            params={
                "aql": 'in:alerts timeFrame:"600 seconds"',
                "length": 1000,
                "from": 0,
                "orderBy": "time",
            },
        ),
    )
    self.assertEqual(os.environ["HTTPS_PROXY"], "http://http_proxy_url")

  @mock.patch("builtins.print")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.armis_client.datetime")
  def test_pagination_for_logs(
      self,
      mocked_datetime,
      mocked_print,
      unused_mock_multiprocessing,
      mock_http_request,
      unused_mocked_sleep,
      mocked_ingest,
      mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case to verify the pagination mechanism for logs."""
    mocked_get_env_var.side_effect = [
        None,
        None,
        None,
        None,
    ]

    mocked_get_last_run.return_value = datetime.datetime(
        2023, 2, 20, 10, 00, 00, tzinfo=datetime.timezone.utc
    )
    mocked_datetime.datetime.now.return_value = datetime.datetime(
        2023, 2, 20, 10, 10, 00, tzinfo=datetime.timezone.utc
    )
    mocked_datetime.datetime.strptime.side_effect = datetime.datetime.strptime

    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        {
            "data": {
                "count": 2,
                "next": 2,
                "results": MOCK_RESPONSE_ALERTS[:2],
                "total": 3,
            }
        },
        status_code=200,
    )
    mocked_response_3 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_4 = MockResponse(
        {
            "data": {
                "count": 3,
                "next": 5,
                "results": MOCK_RESPONSE_ALERTS[1:],
                "total": 8,
            }
        },
        status_code=200,
    )

    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_3,
        mocked_response_4,
    ]

    main.execute_script(
        ARMIS_SERVER_URL,
        ARMIS_SECRET_KEY,
        "ARMIS_ALERTS",
        INITIAL_ACCESS_TOKEN_INFO,
    )

    self.assertEqual(mocked_ingest.call_count, 2)
    self.assertEqual(
        mocked_ingest.mock_calls,
        [
            mock.call(MOCK_RESPONSE_ALERTS[:2], "ARMIS_ALERTS"),
            mock.call([MOCK_RESPONSE_ALERTS[1]], "ARMIS_ALERTS"),
        ],
    )
    mocked_print.assert_has_calls([
        mock.call(
            "A total of 3 alerts were successfully ingested into Chronicle."
        ),
    ])

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}main.armis_client.datetime")
  def test_pagination_in_vulnerabilities(
      self,
      mocked_datetime,
      unused_mock_multiprocessing,
      mock_http_request,
      unused_mocked_sleep,
      mocked_ingest,
      mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case to verify the pagination mechanism in vulnerabilities data type."""
    mocked_get_env_var.side_effect = [
        None,
        None,
        None,
        None,
    ]
    mocked_get_last_run.return_value = datetime.datetime(
        2023, 2, 20, 10, 00, 00, tzinfo=datetime.timezone.utc
    )
    mocked_datetime.datetime.now.return_value = datetime.datetime(
        2023, 2, 20, 10, 10, 00, tzinfo=datetime.timezone.utc
    )
    mocked_datetime.datetime.strptime.side_effect = datetime.datetime.strptime
    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        {
            "data": {
                "count": 1,
                "next": 2,
                "results": MOCK_RESPONSE_VULNERABILITIES[:2],
                "total": 4,
            }
        },
        status_code=200,
    )
    mocked_response_3 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_4 = MockResponse(
        {
            "data": {
                "count": 1,
                "next": None,
                "results": MOCK_RESPONSE_VULNERABILITIES[1:],
                "total": 2,
            }
        },
        status_code=200,
    )

    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_3,
        mocked_response_4,
    ]

    main.execute_script(
        ARMIS_SERVER_URL,
        ARMIS_SECRET_KEY,
        "ARMIS_VULNERABILITIES",
        INITIAL_ACCESS_TOKEN_INFO,
    )

    self.assertEqual(mocked_ingest.call_count, 2)
    self.assertEqual(
        mocked_ingest.mock_calls,
        [
            mock.call(
                [EXPECTED_RESPONSE_VULNERABILITIES[1]], "ARMIS_VULNERABILITIES"
            ),
            mock.call(
                EXPECTED_RESPONSE_VULNERABILITIES[1:][::-1],
                "ARMIS_VULNERABILITIES",
            ),
        ],
    )

  def test_chronicle_ingestion_error(
      self,
      unused_mock_multiprocessing,
      mock_http_request,
      unused_mocked_sleep,
      mocked_ingest,
      unused_mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case scenario when error is obtained from Chronicle ingestion."""
    mocked_get_env_var.side_effect = [
        "http_proxy_url",
        "http_proxy_url",
        None,
        None,
    ]
    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        {"data": {"count": 1, "next": 2, "results": [{"id": 1}], "total": 2}},
        status_code=200,
    )

    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_1,
        mocked_response_2,
    ]

    mocked_ingest.side_effect = requests.HTTPError(
        "Bad Request. Request contains an invalid argument."
    )

    for chronicle_label in CHRONICLE_LABELS:
      with self.assertRaises(Exception) as error:
        main.execute_script(
            ARMIS_SERVER_URL,
            ARMIS_SECRET_KEY,
            chronicle_label,
            INITIAL_ACCESS_TOKEN_INFO,
        )

    self.assertEqual(
        str(error.exception),
        (
            "Unable to push data to Chronicle. Bad Request. "
            "Request contains an invalid argument."
        ),
    )

    self.assertEqual(os.environ["HTTPS_PROXY"], "http://http_proxy_url")

  def test_400_http_error_from_armis_api(
      self,
      unused_mock_multiprocessing,
      mock_http_request,
      unused_mocked_sleep,
      unused_mocked_ingest,
      unused_mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case scenario when 400 error is obtained from Armis API."""
    mocked_get_env_var.side_effect = [
        None,
        None,
        None,
        None,
    ]
    mocked_response = MockResponse(
        {"message": "Invalid secret key.", "success": False},
        status_code=400,
        reason="Bad Request",
    )

    mock_http_request.side_effect = [mocked_response, mocked_response]

    for chronicle_label in CHRONICLE_LABELS:
      with self.assertRaises(Exception) as error:
        main.execute_script(
            ARMIS_SERVER_URL,
            ARMIS_SECRET_KEY,
            chronicle_label,
            INITIAL_ACCESS_TOKEN_INFO,
        )

    self.assertEqual(
        str(error.exception),
        (
            "API call failed. HTTP error. "
            "Error = 400: Bad Request. Invalid secret key."
        ),
    )

  def test_500_http_error_from_armis_api(
      self,
      unused_mock_multiprocessing,
      mock_http_request,
      unused_mocked_sleep,
      unused_mocked_ingest,
      unused_mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case scenario when 500 error is obtained from Armis API."""
    mocked_get_env_var.side_effect = [
        None,
        None,
        None,
        None,
    ]
    mocked_response = MockResponse(
        {"message": "Internal server error occurred.", "success": False},
        status_code=500,
        reason="Internal Server Error",
    )

    mock_http_request.side_effect = [
        mocked_response,
        mocked_response,
        mocked_response,
        mocked_response,
    ]

    with self.assertRaises(Exception) as error:
      main.execute_script(
          ARMIS_SERVER_URL,
          ARMIS_SECRET_KEY,
          "ARMIS_ALERTS",
          INITIAL_ACCESS_TOKEN_INFO,
      )

    self.assertEqual(
        str(error.exception),
        (
            "API call failed. HTTP error. Error = 500: Internal Server Error."
            " Internal server error occurred."
        ),
    )
    self.assertEqual(mock_http_request.call_count, 4)

  def test_401_http_error_from_armis_api(
      self,
      unused_mock_multiprocessing,
      mock_http_request,
      unused_mocked_sleep,
      unused_mocked_ingest,
      unused_mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case scenario when 401 error is obtained from Armis API."""
    mocked_get_env_var.side_effect = [
        None,
        None,
    ]
    mocked_response_1 = MockResponse(
        MOCK_RESPONSE_ACCESS_TOKEN, status_code=200
    )
    mocked_response_2 = MockResponse(
        {"message": "Unauthorized.", "success": False},
        status_code=401,
        reason="Reason for unauthorization",
    )

    mock_http_request.side_effect = [
        mocked_response_1,
        mocked_response_2,
        mocked_response_1,
        mocked_response_2,
    ]

    with self.assertRaises(Exception) as error:
      main.execute_script(
          ARMIS_SERVER_URL,
          ARMIS_SECRET_KEY,
          "ARMIS_ALERTS",
          INITIAL_ACCESS_TOKEN_INFO,
      )

    self.assertEqual(
        str(error.exception),
        (
            "API call failed. HTTP error. Error = 401: Reason for"
            " unauthorization. Unauthorized."
        ),
    )

  def test_connection_error_from_armis_api(
      self,
      unused_mock_multiprocessing,
      mock_http_request,
      unused_mocked_sleep,
      unused_mocked_ingest,
      unused_mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case scenario when connection error is obtained from Armis API."""
    mocked_get_env_var.side_effect = [
        None,
        None,
        None,
        None,
    ]
    mock_http_request.side_effect = requests.ConnectionError(
        "Failed to establish a connection."
    )

    for chronicle_lable in CHRONICLE_LABELS:
      with self.assertRaises(Exception) as error:
        main.execute_script(
            ARMIS_SERVER_URL,
            ARMIS_SECRET_KEY,
            chronicle_lable,
            INITIAL_ACCESS_TOKEN_INFO,
        )

    self.assertEqual(
        str(error.exception),
        (
            "API call failed. Invalid Server URL. "
            "Failed to establish a connection."
        ),
    )

  def test_duplicate_chronicle_label(
      self,
      unused_mock_multiprocessing,
      unused_mock_http_request,
      unused_mocked_sleep,
      unused_mocked_ingest,
      unused_mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case scenario when duplicate chronicle label is provided in environment variable."""

    mocked_get_env_var.side_effect = [
        "ARMIS_ALERTS,ARMIS_ACTIVITIES,ARMIS_ALERTS"
    ]

    with self.assertRaises(Exception) as error:
      main.main(request="")

    self.assertEqual(
        str(error.exception),
        "Chronicle data type(s) ARMIS_ALERTS provided more than once.",
    )

  def test_invalid_chronicle_label(
      self,
      unused_mock_multiprocessing,
      unused_mock_http_request,
      unused_mocked_sleep,
      unused_mocked_ingest,
      unused_mocked_get_last_run,
      mocked_get_env_var,
  ):
    """Test case scenario when invalid chronicle label is provided in environment variable."""

    mocked_get_env_var.side_effect = ["ARMIS_ALERTS, INVALID_LABEL"]

    with self.assertRaises(Exception) as error:
      main.main(request="")

    self.assertEqual(
        str(error.exception),
        (
            "Invalid Chronicle data type(s) INVALID_LABEL provided. "
            "Supported Labels: ARMIS_ALERTS, ARMIS_ACTIVITIES, "
            "ARMIS_DEVICES, ARMIS_VULNERABILITIES"
        ),
    )
