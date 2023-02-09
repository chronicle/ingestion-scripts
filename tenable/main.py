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
"""Fetch assets and vulnerabilities from the TenableIO and ingest into Chronicle.
"""

from typing import Any, Dict, List

from tenable import errors
from tenable import io

from common import ingest
from common import utils

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "TENABLE_IO"

# Date format to be used to parse the date string to the datatime object.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Possible data types.
VALID_DATA_TYPES = ["assets", "vulnerabilities"]

# Possible vulnerability states.
VALID_VULNERABILITY_STATES = ["open", "reopened", "fixed"]

# Page size for fetching assets and vulnerabilities from Tenable.
PAGE_SIZE = 1000

TENABLE_ASSETS_DATA_TYPE = "assets"
TENABLE_VULN_DATA_TYPE = "vulnerabilities"

# By default, the script will collect data of assets and vulnerabilities.
DEFAULT_TENABLE_DATA_TYPE = (
    f"{TENABLE_ASSETS_DATA_TYPE}, {TENABLE_VULN_DATA_TYPE}"
)

# Default values for Tenable vulnerability states.
# By default, the script will collect data for open and reopened
# vulnerabilities.
DEFAULT_TENABLE_VULNERABILITY = "open, reopened"

# Environment variable constants.
ENV_TENABLE_ACCESS_KEY = "TENABLE_ACCESS_KEY"
ENV_TENABLE_SECRET_KEY_PATH = "TENABLE_SECRET_KEY_PATH"
ENV_TENABLE_DATA_TYPE = "TENABLE_DATA_TYPE"
ENV_TENABLE_VULNERABILITY = "TENABLE_VULNERABILITY"


class InvalidValueError(Exception):
  """Custom exception class for invalid values."""

  def __init__(self, message: str) -> None:
    """Constructor for InvalidValueError class.

    Args:
      message (str): Error message.
    """
    self.message = message
    super().__init__(message)


def validate_params(vulnerability_state: List[Any],
                    data_type: List[Any]) -> None:
  """Validate and prepare the configuration parameters.

  Args:
    vulnerability_state (List): State of the vulnerability for which data should
      be fetched.
    data_type (List): Data type of the events.

  Raises:
    InvalidValueError: If any parameter has non-accepted value.
  """
  # Check for valid vulnerability state.
  for vulns in vulnerability_state:
    if vulns not in VALID_VULNERABILITY_STATES:
      raise InvalidValueError(
          "Validation Error: Invalid Value provided for Tenable Vulnerability"
          " State. Vulnerability state should be one of the following:"
          f" {VALID_VULNERABILITY_STATES}"
      )

  # Check for valid data type.
  for data in data_type:
    if data not in VALID_DATA_TYPES:
      raise InvalidValueError(
          "Validation Error: Invalid Value provided for Tenable Data Type. "
          f"Data types should be one of the following: {VALID_DATA_TYPES}")


def collect_data_from_tenable(tio: io.TenableIO, data_type: str,
                              params: Dict[Any, Any]) -> List[Any]:
  """Collect data from Tenable platform.

  Args:
    tio (TenableIO) : TenableIO object.
    data_type (str): Data type for which data needs to be fetched and ingested
    into Chronicle.
    params (Dict): Parameters required for retrieving the data.

  Returns:
    Tenable_data (List): List of data fetched from Tenable.
  """
  try:
    # Collect data for Tenable assets.
    if TENABLE_ASSETS_DATA_TYPE in data_type:
      data_set = tio.exports.assets(**params)
    # Collect data for Tenable vulnerabilities.
    else:
      data_set = tio.exports.vulns(**params)

    tenable_data = list(data_set)
  except errors.UnauthorizedError as error:
    raise RuntimeError(
        f"Invalid client credentials provided: {str(error)}") from error
  except (errors.TioExportsTimeout, errors.TioExportsError) as error:
    raise RuntimeError("The error occurred during data collection from "
                       f"Tenable.io: {str(error)}") from error
  except Exception as error:
    raise Exception("Unknown error occurred during data collection from "
                    f"Tenable.io: {str(error)}") from error

  return tenable_data


def get_and_ingest_assets(tio: io.TenableIO) -> None:
  """Fetch assets from TenableIO platform and ingest into Chronicle.

  Args:
    tio (TenableIO) : TenableIO object.

  Raises:
    RuntimeError: Raised error for an unexpected behavior.
  """
  # Calculate the start time based on the POLL_INTERVAL environment variable.
  start_time = utils.get_last_run_at()
  # Converting the date time object to epoch format.
  epoch_time = int(start_time.timestamp())

  # Prepare the parameters that needs to be used while collecting assets.
  # The PAGE_SIZE parameter is used by the pyTenable SDK internally to collect
  # data from the Tenable. Hence, we will not need to iterate over the pages as
  # it is handled inherently by the SDK.
  params = {
      "chunk_size": PAGE_SIZE,
      "updated_at": epoch_time
  }

  print("Retrieving assets which are updated after "
        f"{start_time.strftime(DATE_FORMAT)}.")

  # Fetch assets information from the Tenable platform.
  assets_list = collect_data_from_tenable(
      tio, data_type=TENABLE_ASSETS_DATA_TYPE, params=params)

  # Ingest assets information into Chronicle.
  if assets_list:
    print(f"Started ingesting {len(assets_list)} asset(s) in Chronicle.")
    try:
      ingest.ingest(assets_list, CHRONICLE_DATA_TYPE)
    except Exception as error:
      raise RuntimeError("Unable to push assets into Chronicle: "
                         f"{str(error)}") from error
  else:
    print("Total 0 Assets retrieved till now.")


def get_and_ingest_vulnerabilities(tio: io.TenableIO,
                                   vulnerability_state: List[Any]) -> None:
  """Fetch vulnerabilities from TenableIO platform and ingest into Chronicle.

  Args:
    tio (TenableIO) : TenableIO object.
    vulnerability_state (List) : A list of vulnerability states that needs to be
    fetched and ingested.

  Raises:
    RuntimeError: Raises error for an unexpected behavior.
  """
  # Calculate the start time based on the POLL_INTERVAL environment variable.
  start_time = utils.get_last_run_at()
  # Converting the date time object to epoch format.
  epoch_time = int(start_time.timestamp())

  # Prepare the parameters that needs to be used while collecting
  # vulnerabilities.
  # The PAGE_SIZE parameter is used by the pyTenable SDK internally to collect
  # data from the Tenable. Hence, we will not need to iterate over the pages as
  # it is handled inherently by the SDK.
  params = {
      "num_assets": PAGE_SIZE,
      "last_found": epoch_time,
      "state": vulnerability_state
  }

  print("Retrieving vulnerabilities which are added after "
        f"{start_time.strftime(DATE_FORMAT)}")

  # Fetch vulnerabilities information from Tenable platform.
  vulnerabilities_list = collect_data_from_tenable(
      tio, data_type=TENABLE_VULN_DATA_TYPE, params=params)

  # Ingest vulnerabilities into Chronicle.
  if vulnerabilities_list:
    print(f"Started ingesting {len(vulnerabilities_list)} "
          "vulnerabilities in Chronicle.")
    try:
      ingest.ingest(vulnerabilities_list, CHRONICLE_DATA_TYPE)
    except Exception as error:
      raise RuntimeError("Unable to push vulnerabilities into "
                         f"Chronicle: {str(error)}") from error
  else:
    print("Total 0 Vulnerabilities retrieved till now.")


def main(request) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    request: Request to execute the cloud function.

  Returns:
    str: "Ingestion completed".
  """
  # Fetch the environment variables.
  access_key = utils.get_env_var(ENV_TENABLE_ACCESS_KEY)
  secret_key = utils.get_env_var(ENV_TENABLE_SECRET_KEY_PATH, is_secret=True)
  tenable_data_type = utils.get_env_var(
      ENV_TENABLE_DATA_TYPE, required=False, default=DEFAULT_TENABLE_DATA_TYPE)
  tenable_vulnerability = utils.get_env_var(
      ENV_TENABLE_VULNERABILITY,
      required=False,
      default=DEFAULT_TENABLE_VULNERABILITY)

  # Create a list of data types from CSV string.
  data_type = [
      type_value.lower().strip()
      for type_value in tenable_data_type.strip().split(",")
  ]

  # Create a list of vulnerability states from CSV string.
  vulnerability_state = [
      state.lower().strip()
      for state in tenable_vulnerability.strip().split(",")
  ]

  # Validating if the expected values are provided for Tenable Vulnerability
  # state and Tenable data type.
  validate_params(vulnerability_state, data_type)

  # Create a Tenable client based on the provided parameters.
  client = io.TenableIO(access_key, secret_key)

  # Fetch and ingest assets from Tenable and ingest into Chronicle.
  if TENABLE_ASSETS_DATA_TYPE in data_type:
    get_and_ingest_assets(client)

  # Fetch and ingest vulnerabilities from Tenable and ingest into Chronicle.
  if TENABLE_VULN_DATA_TYPE in data_type:
    get_and_ingest_vulnerabilities(client, vulnerability_state)

  return "Ingestion completed."
