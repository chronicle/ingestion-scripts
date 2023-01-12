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
"""Fetch indicators from the STIX/TAXII Server and ingest into Chronicle."""

from common import ingest
from common import utils
import taxii_client

# Environment variable constants.
ENV_TAXII_DISCOVERY_URL = "TAXII_DISCOVERY_URL"
ENV_TAXII_USERNAME = "TAXII_USERNAME"
ENV_TAXII_PASSWORD_SECRET_PATH = "TAXII_PASSWORD_SECRET_PATH"
ENV_TAXII_VERSION = "TAXII_VERSION"
ENV_TAXII_COLLECTION_NAMES = "TAXII_COLLECTION_NAMES"

# Log type to push data into Chronicle.
CHRONICLE_DATA_TYPE = "STIX"


def get_and_ingest_indicators(client: taxii_client.TAXIIClient) -> None:
  """Get indicators from STIX/TAXII server and ingest them into Chronicle.

  Args:
    client (taxii_client.TAXIIClient): TAXII Client to be used for collecting
      indicators.

  Raises:
    Exception: If any error occurred while fetching and ingesting the
      indicators.
  """
  # Calculate the start time based on the POLL_INTERVAL environment variable.
  start_time = utils.get_last_run_at()

  # Convert the datetime object to STIX compliant datetime string.
  # Expected format is (YYYY-MM-DDTHH:MM:SSS.SSSZ).
  start_time = taxii_client.convert_date_to_stix_format(start_time)

  # Pull indicators from the TAXII server.
  try:
    fetched_indicators = client.pull_indicators(start_time)
  except Exception as error:
    raise Exception(
        "Failure occurred while fetching the indicators from the STIX/TAXII "
        "server."
    ) from error

  # Ingest data into Chronicle.
  try:
    ingest.ingest(fetched_indicators, CHRONICLE_DATA_TYPE)
  except Exception as error:
    raise Exception(
        "Failure occurred while ingesting the indicators into Chronicle."
    ) from error


def main(req) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
    req: Request to execute the cloud function.

  Returns:
    string: "Ingestion completed."
  """
  # Fetch the environment variables.
  discovery_url = utils.get_env_var(ENV_TAXII_DISCOVERY_URL)
  username = utils.get_env_var(ENV_TAXII_USERNAME, required=False)
  password = utils.get_env_var(
      ENV_TAXII_PASSWORD_SECRET_PATH, is_secret=True, required=False)
  # Possible values of TAXII version are 1.1, 2.0 or 2.1.
  taxii_version = utils.get_env_var(ENV_TAXII_VERSION)
  # Provide specific collection names from which the indicators should be
  # collected. These collection names are specific to the STIX/TAXII server.
  # By default, the indicators will be collected from all the collections.
  collection_names = utils.get_env_var(
      ENV_TAXII_COLLECTION_NAMES, required=False)

  # Create a Taxii client based on the provided parameters.
  client = taxii_client.TAXIIClient(
      discovery_url=discovery_url,
      username=username,
      password=password,
      taxii_version=taxii_version,
      collection_names=collection_names)

  # Fetch and ingest the indicators from STIX/TAXII server into Chronicle.
  get_and_ingest_indicators(client)

  return "Ingestion completed."
