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
"""A common module for collecting indicators from STIX/TAXII versions 1.1, 2.0 and 2.1.

The script connects with the different TAXII Servers and collects indicators.
"""

import datetime
import tempfile
from typing import Any, Dict, List
import urllib

import cabby
from stix import core
from taxii2client import v20
from taxii2client import v21

# STIX compliant date format.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Page size for fetching indicators.
PAGE_SIZE = 1000

# Type of objects to be fetched from the TAXII Server.
TAXII_OBJ_TYPE_TO_FETCH = "indicator"

# Collection Managerment Service constant.
TAXII_COLLECTION_MGMT_SERVICE = "COLLECTION_MANAGEMENT"

# TAXII version constants.
TAXII_VERSION_11 = "1.1"
TAXII_VERSION_20 = "2.0"
TAXII_VERSION_21 = "2.1"

# List of supported values for TAXII version.
SUPPORTED_TAXII_VERSIONS = [
    TAXII_VERSION_11,
    TAXII_VERSION_20,
    TAXII_VERSION_21
]


def convert_date_to_stix_format(datetime_obj: datetime.datetime) -> str:
  """Convert a datetime object into a valid STIX timestamp string.

  Args:
    datetime_obj (datetime.datetime): Python datetime object indicating the
      start time to collect the indicators from.

  Returns:
    str: STIX compliant string representation of the datetime object.
  """
  # Return a datetime string in the format of YYYY-MM-DDTHH:MM:SSS.SSSZ.
  return datetime_obj.strftime(DATE_FORMAT)


class InvalidValueError(Exception):
  """Custom exception class for invalid values."""

  def __init__(self, message: str) -> None:
    """Constructor for InvalidValueError class.

    Args:
      message (str): Error message.
    """
    self.message = message
    super().__init__(message)


class TAXIIClient:
  """Generic implementation of TAXII Client for TAXII version 1.1, 2.0 & 2.1."""

  def __init__(self, discovery_url: str, username: str, password: str,
               taxii_version: str, collection_names: str) -> None:
    """Constructor for TAXIIClient class.

    Args:
      discovery_url (str): Discovery URL of the TAXII Server.
      username (str): Username for authentication.
      password (str): Password for authentication.
      taxii_version (str): TAXII version. Possible values- 1.1, 2.0 or 2.1.
      collection_names (str): CSV string of collection names.
    """
    self.discovery_url = discovery_url.strip()
    self.username = username
    self.password = password
    self.taxii_version = taxii_version.strip()
    self.collection_names = collection_names
    self.client = self.configure_taxii_client()

  def _validate_configuration_params(self) -> None:
    """Validate the configuration parameters.

    Raises:
      InvalidValueError: If any parameter has non-accepted value.
    """
    if not self.discovery_url:
      raise InvalidValueError(
          "Validation error: Discovery URL is empty or invalid.")

    if self.taxii_version not in SUPPORTED_TAXII_VERSIONS:
      raise InvalidValueError("Validation error: "
                              "Invalid TAXII version provided. "
                              "Expected values are 1.1, 2.0 or 2.1.")

  def _get_taxii1_collections(self,
                              client: cabby.client11.Client11) -> List[str]:
    """Return a list of collection names from the TAXII v1 server.

    Args:
      client (cabby.client11.Client11): TAXII v1 client to connect to TAXII
        v1 server.

    Returns:
      List[str]: A list of collection names.
    """
    print("Fetching available collections from TAXII server v1.1.")

    # This will store the TAXII collection management service's URI.
    collection_uri = None

    # Fetch the list of available services from the TAXII server.
    services = client.discover_services()

    # Identifies the collection management service.
    for service in services:
      if service.type == TAXII_COLLECTION_MGMT_SERVICE:
        collection_uri = service.address
        break

    if collection_uri is None:
      print("Failed to find collection management service.")
      return []

    # Returns the list of collection names from TAXII server.
    return [c.name for c in client.get_collections(uri=collection_uri)]

  def _validate_and_filter_collections(self, client: Any) -> None:
    """Validates the collection names provided in TAXII_COLLECTION_NAMES environment variable.

    Args:
      client (Any): TAXII client object to connect to the TAXII server.

    Raises:
      InvalidValueError: If the provided collection name is not available on
        TAXII Server.
    """
    # This will store the list of all collection names available on the server.
    available_collections = None

    # Fetch all available collections from TAXII Server.
    if self.taxii_version == TAXII_VERSION_11:
      available_collections = self._get_taxii1_collections(client)
    else:
      available_collections = [c.title for c in client.collections]

    # Validate the user provided collection names.
    if self.collection_names:
      print("Validating the provided list of TAXII collection names.")

      # Create a list of collection names from the CSV string provided in
      # TAXII_COLLECTION_NAMES environment variable.
      self.collection_names = [
          name.strip() for name in self.collection_names.split(",")
      ]

      # Filter out any empty strings from the collection names list.
      self.collection_names = list(filter(lambda x: x, self.collection_names))

      # Verify whether collection names provided by the user exists on the
      # server. If not, then raise an error.
      not_available_collections = set(
          self.collection_names) - set(available_collections)
      if not_available_collections:
        raise InvalidValueError(
            f"Validation error: "
            f"Could not find the TAXII collections: "
            f"{', '.join(not_available_collections)}.")
    else:
      # If user has not provided any collection name,
      # then set all available collections as collection_names.
      # Meaning, the indicators will be fetched from all available collections.
      print("As no collection names are provided,"
            " objects will be fetched from all available collections.")
      self.collection_names = available_collections

    print("Indicators will be fetched from TAXII collections: ",
          f"{', '.join(self.collection_names)}.")

  def _create_taxii1_client(self):
    """Create a TAXII v1.1 Cabby client.

    Returns:
      client: TAXII v1.1 client.
    """
    # Parse the discovery url provided by user.
    parsed_url = urllib.parse.urlparse(self.discovery_url)
    discovery_url = parsed_url.path

    if len(parsed_url.netloc.split(":")) > 1:
      # If the url contains hostname and port both.
      base, port = parsed_url.netloc.split(":")
      port = int(port)
      client = cabby.create_client(
          base,
          port=port,
          use_https=True,
          discovery_path=discovery_url,
      )
    else:
      # If the url contains hostname only.
      client = cabby.create_client(
          parsed_url.netloc,
          use_https=True,
          discovery_path=discovery_url,
      )

    # Set the username and password in the client object.
    if self.username and self.password:
      client.set_auth(
          username=self.username,
          password=self.password,
      )

    return client

  def configure_taxii_client(self):
    """Create a TAXII Client based on the provided TAXII Version.

    Returns:
        client: TAXII Client.
    """
    # Validate the configuration parameters.
    self._validate_configuration_params()
    client = None

    print(f"Creating TAXII Client for TAXII Version {self.taxii_version}.")

    # Create TAXII Client based on given TAXII Version.
    if self.taxii_version == TAXII_VERSION_11:
      client = self._create_taxii1_client()
    elif self.taxii_version == TAXII_VERSION_20:
      server = v20.Server(
          url=self.discovery_url, user=self.username, password=self.password)
      client = server.default
    elif self.taxii_version == TAXII_VERSION_21:
      server = v21.Server(
          url=self.discovery_url, user=self.username, password=self.password)
      client = server.default

    # Validate the user provided collection names.
    self._validate_and_filter_collections(client)

    return client

  def _pull_indicators_11(self, start_time: str) -> List[Dict[str, Any]]:
    """Pull indicators from TAXII v1.1 server.

    Args:
      start_time (str): STIX compliant datetime string to collect the indicators
        from.

    Returns:
      List[Dict[str, Any]]: List of indicators.
    """
    indicators = []

    print(f"Retrieving the indicators from {start_time}.")
    # Fetch the indicators from the list of validated collection names.
    for collection in self.collection_names:
      print(f"Retrieving the indicators from collection: {collection}.")

      # Make a poll request to TAXII v1 server, and fetch content blocks.
      content_blocks = self.client.poll(
          collection_name=collection, begin_date=start_time)

      # The block data is in bytes. So, write the content of the block
      # to a temporary file. The indicators returned by the TAXII v1 server
      # are in xml format. So, convert those to JSON by using the "stix"
      # library.
      for block in content_blocks:
        temp_file = tempfile.TemporaryFile()
        temp_file.write(block.content)
        temp_file.seek(0)
        stix_package = core.STIXPackage.from_xml(temp_file)
        stix_dict = stix_package.to_dict()  # Convert stix package to dictonary.
        indicators = indicators + stix_dict.get("indicators", [])
        temp_file.close()  # This will delete the temporary file.

      print(f"Completed fetching of indicators from collection: {collection}.")
      print(f"Total {len(indicators)} indicators collected till now.")
    return indicators

  def _pull_indicators_2x(self, start_time: str) -> List[Dict[str, Any]]:
    """Pull indicators from TAXII v2.X Server.

    Args:
      start_time (str): STIX compliant datetime string to collect the indicators
        from.

    Returns:
      List[Dict[str, Any]]: List of indicators.
    """
    all_indicators = []

    # This will store the filtered collection "objects" based on user provided
    # collection names.
    filtered_collections = list(
        filter(lambda x: x.title in self.collection_names,
               self.client.collections))

    if self.taxii_version == TAXII_VERSION_20:
      as_pages_iter = v20.as_pages
    else:
      as_pages_iter = v21.as_pages

    print(f"Retrieving the indicators from {start_time}.")
    # Fetch the indicators from the list of validated collection names.
    for collection in filtered_collections:
      print(
          f"Retrieving the indicators from collection: {collection}."
      )

      try:
        # Execute paginated API calls to the TAXII Server through library and
        # collect the data.
        for bundle in as_pages_iter(
            collection.get_objects,
            per_request=PAGE_SIZE,
            added_after=start_time,
            type=TAXII_OBJ_TYPE_TO_FETCH,
        ):
          # Filtering the indicators here, because API response includes
          # some extra objects like marking-definitions, which are not
          # required.
          indicators = list(
              filter(
                  lambda x: x.get("type").lower() == TAXII_OBJ_TYPE_TO_FETCH,
                  bundle.get("objects", []),
              ))

          if not indicators:
            break

          all_indicators = all_indicators + indicators

      # In version 2.0 TAXII client, pagination is done using headers
      # and H-ISAC TAXII Server is not returning required pagination headers
      # for the last page. Due to which, KeyError is raised by the taxii2client
      # library. Data wouldn't be lost here, as we're getting all data from the
      # API. Only the headers are missing.
      except KeyError:
        pass

      print(
          "Completed fetching of indicators from collection: "
          f"{collection.title}.")
      print(f"Total {len(all_indicators)} indicators collected till now.")
    return all_indicators

  def pull_indicators(self, start_time: str) -> List[Dict[str, Any]]:
    """Pull indicators which are added after start_time based on the provided TAXII version.

    Args:
      start_time (str): STIX compliant datetime string.

    Returns:
      List[Dict[str, Any]]: List of indicators for TAXII v1.1, v2.0 & v2.1.
    """
    print(f"Pulling indicators which are created after {start_time}.")

    if self.taxii_version == TAXII_VERSION_11:
      return self._pull_indicators_11(start_time)
    else:
      return self._pull_indicators_2x(start_time)
