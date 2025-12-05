# Copyright 2025 Google LLC
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

"""Google Threat Intelligence Constants."""

import immutabledict

immutabledict = immutabledict.immutabledict

# ENVIRONMENT VARIABLES CONSTANTS
ENV_VAR_GTI_API_TOKEN = "GTI_API_TOKEN"
ENV_VAR_ENRICHMENT_ENABLED = "ENRICHMENT_ENABLED"
ENV_VAR_HISTORICAL_LOG_FETCH_DURATION = "HISTORICAL_LOG_FETCH_DURATION"
ENV_VAR_LOG_TYPES = "LOG_TYPES"
ENV_REDIS_TTL = "REDIS_TTL"

ENV_VAR_THREAT_LISTS = "THREAT_LISTS"
ENV_VAR_THREAT_LISTS_START_TIME = "THREAT_LISTS_START_TIME"
ENV_VAR_THREAT_LIST_QUERY = "THREAT_LIST_QUERY"

ENV_VAR_FETCH_IOC_STREAM_ENABLED = "FETCH_IOC_STREAM_ENABLED"
ENV_VAR_HISTORICAL_IOC_STREAM_DURATION = "HISTORICAL_IOC_STREAM_DURATION"
ENV_VAR_IOC_STREAM_FILTER = "IOC_STREAM_FILTER"

ENV_VAR_MITRE_ATTACK_ENABLED = "MITRE_ATTACK_ENABLED"

ENV_VAR_GCP_BUCKET_NAME = "GCP_BUCKET_NAME"


# Default Values
DEFAULT_VALUES = immutabledict({
    ENV_VAR_ENRICHMENT_ENABLED: "true",
    ENV_VAR_FETCH_IOC_STREAM_ENABLED: "true",
    ENV_REDIS_TTL: 15,
    ENV_VAR_HISTORICAL_LOG_FETCH_DURATION: 60,
    ENV_VAR_HISTORICAL_IOC_STREAM_DURATION: "1",
    ENV_VAR_THREAT_LISTS: "",
    ENV_VAR_MITRE_ATTACK_ENABLED: "false",
})


# API Constants
BASE_URL = "https://www.virustotal.com"
API_VERSION = "/api/v3"
THREAT_LIST_URL = (
    BASE_URL + API_VERSION + "/threat_lists/{threat_type}/{start_time}"
)
IOC_STREAM_URL = BASE_URL + API_VERSION + "/ioc_stream"
ENRICHMENT_URL = BASE_URL + API_VERSION + "/{entity_type}/{entity_id}"
MITRE_URL = BASE_URL + API_VERSION + "/files/{file_id}/behaviour_mitre_trees"
RELATIONSHIP_URL = (
    BASE_URL + API_VERSION + "/{entity_type}/{entity_id}/{relationship_type}"
)

GTI_APP_VERSION = "1.0.0"

CONTENT_TYPE_JSON = "application/json"
X_TOOL = "gti-google-secops-1.0.0"

CONNECTION_TIMEOUT = 60  # In seconds
READ_TIMEOUT = 300  # In seconds
DEFAULT_SLEEP_TIME = 60

ALL_THREAT_LISTS = (
    "ransomware",
    "malicious-network-infrastructure",
    "malware",
    "threat-actor",
    "trending",
    "mobile",
    "osx",
    "linux",
    "iot",
    "cryptominer",
    "phishing",
    "first-stage-delivery-vectors",
    "vulnerability-weaponization",
    "infostealer",
)

RELATIONSHIP_ATTRIBUTES = (
    "name,id,origin,collection_type,description,"
    "source_regions_hierarchy,targeted_industries_tree,"
    "targeted_regions_hierarchy"
)

ENRICHMENT_RELATIONSHIP_PARAMS = immutabledict({
    "relationships": (
        "collections,malware_families,related_threat_actors,campaigns,comments,"
        "software_toolkits,reports"
    ),
    "relationship_attributes[collections]": RELATIONSHIP_ATTRIBUTES,
    "relationship_attributes[malware_families]": (
        RELATIONSHIP_ATTRIBUTES
    ),
    "relationship_attributes[related_threat_actors]": (
        RELATIONSHIP_ATTRIBUTES
    ),
    "relationship_attributes[software_toolkits]": (
        RELATIONSHIP_ATTRIBUTES
    ),
    "relationship_attributes[campaigns]": RELATIONSHIP_ATTRIBUTES,
    "relationship_attributes[reports]": RELATIONSHIP_ATTRIBUTES,
    "relationship_attributes[comments]": "date,text,votes,tags",
})

RELATIONSHIPS_PER_PAGE = 40
IOC_STREAM_PER_PAGE = 40
IOC_STREAM_DATE_PATTERN = "%Y-%m-%dT%H:%M:%S"
THREAT_FEED_LIMIT = 4000
RETRY_COUNT = 3

# Message Constants
GENERAL_ERROR_MESSAGE = (
    "Failed to fetch {fetch_type}, received status code - {status_code}."
    " Response - {response_text}."
)
ERR_MSG_FAILED_TO_PARSE_RESPONSE = (
    "Error while parsing response from Google Threat Intelligence. Response ="
    " {0}. Error = {1}"
)
CHECK_LOGS_FOR_MORE_DETAILS = " Check logs for more details."
RETRY_MESSAGE = "Retrying after {0} seconds."

IOC_STREAM_CURSOR_CHECKPOINT_KEY = "ioc_stream_cursor"
IOC_STREAM_TIME_CHECKPOINT_KEY = "ioc_stream_time"
GOOGLE_SECOPS_DATA_TYPE = "GCP_THREATINTEL"
MAX_DAYS_TO_FETCH_THREAT_LISTS = 7
MAX_DAYS_TO_FETCH_IOC_STREAM = 7
DEFAULT_HISTORICAL_THREAT_LISTS_DAYS = 1

# Checkpoint file sharding configuration
CHECKPOINT_SHARDS = immutabledict({
    "checkpoint_shard_1.json": [
        "malware",
        "ransomware",
        "phishing",
        "cryptominer",
    ],
    "checkpoint_shard_2.json": [
        "threat-actor",
        "malicious-network-infrastructure",
        "trending",
        "mobile",
    ],
    "checkpoint_shard_3.json": [
        "iot",
        "first-stage-delivery-vectors",
        "vulnerability-weaponization",
        "infostealer",
    ],
    "checkpoint_ioc_stream.json": [
        IOC_STREAM_CURSOR_CHECKPOINT_KEY,
        IOC_STREAM_TIME_CHECKPOINT_KEY,
        "osx",
        "linux",
    ],
})

# Mapping from checkpoint keys to their shard files
CHECKPOINT_KEY_TO_SHARD = {}
for shard_file, keys in CHECKPOINT_SHARDS.items():
  for key in keys:
    CHECKPOINT_KEY_TO_SHARD[key] = shard_file

PERMISSION_DETAILS = immutabledict({
    "Storage Admin": "roles/storage.admin",
    "Secret Manager Secret Accessor": "roles/secretmanager.secretAccessor",
    "Cloud Scheduler Job Runner": "roles/cloudscheduler.jobRunner"
})
