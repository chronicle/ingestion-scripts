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

"""Cyware CTIX Constants for Google SecOps SIEM Integration."""

import immutabledict

USER_AGENT_NAME = "cyware/intel-exchange (GoogleSecopsSIEM/1.0.0)"

# ENVIRONMENT VARIABLES CONSTANTS
ENV_TENANT_NAME = "CYWARE_TENANT_NAME"
ENV_BASE_URL = "CYWARE_BASE_URL"
ENV_ACCESS_ID = "CYWARE_ACCESS_ID"
ENV_SECRET_KEY = "CYWARE_SECRET_KEY"
ENV_ENRICHMENT_ENABLED = "CYWARE_ENRICHMENT_ENABLED"
ENV_INDICATOR_LOOKBACK_DAYS = "CYWARE_INDICATOR_LOOKBACK_DAYS"
ENV_LABEL_NAME = "CYWARE_SAVED_RESULT_SET_NAME"
ENV_GCP_BUCKET_NAME = "GCP_BUCKET_NAME"

# Default values
DEFAULT_VALUES = immutabledict.immutabledict(
    {ENV_ENRICHMENT_ENABLED: "false", ENV_INDICATOR_LOOKBACK_DAYS: 7}
)
FETCH_ENRICHMENT_DATA = "true"
FETCH_RELATION_DATA = "true"

# API Endpoints
SAVED_RESULT_SET_ENDPOINT = "ingestion/rules/save_result_set/"
BULK_IOC_LOOKUP_ENDPOINT = "ingestion/openapi/bulk-lookup/indicator/"

# CTIX API version
CTIX_API_VERSION = "v3"

# Header keys for CTIX authentication
HEADER_ACCESS_ID = "ACCESSID"
HEADER_SIGNATURE = "SIGNATURE"
HEADER_EXPIRES = "EXPIRES"

# Timeouts (in seconds)
CONNECTION_TIMEOUT = 60
READ_TIMEOUT = 300
DEFAULT_SLEEP_TIME = 60
BLOB_DOWNLOAD_TIMEOUT = 30
MAX_EXECUTION_TIME_MINUTES = 55
INGESTION_TIME_CHECK_MINUTES = 50

# Retry configuration
RETRY_COUNT = 3

# Pagination defaults
PAGE_SIZE_FOR_SAVED_RESULT = 1000
PAGE_SIZE_FOR_BULK_IOC = 1000
MAX_BULK_IOC_BATCH_SIZE = 1000
MAX_IOC_LENGTH_FOR_BULK_LOOKUP = 1000

# Signature expiration time (in seconds from current time)
SIGNATURE_EXPIRY_SECONDS = 25

# Chronicle SecOps data type for ingestion
GOOGLE_SECOPS_DATA_TYPE = "CTIX"

# Checkpoint configuration
CHECKPOINT_FILE = "ctix_checkpoint.json"
CHECKPOINT_KEY_FROM_TIMESTAMP = "last_from_timestamp"
CHECKPOINT_KEY_TO_TIMESTAMP = "last_to_timestamp"
CHECKPOINT_KEY_PAGE_NUMBER = "last_page_number"
CHECKPOINT_KEY_CTIX_MODIFIED = "last_ctix_modified"
CHECKPOINT_KEY_PROCESS_LOCK = "process_running"
CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME = "last_run_initiation_time"
CHECKPOINT_KEY_LABEL_LIST = "label_list"
CHECKPOINT_KEY_CURRENT_LABEL = "current_label"

# Message Constants
GENERAL_ERROR_MESSAGE = (
    "Failed to fetch {fetch_type}, received status code - {status_code}."
    " Response - {response_text}."
)
CHECK_LOGS_FOR_MORE_DETAILS = " Check logs for more details."
RETRY_MESSAGE = "Retrying after {delay} seconds."

# Date pattern for timestamps
TIMESTAMP_PATTERN = "%Y-%m-%dT%H:%M:%SZ"

# Enrichment fields to extract from bulk IOC lookup
ENRICHMENT_FIELDS = (
    "name",
    "relations",
    "enrichment_data",
    "custom_attributes",
    "description",
    "first_seen",
    "last_seen",
    "published_collections",
    "sub_type",
    "manual_review",
)

PERMISSION_DETAILS = immutabledict.immutabledict(
    {
        "Storage Admin": "roles/storage.admin",
        "Secret Manager Secret Accessor": "roles/secretmanager.secretAccessor",
        "Cloud Scheduler Job Runner": "roles/cloudscheduler.jobRunner",
        "Chronicle API Editor": "roles/chronicle.editor",
    }
)

LABEL_NAME_SAFE_CHARS = "\"!@$%^*()_+=-[]{}|:;'<>?,./ ~`\\"
