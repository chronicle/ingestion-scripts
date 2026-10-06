# Copyright 2026 Google LLC
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

"""Cyjax Constants for Google SecOps SIEM Integration."""

import immutabledict

# API Configuration
BASE_URI = "https://api.cymon.co/v2"
TIMEOUT = 15
VERSION = "1.0.0"
USER_AGENT = f"cyjax-secops-siem-v{VERSION}"

# HTTP Headers
HEADER_AUTHORIZATION = "Authorization"
HEADER_USER_AGENT = "User-Agent"

# API Endpoints
ENDPOINT_INDICATOR_OF_COMPROMISE = "indicator-of-compromise"
ENDPOINT_INDICATOR_ENRICHMENT = "indicator-of-compromise/enrichment"

# Environment Variable Names
ENV_CYJAX_API_TOKEN = "CYJAX_API_TOKEN"
ENV_HISTORICAL_IOC_DURATION = "HISTORICAL_IOC_DURATION"
ENV_QUERY = "QUERY"
ENV_ENABLE_ENRICHMENT = "ENABLE_ENRICHMENT"
ENV_INDICATOR_TYPES = "INDICATOR_TYPES"
ENV_GCP_BUCKET_NAME = "GCP_BUCKET_NAME"

# Default Values
DEFAULT_VALUES = immutabledict.immutabledict({
    ENV_HISTORICAL_IOC_DURATION: "1",
    ENV_ENABLE_ENRICHMENT: "false",
})

# Historical IOC Duration Limits (in days)
MAX_HISTORICAL_IOC_DURATION = 7

# Timeouts (in seconds)
CONNECTION_TIMEOUT = 60
READ_TIMEOUT = 300
BLOB_DOWNLOAD_TIMEOUT = 30
BLOB_UPLOAD_TIMEOUT = 30

# Execution Time Limits (in minutes)
MAX_EXECUTION_TIME_MINUTES = 55
INGESTION_TIME_CHECK_MINUTES = 50

# Pagination
PAGE_SIZE = 100

# Retry Configuration
RETRY_COUNT = 3
RETRY_DELAY = 60
RETRY_INITIAL_DELAY = 1.0
RETRY_MAXIMUM_DELAY = 30.0
RETRY_MULTIPLIER = 1.5
RETRY_DEADLINE = 120.0

# Google SecOps
GOOGLE_SECOPS_DATA_TYPE = "CYJAX_THREAT_INTELLIGENCE"

# Custom Fields
END_TIME_FIELD_NAME = "custom_end_time"

# Checkpoint Configuration
CHECKPOINT_FILE = "cyjax_checkpoint.json"
CHECKPOINT_KEY_SINCE = "since"
CHECKPOINT_KEY_UNTIL = "until"
CHECKPOINT_KEY_PAGE_NUMBER = "page_number"
CHECKPOINT_KEY_QUERY = "query"
CHECKPOINT_KEY_INDICATOR_TYPES = "indicator_types"
CHECKPOINT_KEY_PROCESS_LOCK = "process_running"
CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME = "last_run_initiation_time"

# Log Message Templates
API_RESPONSE_LOG_MESSAGE = (
    "API call to '{endpoint}' returned status code {status_code}."
    " Response - {response_message}."
)

# IAM Permission Details
PERMISSION_DETAILS = immutabledict.immutabledict({
    "Storage Admin": "roles/storage.admin",
    "Secret Manager Secret Accessor": "roles/secretmanager.secretAccessor",
    "Cloud Scheduler Job Runner": "roles/cloudscheduler.jobRunner",
    "Chronicle API Editor": "roles/chronicle.editor",
})
