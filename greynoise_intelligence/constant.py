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

"""GreyNoise Constants."""

# ENVIRONMENT VARIABLES CONSTANTS
ENV_VAR_GREYNOISE_API_KEY = "GREYNOISE_API_KEY"
ENV_VAR_QUERY = "QUERY"
ENV_VAR_LIVE_INVESTIGATION_DATA_TABLE = "LIVE_INVESTIGATION_DATA_TABLE"
ENV_VAR_GCP_BUCKET_NAME = "GCP_BUCKET_NAME"

# Default Values
DEFAULT_VALUES = {}

GOOGLE_SECOPS_DATA_TYPE = "GREYNOISE"

# API Constants
GREYNOISE_APP_VERSION = "1.0.0"
GREYNOISE_INTEGRATION_NAME = "google-secops-siem-v" + GREYNOISE_APP_VERSION
GNQL_PAGE_SIZE = 10000
DEFAULT_TIME_QUERY = "last_seen:1d"
CHECKPOINT_FILE_NAME = GOOGLE_SECOPS_DATA_TYPE.lower() + "_state.json"

PERMISSION_DETAILS = {
    "Storage Admin": "roles/storage.admin",
    "Secret Manager Secret Accessor": "roles/secretmanager.secretAccessor",
    "Cloud Scheduler Job Runner": "roles/cloudscheduler.jobRunner",
    "Chronicle API Editor": "roles/chronicle.editor",
    "Viewer": "roles/viewer",
    "Cloud Run Invoker": "roles/run.invoker",
}


IP_BATCH_SIZE = 10000  # Number of IPs to process in a single batch
SCHEDULER_HEADER_KEY = "X-CloudScheduler"
# Live Investigation
QUERY_FIELD_NAME = "query"
DATATABLE_FIELD_NAME = "datatable_name"
LIVE_INVESTIGATION_FIELD_NAME = "is_live_investigation"
END_TIME_FIELD_NAME = "custom_end_time"
