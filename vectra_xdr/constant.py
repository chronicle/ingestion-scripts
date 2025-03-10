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

"""Ventra XDR Constants."""

# ENVIRONMENT VARIABLES CONSTANTS
ENV_VAR_INCLUDE_SCORE_DECREASES = "INCLUDE_SCORE_DECREASES"
ENV_VAR_VLANS = "VLANS"
ENV_VAR_INCLUDE_INFO_CATEGORY = "INCLUDE_INFO_CATEGORY"
ENV_VAR_INCLUDE_TRIAGED = "INCLUDE_TRIAGED"
ENV_VECTRA_BASE_URL = "VECTRA_PORTAL_URL"
ENV_GCP_BUCKET_NAME = "GCP_BUCKET_NAME"
ENV_HISTORICAL = "HISTORICAL"
ENV_CLIENT_ID_SECRECT_NAME = "CLIENT_ID"
ENV_CLIENT_SECRET_SECRET_NAME = "SECRET_KEY"
ENV_GCP_PROJECT_NUMBER = "GCP_PROJECT_NUMBER"

ENV_VAR_LOCKDOWN = "ENABLE_LOCKDOWN"
ENV_VAR_AUDIT = "ENABLE_AUDIT"
ENV_VAR_HEALTH = "ENABLE_HEALTH"
ENV_VAR_DETECTION = "ENABLE_DETECTION"
ENV_VAR_SCORING = "ENABLE_SCORING"

# API ENDPOINTS
API_VERSION = "api/v3.4"
VECTRA_ACCESS_TOKEN_ENDPOINT = "oauth2/token"
VECTRA_LOCKDOWN_ENDPOINT = API_VERSION + "/lockdown"
VECTRA_AUDIT_ENDPOINT = API_VERSION + "/events/audits"
VECTRA_HEALTH_ENDPOINT = API_VERSION + "/health"
VECTRA_SCORING_ENDPOINT = API_VERSION + "/events/entity_scoring"
VECTRA_DETECTION_ENDPOINT = API_VERSION + "/events/detections"
VECTRA_APP_VERSION = "1.0.0"
VECTRA_APP_USER_AGENT = "vectra-rux-csiem-" + VECTRA_APP_VERSION

HEADERS = {"Accept": "application/json", "User-Agent": VECTRA_APP_USER_AGENT}
ERRORS = {
    "RATE_LIMIT_EXCEEDED": "Rate limit exceeded. Please wait and try again.",
    "REFRESH_TOKEN_EXPIRE_MESSAGE": (
        "Please try reauthenticating using API client credentials"
    ),
}

# OTHERS
RETRY_COUNT = 3
RETRY_COUNT_TOKEN = 1
DEFAULT_REQUEST_TIMEOUT = 60
WAIT_TIME_FOR_RETRY = 30
MAX_EVENT_LIMIT = 100
TIME_STAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # 2024-06-30T01:29:13Z
HOST_TYPE = "host"
ACCOUNT_TYPE = "account"
NEXT_CHECKPOINT = "next_checkpoint"
REMAINING_COUNT = "remaining_count"
CHRONICLE_DATA_TYPE = "VECTRA_XDR"
METHOD_INTERVAL = 60
GCP_BUCKET_FILE_NAME = "checkpoint.json"
VECTRA_API_TOKEN_SECRET_NAME = "vectra_api_token"

# Default Values
DEFAULT_VALUES = {
    ENV_VAR_INCLUDE_SCORE_DECREASES: "false",
    ENV_VAR_VLANS: "false",
    ENV_VAR_INCLUDE_INFO_CATEGORY: "true",
    ENV_VAR_INCLUDE_TRIAGED: "false",
    ENV_VAR_LOCKDOWN: "true",
    ENV_VAR_AUDIT: "true",
    ENV_VAR_HEALTH: "true",
    ENV_VAR_DETECTION: "true",
    ENV_VAR_SCORING: "true",
    ENV_HISTORICAL: "false",
}
