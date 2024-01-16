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
"""DomainTools Environment variable constants."""

ENV_DOMAINTOOLS_API_USERNAME = "DOMAINTOOLS_API_USERNAME"
ENV_DOMAINTOOLS_API_KEY = "DOMAINTOOLS_API_KEY"
ENV_DNSDB_API_KEY = "DNSDB_API_KEY"
ENV_LOG_TYPE_FILE_PATH = "LOG_TYPE_FILE_PATH"
ENV_PROVISIONAL_TTL = "PROVISIONAL_TTL"
ENV_NON_PROVISIONAL_TTL = "NON_PROVISIONAL_TTL"
ENV_ALLOW_LIST = "ALLOW_LIST"
ENV_MONITORING_LIST = "MONITORING_LIST"
ENV_MONITORING_TAGS = "MONITORING_TAGS"
ENV_BULK_ENRICHMENT = "BULK_ENRICHMENT"
ENV_FETCH_SUBDOMAINS_FOR_MAX_DOMAINS = "FETCH_SUBDOMAINS_FOR_MAX_DOMAINS"
CHRONICLE_DATA_TYPE = "DOMAINTOOLS_THREATINTEL"
DNSDB_URL = "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{}/NS?limit=50&time_last_after=-21600"
ERROR_MSG = "Unable to fetch reference list. Error: {}"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
