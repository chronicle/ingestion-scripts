# Copyright 2024 Google LLC
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
# pylint: disable=line-too-long
"""Team Cymru Scout Constants."""

PROTOCOL = "https://"
VERIFY_SSL = True
IPS_CHUNKSIZE = 10
SIZE_THRESHOLD_BYTES = 950000


class Endpoints:
  """Team Cymru Scout Endpoints."""

  CYMRU_SERVER_ADDRESS = "scout.cymru.com/api/scout"
  USAGE = "/usage"
  IP_FOUNDATION = "/ip/foundation"
  IP_DETAILS = "/ip/{ip}/details"
  DOMAIN_DETAILS = "/search"


class Rest:
  """Team Cymru Scout Rest Constants."""

  STATUS_FORCELIST = list(range(500, 600)) + [
      429,
  ]
  REQUEST_TIMEOUT = 300
  MAX_RETRIES = 3
  BACKOFF_FACTOR = 60


DOMAIN_REGEX = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}$"
IPV4_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
IPV6_REGEX = (
    r"^(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,7}:|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,5}(:[A-Fa-f0-9]{1,4}){1,2}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,4}(:[A-Fa-f0-9]{1,4}){1,3}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,3}(:[A-Fa-f0-9]{1,4}){1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,2}(:[A-Fa-f0-9]{1,4}){1,5}|"
    r"[A-Fa-f0-9]{1,4}:(:[A-Fa-f0-9]{1,4}){1,6}|"
    r":((:[A-Fa-f0-9]{1,4}){1,7}|:)|"
    r"fe80:(:[A-Fa-f0-9]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
    r"::(ffff(:0{1,4}){0,1}:){0,1}"
    r"((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,4}:"
    r"((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))$"
)
