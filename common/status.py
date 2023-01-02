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
"""HTTP status constants to be used across the project."""
import http

STATUS_OK = http.HTTPStatus.OK.value  # For status code 200.
STATUS_BAD_REQUEST = http.HTTPStatus.BAD_REQUEST.value  # For status code 400.
STATUS_UNAUTHORIZED = http.HTTPStatus.UNAUTHORIZED.value  # For status code 401.
STATUS_FORBIDDEN = http.HTTPStatus.FORBIDDEN.value  # For status code 403.
STATUS_NOT_FOUND = http.HTTPStatus.NOT_FOUND.value  # For status code 404.
# For status code 429.
STATUS_TOO_MANY_REQUESTS = http.HTTPStatus.TOO_MANY_REQUESTS.value
# For status code 500.
STATUS_INTERNAL_SERVER_ERROR = http.HTTPStatus.INTERNAL_SERVER_ERROR.value
