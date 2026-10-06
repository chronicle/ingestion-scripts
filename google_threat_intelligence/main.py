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
#
"""Main script for Google Threat Intelligence ingestion."""
from common import utils
import constant
import gti_client
import utility


def main(request):  # pylint: disable=unused-argument
  """Driver function for Google Threat Intelligence ingestion."""
  try:
    gti_api_key = utility.get_environment_variable(
        constant.ENV_VAR_GTI_API_TOKEN, is_required=True, is_secret=True
    )
    bucket_name = utility.get_environment_variable(
        constant.ENV_VAR_GCP_BUCKET_NAME, is_required=True
    )

    gti_client_instance = gti_client.GoogleThreatIntelligenceUtility(
        gti_api_key, bucket_name
    )

    methods_map = {
        constant.ENV_VAR_FETCH_IOC_STREAM_ENABLED: (
            gti_client_instance.get_and_ingest_ioc_stream_events
        ),
        constant.ENV_VAR_THREAT_LISTS: (
            gti_client_instance.get_and_ingest_threat_list_events
        ),
    }

    enabled_methods = []
    for method_name, method_func in methods_map.items():
      if (
          method_name == constant.ENV_VAR_THREAT_LISTS
          and utility.get_environment_variable(method_name)
      ) or utility.get_environment_variable(method_name) == "true":
        enabled_methods.append(method_func)

    # Check if there are no methods to run
    if not enabled_methods:
      utils.cloud_logging(
          "No methods enabled. Please set proper environment variables.",
          severity="ERROR",
      )
      return "No methods enabled. Please set proper environment variables.", 400

    utils.cloud_logging(
        "Enabled methods:"
        f" {', '.join([method.__name__ for method in enabled_methods])}",
    )
    # Run enabled methods
    try:
      utility.run_methods_in_parallel(enabled_methods)
      utils.cloud_logging("Methods execution completed.")
      return "data ingestion completed"
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Unknown exception occurred while executing methods parallel. Error"
          f" message: {repr(e)}",
          severity="ERROR",
      )
      return f"Error executing methods: {repr(e)}"
  except Exception as e:  # pylint: disable=broad-except
    utils.cloud_logging(
        "Unknown exception occurred while retrieving the environment"
        f" credentials. Error message: {repr(e)}",
        severity="ERROR",
    )
    return f"Error initializing: {repr(e)}", 500
