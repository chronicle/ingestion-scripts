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
"""Fetch the logs stored in the Google Cloud Storage Bucket and ingest into Chronicle."""
import datetime
import json
from typing import Any

from google.cloud import exceptions
from google.cloud import storage

from common import ingest
from common import utils

# Date format to be used to parse the date string to the datetime object.
DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f%z"

# Encoding system for Unicode.
UTF_8 = "utf-8"

# Product name.
PRODUCT_NAME = "google cloud platform"

# Environment variable constants.
ENV_GCP_SERVICE_ACCOUNT_SECRET_PATH = "GCP_SERVICE_ACCOUNT_SECRET_PATH"
ENV_CHRONICLE_DATA_TYPE = "CHRONICLE_DATA_TYPE"
ENV_GCS_BUCKET_NAME = "GCS_BUCKET_NAME"


def get_and_ingest_logs(storage_client: storage.Client, bucket_names: list[Any],
                        start_time: datetime.datetime,
                        chronicle_data_type: str) -> None:
  """Get logs from the GCP Storage Bucket and ingest them into Chronicle.

  Args:
    storage_client (storage): GCS Storage Client object to be used.
    bucket_names (list): List of bucket names to read the logs from.
    start_time (datetime): Time from which to start fetching the logs.
    chronicle_data_type (str): Log type to push data into the Chronicle
      platform.

  Raises:
    Exception: Raised error for unexpected behavior.
  """
  print(
      "Retrieving blobs which are created after"
      f" {start_time.strftime(DATE_FORMAT)}."
  )

  no_of_logs = 0

  # Iterate over the GCS buckets to fetch the logs.
  for bucket_name in bucket_names:
    try:
      print(
          "Creating a storage bucket object with the provided bucket name:"
          f" {bucket_name}."
      )
      bucket_object = storage_client.get_bucket(bucket_name)
    except exceptions.NotFound as error:
      raise RuntimeError(
          f"The specified bucket '{bucket_name}' does not exist.") from error
    except Exception as error:
      raise RuntimeError(
          f"Error occurred while creating the object for '{bucket_name}'"
      ) from error

    # Filter the blobs which are created after start_time.
    for blob in bucket_object.list_blobs():
      blob_created_time = blob.time_created

      # If the blob is created after the start_time_obj, then only we'll fetch
      # the data from it.
      if blob_created_time >= start_time:
        try:
          blob_data = json.loads(blob.download_as_text(encoding=UTF_8))

        # If the blob is not in JSON string, then we split the content
        # before parsing it.
        except json.JSONDecodeError:
          try:
            blob_str_data = blob.download_as_text(
                encoding=UTF_8).split("\n")[:-1]
            blob_data = [json.loads(data) for data in blob_str_data]
          except json.JSONDecodeError as error:
            print(f"Could not load the log data from blob {blob.name}.")
            raise RuntimeError(
                f"The log data from {blob.name} is not JSON serializable."
            ) from error

        # Ingest blob data into Chronicle.
        try:
          ingest.ingest(blob_data, chronicle_data_type)
        except Exception as error:
          raise Exception(
              "Unable to push the data to the Chronicle.") from error

        no_of_logs += len(blob_data)

  if not no_of_logs:
    print("No newer logs found for the given bucket.")
  else:
    print(f"Total {no_of_logs} log(s) are successfully ingested to Chronicle.")


# Requests is a user input dictionary passed while running the cloud function.
# The script does not use these params.
def main(request) -> str:  # pylint: disable=unused-argument
  """Entrypoint.

  Args:
      request: Request to execute the cloud function.

  Returns:
      string: "Ingestion completed".
  """
  # Fetching the environment variables.
  gcp_service_account = utils.get_env_var(
      ENV_GCP_SERVICE_ACCOUNT_SECRET_PATH, is_secret=True)
  chronicle_data_type = utils.get_env_var(ENV_CHRONICLE_DATA_TYPE)

  gcs_bucket_name = utils.get_env_var(ENV_GCS_BUCKET_NAME)
  bucket_names = [
      bucket.lower().strip() for bucket in gcs_bucket_name.strip().split(",")
  ]

  start_time = utils.get_last_run_at()

  # Load GCP service account JSON.
  gcp_service_account_dict = utils.load_service_account(
      gcp_service_account, PRODUCT_NAME)

  # Creating storage client based on provided GCP service account JSON.
  try:
    print("Creating a storage client from GCP service account.")
    storage_client = storage.Client.from_service_account_info(
        gcp_service_account_dict)
  except ValueError as error:
    raise RuntimeError(
        "Invalid Google Cloud Service Account provided.") from error
  except Exception as error:
    raise RuntimeError(
        "Error occurred while creating the GCS Client.") from error

  # Fetch and ingest the logs into the Chronicle.
  get_and_ingest_logs(storage_client, bucket_names, start_time,
                      chronicle_data_type)

  return "Ingestion completed."
