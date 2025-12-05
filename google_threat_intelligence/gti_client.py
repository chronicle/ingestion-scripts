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

# pylint: disable=invalid-name

"""Google Threat Intelligence Client for API calls."""

import concurrent.futures
from datetime import datetime, timedelta, timezone  # pylint: disable=g-importing-member, g-multiple-import
import json
import threading
import time

from google.cloud import exceptions
from google.cloud import resourcemanager_v3, storage  # pylint: disable=g-importing-member, g-multiple-import
import requests

from common import env_constants
from common import ingest_v1
from common import utils
import constant
import utility
from exception_handler import GCPPermissionDeniedError, exception_handler

CHECKPOINT_LOCKS = {
    "checkpoint_shard_1.json": threading.Lock(),
    "checkpoint_shard_2.json": threading.Lock(),
    "checkpoint_shard_3.json": threading.Lock(),
    "checkpoint_ioc_stream.json": threading.Lock(),
}


class GoogleThreatIntelligenceUtility:
  """Google Threat Intelligence Utility handle all api operations."""

  def __init__(self, api_token, bucket_name) -> None:
    """Initialize Google Threat Intelligence Object with required credentials.

    Args:
        api_token (str): API Token for Google Threat Intelligence
        bucket_name (str): Name of the Google Cloud Storage Bucket
    """
    self.base_url = constant.BASE_URL
    self.api_version = constant.API_VERSION
    self.bucket_name = bucket_name
    self.api_token = api_token
    self.headers = self.get_gti_headers_with_token()
    self.check_sufficient_permissions_on_service_account()
    utils.cloud_logging("Google Threat Intelligence Client Initialized.")

  @exception_handler(action_name="Google Threat Intelligence Rest API")
  def gti_rest_api(self, *args, **kwargs):  # pylint: disable=unused-argument
    """Make API call to Google Threat Intelligence.

    Args:
        *args: Variable length argument list (unused).
        **kwargs: Arbitrary keyword arguments.

    Returns
    -------
    Dict
        Dict containing response if call is successful.
    """
    timeout = kwargs.get(
        "timeout", (constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT)
    )
    return_dict = {"response": None, "status": False, "retry": False}
    response = requests.request(
        method=kwargs.get("call_type", "GET"),
        url=kwargs.get("url"),
        headers=kwargs.get("headers", {}),
        params=kwargs.get("params", {}),
        data=kwargs.get("data", {}),
        json=kwargs.get("json", None),
        timeout=timeout,
        verify=True,
    )
    return_dict["response"] = response
    return_dict["status"] = True
    return return_dict

  def fetch_gti_data(
      self,
      url,
      timeout,
      should_retry,
      fetch_type,
      params=None,
  ):
    """Fetch Google Threat Intelligence data given a URL and params.

    Args:
        url (str): url to fetch data
        timeout (tuple): timeout for the request
        should_retry (bool): whether to retry the request or not
        fetch_type (str): type of the data being fetched
        params (dict, optional): parameters to pass with the request

    Returns:
        dict: api call response
    """
    retry_count = self.get_retry_count(should_retry)
    count = 0
    return_dict = {
        "status": False,
        "data": {},
        "error": "",
        "response": "",
        "retry": False,
    }
    result = {}
    while count < retry_count:
      result = self.gti_rest_api(
          call_type="GET",
          url=url,
          headers=self.headers,
          params=params,
          timeout=timeout,
      )
      # If the result indicates a retry or failure, decide whether to retry
      if result.get("retry") or not result.get("status"):
        # Check response code or exception for retry logic
        if should_retry and result.get("retry"):
          # Log the retry attempt
          count += 1
          if count == retry_count:
            # If max retries reached, break the loop
            return_dict.update(result)
            return return_dict
          self.log_and_sleep_before_retry()
          continue
        else:
          # If it's not a retry case or if max retries reached, break the loop
          return result
      result = self.parse_and_handle_response(return_dict, result, fetch_type)
      continue_loop, updated_return_dict, count = self.handle_retry(
          result, return_dict, should_retry, retry_count, count
      )
      if not continue_loop:
        return updated_return_dict
      self.log_and_sleep_before_retry()
    return_dict.update(result)
    return return_dict

  def parse_and_handle_response(self, return_dict, result, fetch_type):
    """Parse and handle the API response.

    Args:
        return_dict (dict): dict containing the return values
        result (dict): api response
        fetch_type (str): to identify which api call response is passed

    Returns:
        dict: api call response
    """
    try:
      response = result["response"]
      return_dict["response"] = response
      if response.status_code == 200:
        data = json.loads(response.text)
        return_dict["data"] = data
        return_dict["status"] = result["status"]
      elif response.status_code == 401:
        return_dict["status"] = False
        return_dict["error"] = "Invalid API Token."
        utils.cloud_logging(
            constant.GENERAL_ERROR_MESSAGE.format(
                status_code=response.status_code,
                response_text=response.text,
                fetch_type=fetch_type,
            ),
            severity="ERROR",
        )
      elif response.status_code == 403:
        return_dict["status"] = False
        return_dict["error"] = (
            "API Token does not have permission to access {0}.".format(
                fetch_type
            )
        )
        utils.cloud_logging(
            constant.GENERAL_ERROR_MESSAGE.format(
                status_code=response.status_code,
                response_text=response.text,
                fetch_type=fetch_type,
            ),
            severity="ERROR",
        )
      elif response.status_code == 429 or response.status_code >= 500:
        return_dict["status"] = False
        return_dict["retry"] = True
        return_dict["error"] = (
            "API rate limit exceeded or internal server error occurred while"
            " fetching {0}.".format(fetch_type)
        )
        utils.cloud_logging(
            constant.GENERAL_ERROR_MESSAGE.format(
                status_code=response.status_code,
                response_text=response.text,
                fetch_type=fetch_type,
            ),
            severity="ERROR",
        )
      else:
        return_dict["status"] = False
        return_dict["error"] = (
            "Failed to fetch {0}, received status code - {1}. Response - {2}."
            .format(fetch_type, response.status_code, response.text)
        )
        utils.cloud_logging(
            constant.GENERAL_ERROR_MESSAGE.format(
                status_code=response.status_code,
                response_text=response.text,
                fetch_type=fetch_type,
            ),
            severity="ERROR",
        )
    except ValueError as ex:
      utils.cloud_logging(
          constant.ERR_MSG_FAILED_TO_PARSE_RESPONSE.format(
              result["response"].text, ex
          )
      )
    except Exception as ex:  # pylint: disable=broad-except
      response = result.get("response")
      utils.cloud_logging(
          "Error while handling response from Google Threat Intelligence."
          " Response = {0}. Error = {1}".format(
              response.text if response else "N/A", ex
          ),
          severity="ERROR",
      )
    return return_dict

  def get_gti_headers_with_token(self):
    """Get Google Threat Intelligence api request headers.

    Returns:
        dict: headers
    """
    return {
        "accept": constant.CONTENT_TYPE_JSON,
        "x-apikey": self.api_token,
        "x-tool": constant.X_TOOL,
        "User-Agent": constant.GTI_APP_VERSION,
    }

  def fetch_threat_data(
      self,
      threat_type=None,
      params=None,
      start_time=None,
      timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
      should_retry=False,
  ):
    """Validate the API token and base URL by making an API call.

    Args:
        threat_type (string): threat type name
        params (dict): dict containing parameters to pass
        start_time (str): The start time from which to fetch threat list events
          in ISO 8601 format.
        timeout (tuple): timeout for the request.
        should_retry (bool): whether to retry the request or not.

    Returns:
        dict: api call response
    """
    url = constant.THREAT_LIST_URL.format(
        threat_type=threat_type, start_time=start_time
    )
    return self.fetch_gti_data(
        url=url,
        timeout=timeout,
        should_retry=should_retry,
        fetch_type=threat_type,
        params=params,
    )

  def fetch_ioc_stream(
      self,
      params,
      timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
      should_retry=False,
  ):
    """Fetch Google Threat Intelligence IOC Stream data.

    Args:
        params (dict): Parameters to pass to the API call.
        timeout (tuple): Timeout for the request.
        should_retry (bool): Whether to retry the request or not.

    Raises:
        Exception: If an error occurs during the API call, it logs the error
        message.

    Returns:
        dict: API call response.
    """
    url = constant.IOC_STREAM_URL
    return self.fetch_gti_data(
        url=url,
        timeout=timeout,
        should_retry=should_retry,
        fetch_type="IOC Stream",
        params=params,
    )

  def handle_retry(self, result, return_dict, should_retry, retry_count, count):
    """Handle the logic for retrying the API call.

    Args:
        result (dict): The result of the API call.
        return_dict (dict): The dictionary to update and return if conditions
          are met.
        should_retry (bool): Flag indicating if retries are allowed.
        retry_count (int): The maximum number of retries allowed.
        count (int): The current retry attempt.

    Returns:
        tuple:
            A tuple containing a boolean indicating if the loop should continue,
            the updated return_dict and count.
    """
    # If successful, return immediately
    if result["status"]:
      return False, result, count
    # Check response code for retry logic
    if not should_retry or not result.get("retry", False):
      # Break the loop if it's not a retry case or
      # if other types of errors occurred
      return False, result, count
    count += 1
    if count == retry_count:
      # If max retries reached, update return_dict and break the loop
      return_dict.update(result)
      return False, return_dict, count
    return True, return_dict, count

  def get_retry_count(self, should_retry=False):
    """Return the retry count based on the should_retry flag.

    Args:
        should_retry (bool): Flag indicating if retries are allowed.

    Returns:
        int: The number of retries to attempt.
    """
    return constant.RETRY_COUNT if should_retry else 1

  def log_and_sleep_before_retry(self, sleep_time=constant.DEFAULT_SLEEP_TIME):
    """Log a retry message and sleeps for the retry time.

    This should be called if an API call fails and we want to retry the call.

    Args:
        sleep_time (int): The time in seconds to sleep before retrying.
    """
    utils.cloud_logging(constant.RETRY_MESSAGE.format(sleep_time))
    time.sleep(sleep_time)

  def _ingest_events(self, events):
    """Ingests events into Google SecOps.

    Args:
        events (list): A list of events to be ingested into Google SecOps.

    Raises:
        Exception: If an error occurs during the ingestion process, it logs the
        error message.
    """
    try:
      if events:
        utils.cloud_logging("Ingesting events into Google SecOps.")
        ingest_v1.ingest(events, constant.GOOGLE_SECOPS_DATA_TYPE)
      else:
        utils.cloud_logging(
            "No events to push data to ingest into Google SecOps."
        )
    except Exception as e:
      utils.cloud_logging(
          f"Error occurred while ingesting data: {repr(e)}", severity="ERROR"
      )
      raise

  def _get_checkpoint_file(self, checkpoint_key):
    """Get the appropriate checkpoint file for a given key."""
    shard_file = constant.CHECKPOINT_KEY_TO_SHARD[checkpoint_key]
    utils.cloud_logging(
        f"Checkpoint key '{checkpoint_key}' mapped to shard file"
        f" '{shard_file}'",
        severity="DEBUG",
    )
    return shard_file

  def _get_last_checkpoint(self, checkpoint_key):
    """Retrieve the last checkpoint from bucket for the given checkpoint_key.

    Args:
        checkpoint_key (str): The API checkpoint_key to retrieve the last
          checkpoint.

    Returns:
        str: The last checkpoint for the given checkpoint_key, or None if no
        checkpoint exists.
    """
    checkpoint_file = self._get_checkpoint_file(checkpoint_key)
    try:
      # Get the appropriate checkpoint file for this key

      storage_client = storage.Client()
      bucket = storage_client.get_bucket(self.bucket_name)
      blob = bucket.blob(checkpoint_file)
      if blob.exists():
        data = json.loads(
            blob.download_as_text(timeout=30)
        )  # Add explicit timeout
        value = data.get(checkpoint_key, None)
        utils.cloud_logging(
            f"Retrieved checkpoint for key '{checkpoint_key}' from file"
            f" '{checkpoint_file}' Checkpoint Data Retrieved :"
            f" {json.dumps(data)}",
            severity="DEBUG",
        )
        return value

      else:
        utils.cloud_logging(
            f"Checkpoint file '{checkpoint_file}' in '{self.bucket_name}' does"
            " not exist. ",
            severity="DEBUG",
        )
        return None

    except json.JSONDecodeError:
      utils.cloud_logging(
          f"Failed to decode JSON content from {checkpoint_file}",
          severity="WARNING",
      )
      return None
    except exceptions.NotFound as error:
      raise RuntimeError(
          f"The specified bucket '{self.bucket_name}' does not exist."
      ) from error
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Unknown exception occurred while getting last checkpoint. Error"
          f" message: {e}",
          severity="ERROR",
      )
      return None

  def _set_last_checkpoint(self, checkpoint_key, last_checkpoint):
    """Store the the last checkpoint for the given checkpoint_key in bucket.

    Args:
        checkpoint_key (str): The API checkpoint_key to set the last checkpoint.
        last_checkpoint (str): The last checkpoint to set.

    Raises:
        GCPPermissionDeniedError: If there are permission issues with the GCS
        bucket.
        RuntimeError: If the specified bucket doesn't exist.
        Exception: For other unexpected errors during the process.
    """
    # Get the appropriate checkpoint file and lock
    try:
      checkpoint_file = self._get_checkpoint_file(checkpoint_key)
      lock = CHECKPOINT_LOCKS[checkpoint_file]
      if not lock.acquire(timeout=30):  # Wait up to 30 seconds for lock
        utils.cloud_logging(
            f"Could not acquire lock for '{checkpoint_file}' after 30s,"
            " skipping checkpoint update",
            severity="WARNING",
        )
        return None

      try:
        custom_retry = storage.retry.DEFAULT_RETRY.with_delay(
            initial=1.0, maximum=30.0, multiplier=1.5
        ).with_deadline(120.0)
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(self.bucket_name)
        blob = bucket.blob(checkpoint_file)
        bucket_data = {}
        if blob.exists():
          try:
            bucket_data = json.loads(
                blob.download_as_text(timeout=30)
            )  # Add explicit timeout
            utils.cloud_logging(
                f"Read existing checkpoint data from '{checkpoint_file}'",
                severity="DEBUG",
            )
          except json.JSONDecodeError:
            utils.cloud_logging(
                f"Failed to decode JSON content from '{checkpoint_file}'",
                severity="WARNING",
            )
        else:
          utils.cloud_logging(
              f"Checkpoint file '{checkpoint_file}' does not exist, creating"
              " new file",
              severity="DEBUG",
          )

        bucket_data[checkpoint_key] = last_checkpoint
        blob.upload_from_string(
            json.dumps(bucket_data),
            content_type="application/json",
            retry=custom_retry,
            timeout=30,
        )
        utils.cloud_logging(
            f"Updated Checkpoint File: '{checkpoint_file}', Key:"
            f" '{checkpoint_key}' with the value: {last_checkpoint} Updated"
            f" Checkpoint Data : {json.dumps(bucket_data)}",
            severity="DEBUG",
        )

        return None

      except exceptions.Forbidden as e:
        error_msg = (
            "Permission denied while accessing GCS bucket"
            f" '{self.bucket_name}'. "
        )
        utils.cloud_logging(
            f"{error_msg}. Error: {repr(e)}",
            severity="ERROR",
        )
        raise GCPPermissionDeniedError(
            message=error_msg,
            resource=f"gs://{self.bucket_name}/{checkpoint_file}",
            permissions=["Storage Admin"],
        ) from e
      except exceptions.NotFound as e:
        error_msg = f"The specified bucket '{self.bucket_name}' does not exist."
        utils.cloud_logging(error_msg, severity="ERROR")
        raise RuntimeError(error_msg) from e
      except Exception as e:  # pylint: disable=broad-except
        utils.cloud_logging(
            f"Error updating checkpoint '{checkpoint_key}' in"
            f" '{checkpoint_file}': {repr(e)}\n",
            severity="ERROR",
        )
        raise

      finally:
        lock.release()
    except GCPPermissionDeniedError as e:
      raise RuntimeError(repr(e)) from e

    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Unexpected error while setting last checkpoint for"
          f" {checkpoint_key}: {repr(e)}",
          severity="ERROR",
      )
      return None

  def _process_attack_techniques_for_threat_list(self, threat_list_data):
    """Fetch and process ATT&CK techniques for Threat List data.

    Args:
        threat_list_data (list): The list of IOC items from the threat list.
    """
    try:
      if (
          utility.get_environment_variable(
              constant.ENV_VAR_MITRE_ATTACK_ENABLED
          )
          == "true"
      ):
        for item in threat_list_data:
          if item.get("data", {}).get("type") == "file":
            attack_techniques_data = (
                self.fetch_and_process_attack_techniques_data(
                    item.get("data", {}).get("id"), True
                )
            )
            if attack_techniques_data:
              # Append attack techniques to the file IOC data at parent level
              item["data"].update(attack_techniques_data)
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Error occurred while processing attack techniques for threat list"
          f" data: {repr(e)}",
          severity="ERROR",
      )

  def ingest_events_for_threat_type(
      self, threat_type, threat_list_query, threat_list_start_time
  ):
    """Fetch and ingest events for threat type from Google Threat Intelligence.

    Args:
        threat_type (str): The type of threat to fetch events for.
        threat_list_query (str): The query to filter the threat list by.
        threat_list_start_time (str): The start time from which to fetch threat
          list events in ISO 8601 format.

    Raises:
        Exception: If an error occurs during the process of fetching and
        ingesting threat list events,
            it logs the error message.
    """
    try:
      if threat_type not in constant.ALL_THREAT_LISTS:
        utils.cloud_logging(
            f"Invalid threat list: {threat_type}. Valid threat lists are:"
            f" {constant.ALL_THREAT_LISTS}"
        )
        return
      params = {"limit": constant.THREAT_FEED_LIMIT}
      if threat_list_query:
        params["query"] = threat_list_query
      fetch_data_from = threat_list_start_time
      last_checkpoint = self._get_last_checkpoint(threat_type)
      if last_checkpoint:
        fetch_data_from = last_checkpoint
      while True:
        if utility.check_time_current_hr(fetch_data_from):
          utils.cloud_logging(
              "Reached the end of data, data will be collected in upcoming"
              f" iteration for {threat_type}."
          )
          return

        response = self.fetch_threat_data(
            threat_type,
            params,
            fetch_data_from,
            timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
            should_retry=True,
        )
        if not response.get("status"):
          utils.cloud_logging(
              f"Error occurred while fetching {threat_type} data. Error:"
              f" {response.get('error')}"
          )
          return

        threat_list_data = response.get("data", {}).get("iocs", [])

        utils.cloud_logging(
            f"Fetched {len(threat_list_data)} {threat_type} for hour:"
            f" {fetch_data_from} from Google Threat Intelligence."
        )
        self._process_attack_techniques_for_threat_list(threat_list_data)
        self._ingest_events(threat_list_data)
        utils.cloud_logging(
            f"Successfully ingested {len(threat_list_data)} {threat_type} into"
            " Google SecOps."
        )

        fetch_data_from = utility.add_one_hour_to_formatted_time(
            fetch_data_from
        )
        self._set_last_checkpoint(threat_type, fetch_data_from)

    except (RuntimeError, GCPPermissionDeniedError):
      raise
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Error occurred while fetching and ingesting {threat_type} data."
          f" Error: {repr(e)}",
          severity="ERROR",
      )

  def get_and_ingest_threat_list_events(self):
    """Fetch and ingest events for a given list of threat types from GTI.

    This function fetches events for a given list of threat types from Google
    Threat Intelligence
    by calling `ingest_events_for_threat_type` for each of the types in the
    list. The function
    uses a ThreadPoolExecutor to execute the calls concurrently.

    Environment variables used:
        THREAT_LISTS (required): A comma-separated list of threat types to
        ingest events for.
        THREAT_LIST_QUERY: An optional query to filter the threat list by.
        THREAT_LISTS_START_TIME (required): The start time from which to fetch
        threat list events.

    Raises:
        Exception: If an error occurs during the process of fetching and
        ingesting threat list events,
            it logs the error message.
    """
    try:
      threat_lists = utility.get_environment_variable(
          constant.ENV_VAR_THREAT_LISTS
      )
      threat_types = [
          threat_type.strip() for threat_type in threat_lists.split("|")
      ]
      if "all" in threat_types:
        threat_types = constant.ALL_THREAT_LISTS
      threat_list_query = utility.get_environment_variable(
          constant.ENV_VAR_THREAT_LIST_QUERY
      )
      threat_list_start_time = utility.get_threat_lists_start_time()

      with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for threat_type in threat_types:
          futures.append(
              executor.submit(
                  self.ingest_events_for_threat_type,
                  threat_type,
                  threat_list_query,
                  threat_list_start_time,
              )
          )

        for future in concurrent.futures.as_completed(futures):
          try:
            future.result()
          except Exception as e:  # pylint: disable=broad-except
            utils.cloud_logging(
                "Exception occurred while executing threat lists events"
                f" ingestion: {repr(e)}",
                severity="ERROR",
            )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Execution of threat list events ingestion stops due to exception"
          f" occurred call. Error message: {repr(e)}",
          severity="ERROR",
      )

  def get_and_ingest_ioc_stream_events(self):
    """Fetch IoC stream data from GTI and ingests into Google SecOps.

    Raises:
        Exception: If an error occurs during the process, it logs the error
        message.

    Returns:
        dict: Status and ingestion result.
    """
    params, status = self.get_ioc_stream_params()
    if not status:
      utils.cloud_logging(
          "Invalid parameters for Stream IOC data.", severity="ERROR"
      )
      return
    ioc_stream_fetching_started_at = utility.convert_epoch_to_utc_string(
        int(time.time())
    )
    while True:
      try:
        response = self.fetch_ioc_stream(
            params=params,
            timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
            should_retry=True,
        )
      except Exception as api_exc:  # pylint: disable=broad-except
        utils.cloud_logging(
            f"Exception during IOC Stream API call: {repr(api_exc)}",
            severity="ERROR",
        )
        return
      if not response.get("status"):
        error_msg = response.get(
            "error", "Unknown error while fetching IOC Stream data."
        )
        utils.cloud_logging(
            f"Error while fetching IOC Stream data: {error_msg}",
            severity="ERROR",
        )
        return

      data = response.get("data", {}).get("data", [])
      utils.cloud_logging(
          f"Total {len(data)} IOC Stream data fetched from Google Threat"
          " Intelligence."
      )
      self._process_attack_techniques_for_ioc_stream(data)
      try:
        self._ingest_events(data)
        utils.cloud_logging(
            f"Total {len(data)} IOC Stream data ingested into Google SecOps."
        )
      except (RuntimeError, GCPPermissionDeniedError):
        raise
      except Exception as ingest_exc:  # pylint: disable=broad-except
        utils.cloud_logging(
            f"Error during ingestion: {repr(ingest_exc)}", severity="ERROR"
        )
        return

      params["cursor"] = (
          response.get("data", {}).get("meta", {}).get("cursor", "")
      )
      # write cursor checkpoint
      try:
        self._set_last_checkpoint(
            constant.IOC_STREAM_CURSOR_CHECKPOINT_KEY, params["cursor"]
        )
      except (RuntimeError, GCPPermissionDeniedError):
        raise
      except Exception as checkpoint_exc:  # pylint: disable=broad-except
        utils.cloud_logging(
            f"Error writing cursor checkpoint: {repr(checkpoint_exc)}",
            severity="ERROR",
        )
        # Continue, but log the error

      if not params["cursor"]:
        try:
          self._set_last_checkpoint(
              constant.IOC_STREAM_TIME_CHECKPOINT_KEY,
              ioc_stream_fetching_started_at,
          )
        except (RuntimeError, GCPPermissionDeniedError):
          raise
        except Exception as time_checkpoint_exc:  # pylint: disable=broad-except
          utils.cloud_logging(
              f"Error writing time checkpoint: {repr(time_checkpoint_exc)}",
              severity="ERROR",
          )
        break
    utils.cloud_logging("IOC Stream data fetched and ingested successfully.")

  def get_ioc_stream_params(self):
    """Get parameters for IOC stream API call.

    Returns:
        tuple: A tuple containing:
            - dict: Parameters for IOC stream API call.
            - bool: True if parameters were successfully generated,
              False otherwise.
    """
    params = {"limit": constant.IOC_STREAM_PER_PAGE, "order": "date+"}
    try:
      checkpoint_cursor = self._get_last_checkpoint(
          constant.IOC_STREAM_CURSOR_CHECKPOINT_KEY
      )
      if checkpoint_cursor:
        params["cursor"] = checkpoint_cursor
      filter_str = utility.get_environment_variable(
          constant.ENV_VAR_IOC_STREAM_FILTER
      )
      checkpoint_time = self._get_last_checkpoint(
          constant.IOC_STREAM_TIME_CHECKPOINT_KEY
      )
      if checkpoint_time:
        params["filter"] = filter_str + " date:" + checkpoint_time + "+"
      else:
        days = utility.get_environment_variable(
            constant.ENV_VAR_HISTORICAL_IOC_STREAM_DURATION
        )
        if days is None or days == "":  # pylint: disable=g-explicit-bool-comparison
          days = constant.DEFAULT_VALUES[
              constant.ENV_VAR_HISTORICAL_IOC_STREAM_DURATION
          ]
        days = int(days)
        # Check if days is more than 30
        if days > constant.MAX_DAYS_TO_FETCH_IOC_STREAM:
          utils.cloud_logging(
              f"HISTORICAL_IOC_STREAM_DURATION value '{days}' is more than"
              f" '{constant.MAX_DAYS_TO_FETCH_IOC_STREAM}'.",
              severity="ERROR",
          )
          return params, False
        date_n_days_ago = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).strftime(constant.IOC_STREAM_DATE_PATTERN)
        params["filter"] = filter_str + " date:" + date_n_days_ago + "+"
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Error occurred while fetching and ingesting Stream IOC data."
          f" Error: {repr(e)}",
          severity="ERROR",
      )
      return params, False
    return params, True

  def get_attack_techniques(self, file_hash, should_retry=False):
    """Fetch attack techniques for a given file hash.

    Args:
        file_hash (str): The hash of the file to fetch attack techniques for.
        should_retry (bool): Whether to retry API calls if they fail.

    Raises:
        Exception: If an error occurs during the API call, it logs the error
        message.

    Returns:
        dict: A dictionary containing the response from Google Threat
        Intelligence.
    """
    url = constant.MITRE_URL.format(file_id=file_hash)
    return self.fetch_gti_data(
        url=url,
        timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
        should_retry=should_retry,
        fetch_type="Attack Techniques",
    )

  def _process_attack_techniques_for_ioc_stream(self, data):
    """Fetch and process ATT&CK techniques for IOC Stream data.

    Args:
        data (list): The list of IOC items from the stream.
    """
    try:
      if (
          utility.get_environment_variable(
              constant.ENV_VAR_MITRE_ATTACK_ENABLED
          )
          == "true"
      ):
        for item in data:
          if item.get("type") == "file":
            attack_techniques_data = (
                self.fetch_and_process_attack_techniques_data(
                    item.get("id"), True
                )
            )
            if attack_techniques_data:
              # Append attack techniques to the file IOC data at parent level
              item.update(attack_techniques_data)
    except Exception as attack_techniques_exc:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Error during attack techniques processing for IOC Stream data:"
          f" {repr(attack_techniques_exc)}",
          severity="ERROR",
      )

  def fetch_and_process_attack_techniques_data(self, ioc_value, should_retry):
    """Fetch and process ATT&CK techniques for given IOC type and IOC value.

    This method retrieves MITRE ATT&CK techniques data for a given file hash
    IOC,
    and structures it in the new sandboxobject format to be appended to file IOC
    data.

    Args:
        ioc_value (str): IOC value (file hash).
        should_retry (bool): Whether to retry API calls on failure.

    Returns:
        dict: Structured attack techniques data in sandboxobject format, or None
        if error.
    """
    utils.cloud_logging(
        "Fetching ATT&CK techniques data for file: {0}.".format(ioc_value)
    )
    attack_techniques_response = self.get_attack_techniques(
        file_hash=ioc_value, should_retry=should_retry
    )

    if not attack_techniques_response["status"]:
      utils.cloud_logging(
          "Error while fetching ATT&CK techniques data for file: {0}.".format(
              ioc_value
          ),
          severity="ERROR",
      )
      return None

    attack_techniques_data = attack_techniques_response["data"].get("data", {})
    sandboxobject_list = []

    # Process each sandbox's tactics and techniques
    for sandbox_name, tactics_dict in attack_techniques_data.items():
      sandboxobject = {
          "sandbox_name": sandbox_name,
          "ioc_value": ioc_value,
          "tactics": tactics_dict.get("tactics"),
      }
      sandboxobject_list.append(sandboxobject)

    if sandboxobject_list:
      utils.cloud_logging(
          "Successfully processed ATT&CK techniques data for file: {0}.".format(
              ioc_value
          )
      )
      return {"sandboxobject": sandboxobject_list}
    else:
      utils.cloud_logging(
          "No ATT&CK techniques found for file: {0}.".format(ioc_value)
      )
      return None

  def check_sufficient_permissions_on_service_account(self):
    """Check if the service account has sufficient permissions.

    This method checks if the service account has sufficient permissions to
    perform necessary operations. It retrieves the IAM policy for the project
    and checks if the service account has the necessary permissions. If not,
    it raises an exception.

    Returns:
      bool: True if the service account has sufficient permissions.

    Raises:
      RuntimeError: If the service account does not have sufficient permissions.
    """

    missing_permissions = set()
    try:
      client = resourcemanager_v3.ProjectsClient()
      chronicle_project_number = utility.get_environment_variable(
          env_constants.ENV_CHRONICLE_PROJECT_NUMBER
      )
      resource_name = f"projects/{chronicle_project_number}"
      policy = client.get_iam_policy(request={"resource": resource_name})

      service_account_email = requests.get(
          "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
          headers={"Metadata-Flavor": "Google"},
      ).text
      for permission_name, role in constant.PERMISSION_DETAILS.items():
        if not any(
            "serviceAccount:" + service_account_email in binding.members
            for binding in policy.bindings
            if binding.role == role
        ):
          missing_permissions.add(permission_name)

      if missing_permissions:
        error_msg = (
            f"Service account - {service_account_email} does not have"
            " sufficient permissions."
        )
        utils.cloud_logging(f"{error_msg}")
        raise GCPPermissionDeniedError(
            message=error_msg,
            resource=resource_name,
            permissions=list(missing_permissions),
        )
      else:
        utils.cloud_logging("Service account has sufficient permissions.")
        return True
    except Exception as e:
      utils.cloud_logging(f"Unexpected error: {repr(e)}")
      raise Exception(f"Unexpected error: {e}") from e  # pylint: disable=broad-exception-raised
