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


"""Vectra Client for API calls."""

import copy
import datetime
import json
import multiprocessing
import time
import urllib.parse

from google.cloud import storage
import requests

from common import ingest
from common import status
from common import utils
import constant
import exception
import utils as vectra_utils

LOCK = multiprocessing.Lock()


class VectraClient:
  """VectraClient to interact with Vectra and Ingest data to Google SecOps."""

  def __init__(
      self,
      client_id,
      client_secret,
      base_url,
      bucket_name,
      secret_manager_client,
  ):
    self.session = requests.session()
    self.client_id = client_id
    self.client_secret = client_secret
    self.base_url = base_url
    self.bucket_name = bucket_name
    self.access_token = None
    self.refresh_token = None
    self.session.headers.update(constant.HEADERS)
    self.secret_manager_client = secret_manager_client

    utils.cloud_logging("Vectra Client Initialized.")
    self._generate_initial_access_and_refresh_token()

  def _generate_initial_access_and_refresh_token(self):
    """generate initial access and refresh token if not exists."""
    try:
      token_info = self.secret_manager_client.get_secrets(
          constant.VECTRA_API_TOKEN_SECRET_NAME
      )
      self.access_token = token_info.get("access_token")
      self.refresh_token = token_info.get("refresh_token")
    except Exception:  # pylint: disable=broad-except
      token_info = None

    if not token_info or not self.access_token or not self.refresh_token:
      try:
        self._generate_access_and_refresh_token()
        utils.cloud_logging("New access and refresh tokens generated.")
      except (
          exception.RefreshTokenException,
          exception.RateLimitException,
          exception.VectraException,
          exception.UnauthorizeException,
      ) as e:
        utils.cloud_logging(f"Failed to generate tokens: {e}", severity="ERROR")
        self.access_token = None
        self.refresh_token = None
        raise Exception(e) from e  # pylint: disable=broad-exception-raised

    if self.access_token:
      self.session.headers.update(
          {"Authorization": f"Bearer {self.access_token}"}
      )

  def _make_rest_call_for_token_generation(
      self, body=None, retry_count=constant.RETRY_COUNT, **kwargs
  ):
    """Generates new access and refresh tokens and updates secret manager.

    Args:
        body (str, optional): The JSON payload of the request. Defaults to None.
        retry_count (int, optional): The number of retries in case of rate
          limit. Defaults to RETRY_COUNT.
        **kwargs: Additional keyword arguments for the request.

    Returns:
        dict: The JSON response from the API.

    Raises:
        RateLimitException: If the API rate limit is exceeded.
        UnauthorizeException: If the access token is invalid.
    """
    response = None
    try:
      request_url = urllib.parse.urljoin(
          self.base_url, constant.VECTRA_ACCESS_TOKEN_ENDPOINT
      )
      response = self.session.request(
          method="POST",
          url=request_url,
          data=body,
          **kwargs,
      )
      self.validate_response(constant.VECTRA_ACCESS_TOKEN_ENDPOINT, response)
    except exception.RateLimitException as e:
      if response is not None:
        if retry_count > 0:
          backoff_time = int(
              response.headers.get("Retry-After", constant.WAIT_TIME_FOR_RETRY)
          )
          utils.cloud_logging(
              "Retrying the token generation request after {} seconds.".format(
                  backoff_time
              ),
              severity="ERROR",
          )
          time.sleep(backoff_time)
          retry_count -= 1
          return self._make_rest_call_for_token_generation(
              body=body, retry_count=retry_count, **kwargs
          )
        else:
          utils.cloud_logging(
              "Maximum retry count reached. Failed to generate new access token"
              f" using refresh token. {constant.ERRORS['RATE_LIMIT_EXCEEDED']}",
              severity="ERROR",
          )
          raise exception.RateLimitException(
              constant.ERRORS["RATE_LIMIT_EXCEEDED"]
          ) from e
      else:
        utils.cloud_logging("API response is not valid.")
        return {}
    except exception.RefreshTokenException as e:
      utils.cloud_logging(
          "Generating new access and refresh token as the refresh"
          " token is expired.",
          severity="Info",
      )
      raise exception.RefreshTokenException(
          "Failed to generate new access token using refresh token."
      ) from e
    except exception.UnauthorizeException as e:
      utils.cloud_logging(
          "Provided Credentials are not valid!. Please verify provided"
          f" credentials. Error message: {e}",
          severity="ERROR",
      )
      raise exception.UnauthorizeException(
          "Provided Credentials are not valid!. Please verify provided"
          " credentials."
      ) from e
    except Exception as e:
      utils.cloud_logging(
          "Unknown exception occurred generating access token. Error"
          f" message: {e}",
          severity="ERROR",
      )
      raise exception.VectraException(e) from e

    # retrieve existing secrets
    response_data = {}
    try:
      response_data = response.json()
      existing_secrets = self.secret_manager_client.get_secrets(
          secret_name=constant.VECTRA_API_TOKEN_SECRET_NAME
      )
    except Exception:  # pylint: disable=broad-except
      existing_secrets = {}

    updated_secrets = copy.deepcopy(existing_secrets)
    if response_data.get("access_token", None):
      self.access_token = response_data["access_token"]
      updated_secrets["access_token"] = self.access_token

    if response_data.get("refresh_token", None):
      self.refresh_token = response_data["refresh_token"]
      updated_secrets["refresh_token"] = self.refresh_token

    self.secret_manager_client.set_or_update_secrets(
        constant.VECTRA_API_TOKEN_SECRET_NAME, updated_secrets
    )
    self.session.headers.update(
        {"Authorization": f"Bearer {self.access_token}"}
    )
    return response_data

  def _generate_access_and_refresh_token(self):
    """Generates new access token and refresh token using provided client_id and client_secret."""
    payload = "grant_type=client_credentials"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
      self._make_rest_call_for_token_generation(
          body=payload,
          headers=headers,
          auth=requests.auth.HTTPBasicAuth(self.client_id, self.client_secret),
      )
    except exception.UnauthorizeException as e:
      utils.cloud_logging(
          "UnauthorizeException occurred while generating access token. Error"
          f" message: {e}",
          severity="ERROR",
      )
      raise exception.UnauthorizeException(e) from e
    except exception.RateLimitException as e:
      utils.cloud_logging(
          "RateLimitException occurred while generating access token. Error"
          f" message: {e}",
          severity="ERROR",
      )
      raise exception.RateLimitException(e) from e
    except Exception as e:
      utils.cloud_logging(
          "Exception occurred while generating access token. Error"
          f" message: {e}",
          severity="ERROR",
      )
      raise exception.VectraException(e) from e

  def _generate_access_token(self):
    """Generates new access token using existing refresh token.

    Generates new access token using existing refresh token and updates the
    secret manager with the new access token and refresh token if it exists.
    If the refresh token is expired, it generates new access token and refresh
    token using provided client_id and client_secret.

    Raises:
        RateLimitException: If the API rate limit is exceeded.
        UnauthorizeException: If the access token is invalid.
        VectraException: If any other exception occurs.
    """
    payload = f"grant_type=refresh_token&refresh_token={self.refresh_token}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
      self._make_rest_call_for_token_generation(body=payload, headers=headers)
    except exception.RefreshTokenException:
      utils.cloud_logging(
          "Generating new access and refresh token as the refresh"
          " token is expired.",
          severity="Info",
      )
      self._generate_access_and_refresh_token()
    except exception.RateLimitException as e:
      utils.cloud_logging(
          "RateLimitException exception occurred while generating access token"
          f" from refresh token. Error message: {e}",
          severity="ERROR",
      )
      raise exception.RateLimitException(e) from e
    except Exception as e:
      utils.cloud_logging(
          "Unknown exception occurred while generating access token from"
          f" refresh token. Error message: {e}",
          severity="ERROR",
      )
      raise exception.VectraException(e) from e

  def _ingest_events(self, events):
    """Ingests events into Chronicle.

    Args:
        events (list): A list of events to be ingested into Chronicle.

    Raises:
        Exception: If an error occurs during the ingestion process, it logs the
        error message.
    """
    try:
      if events:
        utils.cloud_logging("Ingesting events into Chronicle.")
        ingest.ingest(events, constant.CHRONICLE_DATA_TYPE)
      else:
        utils.cloud_logging("No events to push data to ingest into Chronicle.")
    except Exception as e:
      utils.cloud_logging(
          f"Error occurred while ingesting data: {e}", severity="ERROR"
      )
      raise Exception(e) from e  # pylint: disable=broad-exception-raised

  def _get_last_checkpoint(self, endpoint):
    """Retrieves the last checkpoint from bucket for the given endpoint.

    Args:
        endpoint (str): The API endpoint to retrieve the last checkpoint.

    Returns:
        str: The last checkpoint for the given endpoint, or None if no
        checkpoint exists.
    """
    try:
      storage_client = storage.Client()
      bucket = storage_client.get_bucket(self.bucket_name)
      blob = bucket.blob(constant.GCP_BUCKET_FILE_NAME)
      if blob.exists():
        data = json.loads(blob.download_as_text())
        return data.get(endpoint, None)
      else:
        utils.cloud_logging(
            f"Checkpoint file in '{self.bucket_name}' does not exist."
        )
        return None
    except json.JSONDecodeError:
      utils.cloud_logging(
          f"Failed to decode JSON content from {constant.GCP_BUCKET_FILE_NAME}",
          severity="WARNING",
      )
      return None
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Unknown exception occurred while getting last checkpoint. Error"
          f" message: {e}",
          severity="ERROR",
      )
      return None

  def _set_last_checkpoint(self, endpoint, last_checkpoint):
    """Store the the last checkpoint for the given endpoint in bucket.

    Args:
        endpoint (str): The API endpoint to set the last checkpoint.
        last_checkpoint (str): The last checkpoint to set.

    Raises:
        Exception: If an error occurs during the process of setting the last
        checkpoint, it logs the
        error message.
    """
    try:
      with LOCK:
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(
            vectra_utils.get_environment_variable(constant.ENV_GCP_BUCKET_NAME)
        )
        blob = bucket.blob(constant.GCP_BUCKET_FILE_NAME)
        bucket_data = {}
        if blob.exists():
          try:
            bucket_data = json.loads(blob.download_as_text())
          except json.JSONDecodeError:
            utils.cloud_logging(
                "Failed to decode JSON content from"
                f" {constant.GCP_BUCKET_FILE_NAME}",
                severity="WARNING",
            )
        bucket_data[endpoint] = last_checkpoint
        with blob.open(mode="w", encoding="utf-8") as f:
          f.write(json.dumps(bucket_data))
        utils.cloud_logging(
            f"Updated checkpoint values for endpoint: [{endpoint}]. last"
            f" checkpoint: {last_checkpoint}"
        )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Unknown exception occurred while setting checkpoint. Error"
          f" message: {e}",
          severity="ERROR",
      )
      return None

  def _make_api_call(
      self,
      endpoint: str,
      params: dict[str, str] | None = None,
      method: str = "GET",
      body: dict[str, str] | None = None,
      retry_count: int = constant.RETRY_COUNT,
      retry_count_token: int = constant.RETRY_COUNT_TOKEN,
      **kwargs,
  ) -> dict:  # pylint: disable=g-bare-generic
    """Makes a request call to the VectraRUX.

    Args:
        endpoint (str): Endpoint of the API.
        params (dict, optional): The parameters of the request. Defaults to
          None.
        method (str): The method of the request (GET, POST, etc.). Defaults to
          "GET".
        body (dict, optional): The JSON payload of the request. Defaults to
          None.
        retry_count (int, optional): The number of retries in case of rate
          limit. Defaults to RETRY_COUNT.
        retry_count_token (int, optional): The number of retries in case of
          unauthorized response. Defaults to RETRY_COUNT_TOKEN.
        **kwargs: Additional keyword arguments for the request.

    Returns:
        dict: The JSON response from the API.

    Raises:
        RateLimitException: If the API rate limit is exceeded.
        UnauthorizeException: If the access token is invalid.
    """
    request_url = urllib.parse.urljoin(self.base_url, endpoint)
    response = None
    try:
      response = self.session.request(
          method,
          request_url,
          params=params,
          data=body,
          timeout=constant.DEFAULT_REQUEST_TIMEOUT,
          **kwargs,
      )
      self.validate_response(endpoint, response)
      return response.json()
    except exception.RateLimitException as e:
      if response is not None:
        if retry_count > 0:
          # identify the retry after from the response header
          backoff_time = int(
              response.headers.get("Retry-After", constant.WAIT_TIME_FOR_RETRY)
          )
          utils.cloud_logging(
              f"Retrying the request [{endpoint}] after"
              f" {backoff_time} seconds.",
              severity="WARNING",
          )
          time.sleep(backoff_time)
          retry_count -= 1
          return self._make_api_call(
              endpoint,
              params,
              method,
              body,
              retry_count,
              retry_count_token,
              **kwargs,
          )
        else:
          utils.cloud_logging(
              "Maximum retry count reached. Failed to make API call request"
              f" [{endpoint}]. {constant.ERRORS['RATE_LIMIT_EXCEEDED']}",
              severity="ERROR",
          )
          raise exception.RateLimitException(
              constant.ERRORS["RATE_LIMIT_EXCEEDED"]
          ) from e
      else:
        utils.cloud_logging("API response is not valid.")
        return {}
    except exception.UnauthorizeException as e:
      if retry_count_token > 0:
        utils.cloud_logging(
            "UnauthorizeException occurred while making API call. Error"
            f" message: {e}."
        )
        utils.cloud_logging("Generating new tokens due to token expiration")
        self._generate_access_token()
        retry_count_token -= 1
        return self._make_api_call(
            endpoint,
            params,
            method,
            body,
            retry_count,
            retry_count_token,
            **kwargs,
        )
      else:
        utils.cloud_logging(
            "Retry count for generating new tokens reached."
            "UnauthorizeException occurred while making API call. Error"
            f" message: {e}.",
            severity="ERROR",
        )
        raise exception.UnauthorizeException(e) from e
    except json.JSONDecodeError as e:
      utils.cloud_logging(
          "Exception occurred while decoding response json. Error"
          f" message: {e}",
          severity="ERROR",
      )
      return {}
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Exception occurred while making API call. Error message: {e}",
          severity="ERROR",
      )
      return {}

  def _handle_checkpoint(self, last_checkpoint):
    """Handles the checkpoint logic for API requests.

    If a last checkpoint is provided, returns ("from", last_checkpoint). If no
    last checkpoint is provided, returns a timestamp from 24 hours ago with the
    field "event_timestamp_gte".

    Args:
        last_checkpoint (str): The last known checkpoint value.

    Returns:
        tuple: A tuple containing the checkpoint field and its value.
    """
    checkpoint_field = "from"
    checkpoint_value = last_checkpoint
    if not last_checkpoint:
      current_time = datetime.datetime.now()
      event_timestamp = current_time.isoformat()

      if (
          vectra_utils.get_environment_variable(constant.ENV_HISTORICAL)
          == "true"
      ):
        utils.cloud_logging(
            "Historical mode is enabled. Setting checkpoint to 24 hours ago."
        )
        time_24_hours_ago = current_time - datetime.timedelta(hours=24)
        event_timestamp = time_24_hours_ago.isoformat()
      else:
        utils.cloud_logging(
            "No last checkpoint found. Setting checkpoint to current current"
            " time.",
            severity="WARNING",
        )
      checkpoint_field = "event_timestamp_gte"
      checkpoint_value = event_timestamp

    utils.cloud_logging(
        f"Checkpoint field: {checkpoint_field}. Checkpoint value:"
        f" {checkpoint_value}"
    )
    return checkpoint_field, checkpoint_value

  def _extract_response(self, response):
    """Extracts events, remaining count, and checkpoint information from the API response.

    Args:
        response (dict): The API response containing events and checkpoint data.

    Returns:
        tuple: A tuple containing a list of events, the remaining count, and the
        next checkpoint.

    Raises:
        KeyError: If 'NEXT_CHECKPOINT' is not present in the response.
        ValueError: If the 'NEXT_CHECKPOINT' is None.
        TypeError: If the 'events' or 'remaining_count' is not of type list or
        int.
    """
    if not response:
      utils.cloud_logging("Response is None", severity="ERROR")
      raise TypeError("Response is None")

    try:
      next_checkpoint = response.get(constant.NEXT_CHECKPOINT, None)
      if next_checkpoint is None:
        utils.cloud_logging(
            "next_checkpoint not found while extracting the response",
            severity="ERROR",
        )
        raise ValueError("Next Checkpoint is None")

      events = response.get("events")
      if events is None:
        utils.cloud_logging(
            "No events found while extracting the response", severity="ERROR"
        )
        raise TypeError("Events is None")

      remaining_count = response.get(constant.REMAINING_COUNT)
      if remaining_count is None:
        utils.cloud_logging(
            "Remaining count not found while extracting the response",
            severity="ERROR",
        )
        raise TypeError("Remaining count is None")

      if not isinstance(events, list):
        utils.cloud_logging("Events is not of type list", severity="ERROR")
        raise TypeError("Events is not of type list")

      return events, remaining_count, next_checkpoint
    except TypeError as e:
      utils.cloud_logging(f"TypeError occurred. Error : {e}", severity="ERROR")
      raise TypeError(e) from e
    except ValueError as e:
      utils.cloud_logging(f"ValueError occurred: Error : {e}", severity="ERROR")
      raise ValueError(e) from e

  def get_and_ingest_detection_events(self):
    """Retrieves detection events of type 'account' and 'host' from Vectra and ingests them into Chronicle.

    Raises:
        Exception: If an error occurs during the ingestion process, it logs the
        error message.
    """
    try:
      remaining_count = 1
      while remaining_count > 0:
        response = self._get_detection_events_by_type(constant.ACCOUNT_TYPE)
        events, remaining_count, next_checkpoint = self._extract_response(
            response
        )
        utils.cloud_logging(
            f"Detection Events by {constant.ACCOUNT_TYPE} type: {len(events)}."
            f" Next checkpoint: {next_checkpoint}. Remaining count:"
            f" {remaining_count}"
        )
        self._ingest_events(events)
        self._set_last_checkpoint(
            constant.VECTRA_DETECTION_ENDPOINT + "_" + constant.ACCOUNT_TYPE,
            next_checkpoint,
        )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Execution of Detection {constant.ACCOUNT_TYPE} stops due to"
          f" exception occurred while making API call. Error message: {e}",
          severity="ERROR",
      )

    try:
      remaining_count = 1
      while remaining_count > 0:
        response = self._get_detection_events_by_type(constant.HOST_TYPE)
        events, remaining_count, next_checkpoint = self._extract_response(
            response
        )
        utils.cloud_logging(
            f"Detection Events by {constant.HOST_TYPE} type: {len(events)}."
            f" Next checkpoint: {next_checkpoint}. Remaining count:"
            f" {remaining_count}"
        )
        self._ingest_events(events)
        self._set_last_checkpoint(
            constant.VECTRA_DETECTION_ENDPOINT + "_" + constant.HOST_TYPE,
            next_checkpoint,
        )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Execution of Detection {constant.HOST_TYPE} stops due to exception"
          f" occurred while making API call. Error message: {e}",
          severity="ERROR",
      )

  def _get_detection_events_by_type(self, detection_type):
    """Retrieves detection events for a specified type from Vectra.

    Args:
        detection_type (str): The type of detection events to retrieve, e.g.,
          'account' or 'host'.

    Returns:
        dict: The API response containing detection events.

    Raises:
        Exception: If an error occurs during the API call.
    """
    try:
      last_checkpoint = self._get_last_checkpoint(
          constant.VECTRA_DETECTION_ENDPOINT + "_" + detection_type
      )
      checkpoint_field, checkpoint_value = self._handle_checkpoint(
          last_checkpoint
      )

      query_params = {
          checkpoint_field: checkpoint_value,
          "type": detection_type,
          "include_info_category": vectra_utils.get_environment_variable(
              constant.ENV_VAR_INCLUDE_INFO_CATEGORY
          ),
          "include_triaged": vectra_utils.get_environment_variable(
              constant.ENV_VAR_INCLUDE_TRIAGED
          ),
          "limit": constant.MAX_EVENT_LIMIT,
      }

      # finalize the ERRORS passing
      response = self._make_api_call(
          constant.VECTRA_DETECTION_ENDPOINT, query_params
      )
      return response
    except Exception as e:
      raise Exception(e) from e  # pylint: disable=broad-exception-raised

  def get_and_ingest_audit_events(self):
    """Retrieves audit events from Vectra and ingests them into Chronicle.

    Raises:
        Exception: If an error occurs during the ingestion process.
    """
    try:
      remaining_count = 1
      while remaining_count > 0:
        response = self._get_audit_events()
        events, remaining_count, next_checkpoint = self._extract_response(
            response
        )
        utils.cloud_logging(
            f"Audit Events: {len(events)}. Next checkpoint: {next_checkpoint}."
            f" Remaining count: {remaining_count}"
        )
        self._ingest_events(events)
        self._set_last_checkpoint(
            constant.VECTRA_AUDIT_ENDPOINT, next_checkpoint
        )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Execution of Audit stops due to exception occurred while making API"
          f" call. Error message: {e}",
          severity="ERROR",
      )

  def _get_audit_events(self):
    """Retrieves audit events from Vectra.

    Returns:
        dict: The API response containing audit events.

    Raises:
        Exception: If an error occurs during the API call.
    """
    try:
      last_checkpoint = self._get_last_checkpoint(
          constant.VECTRA_AUDIT_ENDPOINT
      )
      utils.cloud_logging(f"Audit events. Last checkpoint: {last_checkpoint}")
      checkpoint_field, checkpoint_value = self._handle_checkpoint(
          last_checkpoint
      )
      query_params = {
          checkpoint_field: checkpoint_value,
          "limit": constant.MAX_EVENT_LIMIT,
      }
      response = self._make_api_call(
          constant.VECTRA_AUDIT_ENDPOINT, query_params
      )
      return response
    except Exception as e:
      raise Exception(e) from e  # pylint: disable=broad-exception-raised

  def get_and_ingest_entity_scoring_events(self):
    """Retrieves and ingests entity scoring events from Vectra for both account and host types.

    Raises:
        Exception: If an error occurs during the API call or event ingestion
        process, it logs
        the error message.
    """
    try:
      remaining_count = 1
      while remaining_count > 0:
        response = self._get_entity_scoring_by_type(constant.ACCOUNT_TYPE)
        events, remaining_count, next_checkpoint = self._extract_response(
            response
        )
        utils.cloud_logging(
            f"Entity scoring Events by {constant.ACCOUNT_TYPE} type:"
            f" {len(events)}. Next checkpoint: {next_checkpoint}. Remaining"
            f" count: {remaining_count}"
        )
        self._ingest_events(events)
        self._set_last_checkpoint(
            constant.VECTRA_SCORING_ENDPOINT + "_" + constant.ACCOUNT_TYPE,
            next_checkpoint,
        )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Execution of Scoring {constant.ACCOUNT_TYPE} stops due to exception"
          f" occurred while making API call. Error message: {e}",
          severity="ERROR",
      )

    try:
      remaining_count = 1
      while remaining_count > 0:
        response = self._get_entity_scoring_by_type(constant.HOST_TYPE)
        events, remaining_count, next_checkpoint = self._extract_response(
            response
        )
        utils.cloud_logging(
            f"Entity scoring Events by {constant.HOST_TYPE} type:"
            f" {len(events)}. Next checkpoint: {next_checkpoint}. Remaining"
            f" count: {remaining_count}"
        )
        self._ingest_events(events)
        self._set_last_checkpoint(
            constant.VECTRA_SCORING_ENDPOINT + "_" + constant.HOST_TYPE,
            next_checkpoint,
        )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Execution of Scoring {constant.HOST_TYPE} stops due to exception"
          f" occurred while making API call. Error message: {e}",
          severity="ERROR",
      )

  def _get_entity_scoring_by_type(self, entity_type):
    """Retrieves entity scoring events of the specified type from Vectra.

    Args:
        entity_type (str): The type of entity for which to retrieve scoring
          events.

    Returns:
        dict: The API response containing the entity scoring events.

    Raises:
        Exception: If an error occurs during the API call, it raises an
        exception with the error message.
    """
    try:
      last_checkpoint = self._get_last_checkpoint(
          constant.VECTRA_SCORING_ENDPOINT + "_" + entity_type
      )
      utils.cloud_logging(
          f"Entity scoring events by {entity_type} type. Last checkpoint:"
          f" {last_checkpoint}"
      )

      checkpoint_field, checkpoint_value = self._handle_checkpoint(
          last_checkpoint
      )

      query_params = {
          checkpoint_field: checkpoint_value,
          "type": entity_type,
          "include_score_decreases": vectra_utils.get_environment_variable(
              constant.ENV_VAR_INCLUDE_SCORE_DECREASES
          ),
          "limit": constant.MAX_EVENT_LIMIT,
      }

      # finalize the ERRORS passing
      response = self._make_api_call(
          constant.VECTRA_SCORING_ENDPOINT, query_params
      )
      return response
    except Exception as e:
      raise Exception(e) from e  # pylint: disable=broad-exception-raised

  def get_and_ingest_lockdown_events(self):
    """Retrieves lockdown events of type 'account' and 'host' from Vectra and ingests them into Chronicle.

    Raises:
        Exception: If an error occurs during the API call or event ingestion
        process, it logs the error message.
    """
    try:
      response = self._get_entity_lockdown_by_type(constant.ACCOUNT_TYPE)
      if response is not None and isinstance(response, list):
        self._ingest_events(response)
      else:
        utils.cloud_logging(
            "No data lockdown received from the API response for account type."
        )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Execution of Lockdown {constant.ACCOUNT_TYPE} stops due to"
          f" exception occurred while making API call. Error message: {e}",
          severity="ERROR",
      )

    try:
      response = self._get_entity_lockdown_by_type(constant.HOST_TYPE)
      if response is not None and isinstance(response, list):
        self._ingest_events(response)
      else:
        utils.cloud_logging(
            "No data lockdown received from the API response for host type."
        )
    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          f"Execution of Lockdown {constant.HOST_TYPE} stops due to exception"
          f" occurred while making API call. Error message: {e}",
          severity="ERROR",
      )

  def _get_entity_lockdown_by_type(self, lockdown_type):
    """Retrieves lockdown events of the specified type from Vectra.

    Args:
        lockdown_type (str): The type of lockdown events to retrieve, e.g.,
          'account' or 'host'.

    Returns:
        list: The API response containing the lockdown events.

    Raises:
        Exception: If an error occurs during the API call, it raises an
        exception with the error message.
    """
    try:
      utils.cloud_logging(f"Entity lockdown events for {lockdown_type} type.")
      query_params = {"type": lockdown_type}
      response = self._make_api_call(
          constant.VECTRA_LOCKDOWN_ENDPOINT, query_params
      )
      return response
    except Exception as e:
      raise Exception(e) from e  # pylint: disable=broad-exception-raised

  def get_and_ingest_health_events(self):
    """Retrieves health events from Vectra and ingests them into Chronicle.

    Raises:
        Exception: If an error occurs during the API call or event ingestion
        process, it logs the error message.
    """

    try:
      query_params = {
          "v_lans": vectra_utils.get_environment_variable(
              constant.ENV_VAR_VLANS
          ),
      }
      response = self._make_api_call(
          constant.VECTRA_HEALTH_ENDPOINT, query_params
      )
      if response is not None:
        response = [response]
        self._ingest_events(response)
        utils.cloud_logging("Health events ingested into Chronicle.")
      else:
        utils.cloud_logging("No data health received from the API response.")

    except Exception as e:  # pylint: disable=broad-except
      utils.cloud_logging(
          "Execution of Health stops due to exception occurred while making"
          f" API call. Error message: {e}",
          severity="ERROR",
      )

  @classmethod
  def validate_response(
      cls, url, response: requests.Response, error_msg="An error occurred"
  ) -> None:
    """Validate the response from the API.

    Args:
        url (str): The URL of the API request.
        response (requests.Response): The response object.
        error_msg (str, optional): The error message to use if an error occurs.
          Defaults to "An error occurred".

    Raises:
        RateLimitException: If the API rate limit is exceeded.
    """
    try:
      response.raise_for_status()
    except requests.HTTPError as error:
      if response.status_code == status.STATUS_TOO_MANY_REQUESTS:
        utils.cloud_logging(
            "RateLimitException occurred. API rate limit exceeded. Error"
            f" message: {error}",
            severity="ERROR",
        )
        raise exception.RateLimitException("API rate limit exceeded.") from None
      vectra_utils.HandleExceptions(
          url, error, response, error_msg
      ).do_process()
