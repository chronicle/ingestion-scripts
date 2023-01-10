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
"""Unit test file for auth.py file."""

import unittest
from unittest import mock

from common import auth

# Path to common framework.
INGESTION_SCRIPTS_PATH = "common."


class TestAuthMethod(unittest.TestCase):
  """Unit test class for AuthMethod."""

  @mock.patch("requests.Request")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}auth.AuthMethod._make_api_call")
  def test_paginate_success(self, mock_make_api_call, unused_mock_request):
    """Test case to verify the success scenario for the paginate method.

    Args:
      mock_make_api_call (mock.Mock): Mocked object of _make_api_call method.
      unused_mock_request (mock.Mock): Mocked object of request module.

    Asserts:
      Validates that the response object is called through session.paginate()
      method.
    """
    auth_method = auth.AuthMethod()
    response_object = mock.MagicMock()
    mock_make_api_call.return_value = response_object
    mock_before_next = mock_has_next = mock.MagicMock()
    mock_before_next.return_value = ""
    mock_has_next.return_value = False
    result = auth_method.paginate(
        self, has_next=mock_has_next, before_next=mock_before_next)
    assert list(result) == [response_object]

  def test_paginate_failure_has_next(self):
    """Test case to verify that paginate method raises ValueError when has_next is not passed to paginate.

    Asserts:
      Validates that paginate() method raises ValueError if has_next() method
      is not passed.
    """
    auth_method = auth.AuthMethod()
    with self.assertRaises(ValueError):
      result = auth_method.paginate(before_next="")
      next(result)

  def test_paginate_failure_before_next(self):
    """Test case to verify that paginate method raises ValueError when before_next is not passed to paginate.

    Asserts:
      Validates that paginate() method raises ValueError if before_next() method
      is not passed.
    """
    auth_method = auth.AuthMethod()
    with self.assertRaises(ValueError):
      result = auth_method.paginate(has_next="")
      next(result)

  def test_make_api_call_success_200(self):
    """Test case to verify the success scenario for the _make_api_call method.

    Asserts:
      Validates that execution of make_api_call() method if the status code of
      the response is 200.
      Validates prepare_request() method is called once.
      Validates send() method is called once.
    """
    auth_method = auth.AuthMethod()
    auth_method.session = mock.MagicMock()
    mock_response = mock.MagicMock()
    auth_method.session.send.return_value = mock_response
    mock_response.status_code = 200
    assert auth_method._make_api_call(mock.MagicMock()) == mock_response
    assert auth_method.session.prepare_request.call_count == 1
    assert auth_method.session.send.call_count == 1

  def test_make_api_call_error_401(self):
    """Test case to verify that the token is refreshed when API returns 401 error.

    Asserts:
      Validates that execution of make_api_call() method if the status code of
      the response is 401.
      Validates prepare_request() method is called once.
      Validates send() method is called once.
      Validates refresh_auth_tokens() method is called once.
    """
    auth_method = auth.AuthMethod()
    auth_method.session = mock.MagicMock()
    auth_method.refresh_auth_tokens = mock.MagicMock()
    mock_response = mock.MagicMock()
    auth_method.session.send.return_value = mock_response
    mock_response.status_code = 401
    assert auth_method._make_api_call(mock.MagicMock()) == mock_response
    assert auth_method.session.prepare_request.call_count == 2
    assert auth_method.session.send.call_count == 2
    assert auth_method.refresh_auth_tokens.call_count == 1

  def test_make_api_call_error_403(self):
    """Test case to verify that the token is refreshed when API returns 403 error.

    Asserts:
      Validates that execution of make_api_call() method if the status code of
      the response is 401.
      Validates prepare_request() method is called once.
      Validates send() method is called once.
      Validates refresh_auth_tokens() method is called once.
    """
    auth_method = auth.AuthMethod()
    auth_method.session = mock.MagicMock()
    auth_method.refresh_auth_tokens = mock.MagicMock()
    mock_response = mock.MagicMock()
    auth_method.session.send.return_value = mock_response
    mock_response.status_code = 403
    assert auth_method._make_api_call(mock.MagicMock()) == mock_response
    assert auth_method.session.prepare_request.call_count == 2
    assert auth_method.session.send.call_count == 2
    assert auth_method.refresh_auth_tokens.call_count == 1


class TestOAuthClientCredentialsAuth(unittest.TestCase):
  """Unit test class for OAuthClientCredentialsAuth."""

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}auth.requests")
  def test_init_success(self, mock_requests):
    """Test case to verify the successful initialization of the object.

    Args:
      mock_requests (mock.Mock): Mocked object of requests module.

    Asserts:
      Validates that requests.Request() method is called once.
      Validates before_request() method is called once.
      Validates requests.Session() method is called once.
      Validates session.send() method is called once.
      Validates json() method is called once.
    """
    mock_session = mock.MagicMock()
    mock_requests.Session.return_value = mock_session
    mock_response = mock.MagicMock()
    mock_session.send.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "access_token",
    }
    mock_before_request = mock.MagicMock()
    oauth_ob = auth.OAuthClientCredentialsAuth("endpoint", "client_id",
                                               "client_secret", "scope",
                                               mock_before_request)
    assert isinstance(oauth_ob, auth.OAuthClientCredentialsAuth)
    assert mock_requests.Request.call_count == 1
    assert mock_before_request.call_count == 1
    assert mock_requests.Session.call_count == 1
    assert mock_session.send.call_count == 1
    assert mock_response.json.call_count == 1

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}auth.requests")
  def test_init_for_access_token(self, mock_requests):
    """Test case to verify the successful initialization of the object.

    Args:
      mock_requests (mock.Mock): Mocked object of requests module.

    Asserts:
      Validates that requests.Request() method is called once.
      Validates before_request() method is called once.
      Validates requests.Session() method is called once.
      Validates session.send() method is called once.
      Validates json() method is called once.
      Validates the access token is added in the session headers.
    """
    mock_session = mock.MagicMock()
    mock_requests.Session.return_value = mock_session
    mock_response = mock.MagicMock()
    mock_session.send.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "access_token",
        "refresh_token": "refresh_token"
    }
    mock_before_request = mock.MagicMock()
    oauth_ob = auth.OAuthClientCredentialsAuth("endpoint", "client_id",
                                               "client_secret", "scope",
                                               mock_before_request)
    assert mock_requests.Request.call_count == 1
    assert mock_before_request.call_count == 1
    assert mock_requests.Session.call_count == 1
    assert mock_session.send.call_count == 1
    assert mock_response.json.call_count == 1
    assert oauth_ob.session.headers["Authorization"] == "Bearer access_token"

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}auth.requests")
  def test_init_for_failure(self, mock_requests):
    """Test case to verify the execution of init when API returns 401 error.

    Args:
      mock_requests (mock.Mock): Mocked object of requests module.

    Asserts:
      Validates that requests.Request() method is called once.
      Validates before_request() method is called once.
      Validates requests.Session() method is called once.
      Validates session.send() method is called once.
      Validates json() method is called once.
    """
    mock_session = mock.MagicMock()
    mock_requests.Session.return_value = mock_session
    mock_response = mock.MagicMock()
    mock_session.send.return_value = mock_response
    mock_response.status_code = 401
    mock_before_request = mock.MagicMock()
    oauth_ob = auth.OAuthClientCredentialsAuth("endpoint", "client_id",  # pylint: disable=unused-variable
                                               "client_secret", "scope",
                                               mock_before_request)
    assert mock_requests.Request.call_count == 1
    assert mock_before_request.call_count == 1
    assert mock_requests.Session.call_count == 1
    assert mock_session.send.call_count == 1
    assert mock_response.json.call_count == 1


class TestOAuthPasswordGrantCredentialsAuth(unittest.TestCase):
  """Unit test class for TestOAuthPasswordGrantCredentialsAuth."""

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}auth.requests")
  def test_init_access_token(self, mock_requests):
    """Test case to verify the successful execution of init function.

    Args:
      mock_requests (mock.Mock): Mocked object of requests module.

    Asserts:
      Validates that requests.POST() method is called once.
      Validates json() method is called once.
      Validates the presence of Authorization key in session headers.
    """
    mock_response = mock.MagicMock()
    mock_requests.post.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "access_token",
        "refresh_token": "refresh_token"
    }
    oauth_ob = auth.OAuthPasswordGrantCredentialsAuth("endpoint", "username",
                                                      "password", "client_id",
                                                      "scope")
    assert mock_requests.post.call_count == 1
    assert mock_response.json.call_count == 1
    assert "Authorization" in oauth_ob.session.headers

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}auth.requests")
  def test_init_failure(self, mock_requests):
    """Test case to verify the execution of init when API returns 401 error.

    Args:
      mock_requests (mock.Mock): Mocked object of requests module.

    Asserts:
      Validates that requests.POST() method is called once.
      Validates json() method is called once.
    """
    mock_response = mock.MagicMock()
    mock_requests.post.return_value = mock_response
    mock_response.status_code = 401
    oauth_ob = auth.OAuthPasswordGrantCredentialsAuth("endpoint", "username",  # pylint: disable=unused-variable
                                                      "password", "client_id",
                                                      "scope")
    assert mock_requests.post.call_count == 1
    assert mock_response.json.call_count == 1


class TestOAuthJWTCredentialsAuth(unittest.TestCase):
  """Unit test class for OAuthJWTCredentialsAuth."""

  @mock.patch(f"{INGESTION_SCRIPTS_PATH}auth.requests")
  @mock.patch(f"{INGESTION_SCRIPTS_PATH}auth.jwt")
  def test_init_when_access_token_in_response(self, unused_mock_jwt,
                                              mock_requests):
    """Test case to verify the execution of init when access_token found in response.

    Args:
      mock_requests (mock.Mock): Mocked object of requests module.

    Asserts:
      Validates the presence of access token in the session headers.
    """
    mock_response = mock.MagicMock()
    mock_requests.post.return_value = mock_response
    mock_response.json.return_value = {
        "access_token": "access_token",
        "refresh_token": "refresh_token"
    }
    oauth_ob = auth.OAuthJWTCredentialsAuth("endpoint", "claims", "key",
                                            "algorithm", {})
    assert oauth_ob.session.headers["Authorization"] == "Bearer access_token"
