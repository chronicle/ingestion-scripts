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
"""Implementation of various authentication methods used for data collection."""

import base64
from typing import Callable, Optional

import jwt
import requests

from common import status

# Default timeout for requests in seconds.
DEFAULT_TIMEOUT = 60

# The names of the keyword argument, which will be used by paginate() method
# to extract the Callables from the kwargs.
HAS_NEXT = "has_next"
BEFORE_NEXT = "before_next"

# Grant types to be used for OAuth based authentication.
OAUTH_JWT_AUTH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
OAUTH_CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials"


class AuthMethod:
  """Main class for authentication."""

  session: requests.Session = requests.Session()

  def refresh_auth_tokens(self):
    """Generic method for refreshing the authentication tokens.

    This method should be defined by the child class whenever there is
    a possibility of refreshing authentication tokens. This method will be
    called by _make_api_call() function to refresh the authentication token, if
    it is expired while making the successive requests.

    Raises:
      NotImplementedError: Raises NotImplementedError.
    """
    raise NotImplementedError()

  def paginate(self, *args, **kwargs):
    """Paginate the REST API calls.

    This function requires two callables to be passed as keyword arguments.
    has_next: A function that checks whether the response contains the next page
      or not.
    before_next: A function that takes the current request and response and
      returns the next request URL by updating the current URL.

    Args:
      *args: Any number of positional arguments to pass in REST API execution.
      **kwargs: Any number of keyword arguments to pass in REST API execution.

    Yields:
      response: The response of current API call.

    Raises:
      ValueError: If "has_next" or "before_next" is not found in kwargs.
      HTTPError: If any error occures during API calls.
    """

    if HAS_NEXT not in kwargs:
      raise ValueError("The 'has_next' method is required to allow pagination "
                       "during the data collection.")
    if BEFORE_NEXT not in kwargs:
      raise ValueError("The 'before_next' method is required to prepare the "
                       "next page URL for the data collection.")
    has_next = kwargs.pop(HAS_NEXT)
    before_next = kwargs.pop(BEFORE_NEXT)
    request = requests.Request(*args, **kwargs)

    # Iterate through the pages till we collect all the events in the given
    # time frame
    while True:
      response = self._make_api_call(request)
      response.raise_for_status()
      yield response

      # Break the loop if no new pages are available for data collection
      if not has_next(response):
        break
      request = before_next(request, response)

  def _make_api_call(self, request) -> requests.Response:
    """Prepare requests session and execute the REST API calls.

    Args:
      request (requests.Request): An HTTP request.

    Returns:
      request.Response: Response returned by the API.

    Raises:
      requests.exceptions.HTTPError: Raises HTTPError if the REST API execution
      is unsuccessful.
    """
    req = self.session.prepare_request(request)

    # Execute the REST API call with the default timeout as 60 seconds.
    response = self.session.send(req, timeout=DEFAULT_TIMEOUT)

    # If the HTTP status code of the response is 401 or 403, refresh the API
    # tokens and retry the REST API call execution.
    if response.status_code in [
        status.STATUS_UNAUTHORIZED, status.STATUS_FORBIDDEN
    ]:
      try:
        self.refresh_auth_tokens()
        req = self.session.prepare_request(request)
        response = self.session.send(req, timeout=DEFAULT_TIMEOUT)

        # Raises HTTPError if the REST API execution is unsuccessful.
        response.raise_for_status()
        return response
      # If the `self.refresh_auth_tokens` method is not implemented in the child
      # class, this class will raise the NotImplementedError exception and the
      # REST API call response is returned.
      except NotImplementedError:
        return response
    else:
      response.raise_for_status()
      return response

  def handle_http_error(self, response: requests.Response):
    """Raise error for HTTP status codes except 200.

    Args:
      response (requests.Response): Response received from the API.

    Raises:
      HTTPError: Error raised for invalid status codes.
    """
    response_json = {}
    try:
      response_json = response.json()
      response.raise_for_status()
    except Exception as error:
      print(
          "Error occurred while retrieiving the OAuth token. "
          f"HTTP Status Code: {response.status_code} Error: {response_json}")
      raise error

  def __getattr__(self, request_method) -> Callable[..., requests.Response]:
    """Wrapper for the `_make_api_call` method.

    This method will allow making API calls using the class's object.
    For Ex.:
    >> obj = UsernamePasswordAuth("dummy", "dummy")
    >> obj.get(<url>) # This will make a get call to the API.

    Args:
      request_method (str): Type of request to execute (Ex: "get", "post").

    Returns:
      Callable: A function that makes the API call and returns the response.
    """

    def wrapper(*args, **kwargs):
      """Wrapper for api calls method.

      Args:
        *args: Any number of positional arguments.
        **kwargs: Any number of keyword arguments.

      Returns:
        request.Response: Response returned by the API.
      """
      request = requests.Request(request_method, *args, **kwargs)
      return self._make_api_call(request)

    return wrapper


class UsernamePasswordAuth(AuthMethod):
  """Initialize the session using the Basic authentication."""

  def __init__(self, username: str, password: str) -> None:
    """Constructor for UsernamePasswordAuth class.

    Args:
      username (str): Username for authentication.
      password (str): Password for authentication.
    """
    self.session.auth = (username, password)


class APIKeyAuth(AuthMethod):
  """Initialize the session using the API key authentication."""

  def __init__(self, api_key: str) -> None:
    """Constructor for APIKeyAuth class.

    Args:
      api_key (str): API Key to use for authentication.
    """
    self.session.headers["Authorization"] = api_key


class OAuthClientCredentialsAuth(AuthMethod):
  """Authenticate using OAuth client credentials."""

  def __init__(
      self,
      endpoint: str,
      client_id: str,
      client_secret: str,
      scope: Optional[str] = None,
      before_request: Optional[Callable[..., requests.Request]] = None,
  ) -> None:
    """Constructor for OAuthClientCredentialsAuth class.

    Args:
      endpoint (str): URL endpoint for authentication.
      client_id (str): Client ID used for authentication.
      client_secret (str): Client Secret.
      scope (Optional[str]): Scope of the authentication. This parameter
        provides a way to limit the amount of access that is granted to an
        access token.
      before_request (Optional[Callable[..., requests.Request]]): If provided,
        function will be executed before establishing session.
    """
    self.endpoint = endpoint
    self.client_id = client_id
    self.client_secret = client_secret
    self.scope = scope
    self.before_request = before_request
    self.get_oauth_token()

  def get_oauth_token(self) -> None:
    """Retrieve OAuth token using Client ID and Client Secret."""
    # OAuth type 'client_credentials' will return only the access token in the
    # response. The session needs to be created again once the access token is
    # expired
    data = {
        "grant_type": OAUTH_CLIENT_CREDENTIALS_GRANT_TYPE,
        "client_id": self.client_id,
        "client_secret": self.client_secret,
    }
    if self.scope:
      data["scope"] = self.scope

    request = requests.Request("post", url=self.endpoint, data=data)

    if self.before_request:
      request = self.before_request(request)
    session = requests.Session()
    response = session.send(request.prepare())

    if response.status_code == status.STATUS_OK:
      response = response.json()
      access_token = response["access_token"]
      self.session.headers.update({"Authorization": f"Bearer {access_token}"})
    else:
      self.handle_http_error(response)

  def refresh_auth_tokens(self) -> None:
    """Get the new OAuth token to resume the data collection."""
    print("Getting the new access token for API call execution.")
    self.get_oauth_token()


class OAuthPasswordGrantCredentialsAuth(AuthMethod):
  """Authenticate using OAuth username and password credentials."""

  def __init__(
      self,
      endpoint: str,
      username: str,
      password: str,
      client_id: str,
      scope: Optional[str] = None,
  ) -> None:
    """Constructor for OAuthPasswordGrantCredentialsAuth class.

    Args:
      endpoint (str): URL endpoint for authentication.
      username (str): Username used for authentication.
      password (str): Password used for authentication.
      client_id (str): Client ID used for authentication.
      scope (Optional[str]): Scope of the authentication. This parameter
        provides a way to limit the amount of access that is granted to an
        access token.
    """
    self.endpoint = endpoint
    self.username = username
    self.password = password
    self.client_id = client_id
    self.scope = scope
    self.get_oauth_token()

  def get_oauth_token(self) -> None:
    """Retrieve OAuth token to execute the REST API calls."""
    data = {
        "grant_type": OAUTH_CLIENT_CREDENTIALS_GRANT_TYPE,
        "username": self.username,
        "password": self.password,
        "client_id": self.client_id,
    }
    if self.scope:
      data["scope"] = self.scope
    response = requests.post(url=self.endpoint, data=data)
    if response.status_code == status.STATUS_OK:
      response = response.json()
      access_token = response["access_token"]
      self.session.headers.update({"Authorization": f"Bearer {access_token}"})
    else:
      self.handle_http_error(response)

  def refresh_auth_tokens(self) -> None:
    """Refresh OAuth token."""
    print("Trying to refresh the OAuth token.")
    self.get_oauth_token()


class HeaderAuth(AuthMethod):
  """Initialise the session by setting the username and password in headers."""

  def __init__(self, username: str, password: str) -> None:
    """Constructor for HeaderAuth class.

    Args:
      username (str): Username used for authentication.
      password (str): Password used for authentication.
    """
    user_pass = bytes(username + ":" + password, "utf-8")
    encoded_credentials = base64.b64encode(user_pass).decode("ascii")
    encoded_value = "Basic {}".format(encoded_credentials)
    headers = {"Authorization": encoded_value}
    self.session.headers.update(headers)


class OAuthJWTCredentialsAuth(AuthMethod):
  """Initialise the session using the OAuth JWT credentials."""

  def __init__(self, endpoint: str, claims, key, algorithm: str,
               headers) -> None:
    """Constructor for OAuthJWTCredentialsAuth class.

    Args:
      endpoint (str): URL endpoint for authentication.
      claims: Claims to encode.
      key: Key to use for encoding.
      algorithm (str): Algorithm to use for encoding.
      headers: Headers to be used while encoding.
    """
    self.endpoint = endpoint
    self.claims = claims
    self.key = key
    self.algorithm = algorithm
    self.headers = headers
    self.get_oauth_token()

  def get_oauth_token(self) -> None:
    """Retrieve OAuth token."""
    assertion_token = jwt.encode(
        self.claims, self.key, algorithm=self.algorithm, headers=self.headers)
    body = {
        "grant_type": OAUTH_JWT_AUTH_GRANT_TYPE,
        "assertion": assertion_token,
    }
    response = requests.post(self.endpoint, headers=self.headers, data=body)
    if response.status_code == status.STATUS_OK:
      response = response.json()
      access_token = response["access_token"]
      self.session.headers.update({"Authorization": f"Bearer {access_token}"})
    else:
      self.handle_http_error(response)

  def refresh_auth_tokens(self) -> None:
    """Refresh OAuth token."""
    print("Trying to refresh the OAuth token.")
    self.get_oauth_token()
