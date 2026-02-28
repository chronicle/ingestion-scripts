# Ingestion functions intended to retrieve data payloads
# from the CyberArk Audit service, split them, and then
# send them to the appropriate backend receiver for Google
# SecOps SIEM.

"""Fetch logs from the CyberArk Audit API and ingest them to SecOps."""

import json
import base64
from datetime import datetime, timezone

# from google.cloud import storage

# from common import ingest
# from common import utils
import requests

# CyberArk Identity Basic Auth. ID
CYBERARK_OAUTH_CLIENT_ID = input("id")
# CyberArk Identity Basic Auth. Secret
CYBERARK_OAUTH_CLIENT_SECRET = input("secret")
# CyberArk Audit API Key
CYBERARK_AUDIT_API_KEY = ""
# CyberArk Identity Base URL for the SIEM Integration WebApp
CYBERARK_IDENTITY_SIEM_APP_URL = input("url")
# CyberArk Audit Base URL
CYBERARK_AUDIT_BASEURL = ""
# Google Storage Account Name
GCP_BUCKET_NAME = ""

# Function to retrieve the last range of logs from the Google Storage location
# def get_last_range() -> str:


# Function to construct and return a valid query body for the Audit API to ingest and receive
def build_query_body(start_date: str) -> str:
    print("Building the Audit query... ")

    now_utc = datetime.now(timezone.utc)
    current_date = now_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    print(current_date)

    query = {
        "filterModel": {
            "date": {
                "dateFrom": start_date,
                "dateTo"  : current_date
            }
        }
    }

    query_json = json.dumps(query, indent=3)

    return query_json



# Function to authenticate to the CyberArk SIEM Web Application in Identity and retrieve an Auth Token
def get_identity_siem_auth(client_id: str, client_secret: str, siem_url: str) -> str:
    print("Authenticating to Identity's SIEM WebApplication... ")

    secret_header_value_b64 = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")

    id_headers = {
        "Authorization" : f"Basic {secret_header_value_b64}",
        "Content-Type": "application/x-www-form-urlencoded"
    
    }

    id_body = {
        "grant_type" : "client_credentials",
        "scope"      : "isp.audit.events:read"
    }

    try:
        identity_response = requests.post(
            url=siem_url,

            data=id_body,

            headers=id_headers
        )

        if identity_response.status_code == 200:
            
            token_data = identity_response.json()

            return token_data.get("access_token")

    except requests.exceptions.RequestException as exc:
        print("Network/HTTP error:", str(exc))

    


# Function to retrieve a CursorRef from Audit that represents the query for the range assigned
# def get_cursor_ref(identity_token: str) -> str:



# Function to use the CursorRef to retrieve the actual log payload
# def get_log_data(identity_token: str, cursor_ref: str, audit_api_key: str) -> str:



# Function to tag and send the logs to SecOps
# def send_log(log_json: str) -> str:



# Function to update the Google BLOB with the new data/time range
# def update_range() -> None:



# Main function
def main():
    token = get_identity_siem_auth(CYBERARK_OAUTH_CLIENT_ID, CYBERARK_OAUTH_CLIENT_SECRET, CYBERARK_IDENTITY_SIEM_APP_URL)
    print(token)

if __name__ == "__main__":
    main()
