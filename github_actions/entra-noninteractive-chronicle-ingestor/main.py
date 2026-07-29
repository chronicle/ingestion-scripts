# chronicle-scripts/entra-noninteractive-chronicle-ingestor/main.py

import os
import requests
from common import ingest, utils

LOG_TYPE = "AZURE_AD"
GRAPH_URL = "https://graph.microsoft.com/beta/auditLogs/signIns"

def get_token():
    print("[INFO] Requesting access token...")
    tenant_id = os.getenv("GRAPH_TENANT_ID")
    client_id = os.getenv("GRAPH_CLIENT_ID")
    client_secret = os.getenv("GRAPH_CLIENT_SECRET")

    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }

    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()["access_token"]

def fetch_signins(access_token, since):
    print("[INFO] Fetching non-interactive sign-ins from Microsoft Graph (beta)...")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    filter_time = since.isoformat()
    params = {
        "$filter": f"createdDateTime ge {filter_time} and signInEventTypes/any(t:t eq 'nonInteractiveUser')",
        "$top": 100
    }

    all_logs = []
    response = requests.get(GRAPH_URL, headers=headers, params=params)
    response.raise_for_status()

    data = response.json()
    all_logs.extend(data.get("value", []))

    print(f"[INFO] Retrieved {len(all_logs)} non-interactive sign-ins.")
    return all_logs

def main():
    print("[INFO] Starting Microsoft Entra ingestion for non-interactive sign-ins...")

    access_token = get_token()
    since = utils.get_last_run_at()  # Default 5 mins or POLL_INTERVAL
    logs = fetch_signins(access_token, since)
    ingest.ingest(logs, LOG_TYPE)

if __name__ == "__main__":
    main()
