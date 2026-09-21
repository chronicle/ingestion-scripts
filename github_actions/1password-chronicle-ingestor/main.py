import os
import requests
from datetime import datetime, timezone
from common import ingest, env_constants, utils

CHRONICLE_LOG_TYPE = "ONEPASSWORD"
EVENTS_API_URL = os.getenv("EVENTS_API_URL")
ONEPASSWORD_TOKEN = os.getenv("ONEPASSWORD_TOKEN")

def fetch_events(start_time: datetime):
    headers = {
        "Authorization": f"Bearer {ONEPASSWORD_TOKEN}",
        "Content-Type": "application/json"
    }

    iso_since = start_time.replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
    body = {
        "limit": 1000,
        "since": iso_since
    }

    print(f"[INFO] Fetching 1Password events since {iso_since} from {EVENTS_API_URL}")
    response = requests.post(EVENTS_API_URL, headers=headers, json=body)
    response.raise_for_status()

    data = response.json()
    print(f"[INFO] Retrieved {len(data.get('items', []))} events from 1Password.")
    return data.get("items", [])

def main():
    last_run_time = utils.get_last_run_at()
    logs = fetch_events(last_run_time)
    ingest.ingest(logs, CHRONICLE_LOG_TYPE)
    print("[INFO] Ingestion completed.")

if __name__ == "__main__":
    main()
