"""Fetch GitHub audit logs and ingest into Chronicle."""

from datetime import datetime, timedelta, timezone
import os
import json
import requests

from common import ingest

GITHUB_API_URL = os.getenv("GITHUB_AUDIT_URL")
CHRONICLE_DATA_TYPE = "GITHUB"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
LAST_RUN_FILE = ".github_audit_last_run.json"

GITHUB_TOKEN = os.getenv("GITHUB_AUDIT_TOKEN")

def load_last_run_timestamp() -> datetime:
    if os.path.exists(LAST_RUN_FILE):
        with open(LAST_RUN_FILE, "r") as f:
            data = json.load(f)
            last_run_str = data.get("last_run", "")
            if last_run_str:
                return datetime.strptime(last_run_str, DATE_FORMAT).replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - timedelta(days=1)

def save_last_run_timestamp(timestamp: datetime) -> None:
    with open(LAST_RUN_FILE, "w") as f:
        json.dump({"last_run": timestamp.strftime(DATE_FORMAT)}, f)

def fetch_github_audit_logs(since: str):
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    url = f"{GITHUB_API_URL}?per_page=100&since={since}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"[ERROR] Failed to retrieve logs: {response.status_code} {response.text}")
        response.raise_for_status()
    logs = response.json()
    print(f"[INFO] Retrieved {len(logs)} GitHub audit logs.")
    return logs

def main():
    if not GITHUB_TOKEN or not GITHUB_API_URL:
        raise RuntimeError("GITHUB_AUDIT_TOKEN or GITHUB_AUDIT_URL is not set!")
    last_run_time = load_last_run_timestamp()
    since = last_run_time.strftime(DATE_FORMAT)
    print(f"[INFO] Fetching GitHub audit logs since {since}")
    logs = fetch_github_audit_logs(since)
    if logs:
        ingest.ingest(logs, CHRONICLE_DATA_TYPE)
        print(f"[INFO] Successfully ingested {len(logs)} log(s).")
    else:
        print("[INFO] No new events to ingest.")
    save_last_run_timestamp(datetime.now(timezone.utc))

if __name__ == "__main__":
    main()

