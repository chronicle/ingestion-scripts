"""Fetch Thinkst Canary audit logs and ingest into Chronicle."""

import os
import json
import requests
import datetime

from common import ingest

LOG_TYPE = "THINKST_CANARY"
CANARY_AUDIT_URL = "https://{console}.canary.tools/api/v1/audit_trail/fetch"
LAST_RUN_FILE = ".canary_last_run.json"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S UTC+0000"

def load_last_run_timestamp():
    try:
        if os.path.exists(LAST_RUN_FILE):
            with open(LAST_RUN_FILE, "r") as f:
                data = json.load(f)
                ts = data.get("last_run")
                if ts:
                    return datetime.datetime.strptime(ts, DATE_FORMAT).replace(tzinfo=datetime.timezone.utc)
    except Exception:
        pass
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(hours=1)

def save_last_run_timestamp(timestamp):
    with open(LAST_RUN_FILE, "w") as f:
        json.dump({"last_run": timestamp.strftime(DATE_FORMAT)}, f)

def get_canary_audit_logs(console_id, auth_token, since):
    url = CANARY_AUDIT_URL.format(console=console_id)
    params = {"auth_token": auth_token}
    response = requests.get(url, params=params)
    response.raise_for_status()

    raw_data = response.json()
    audit_events = raw_data.get("audit_trail", [])
    new_events = []

    for event in audit_events:
        event_time_str = event.get("timestamp", "")
        try:
            event_time = datetime.datetime.strptime(event_time_str, DATE_FORMAT).replace(tzinfo=datetime.timezone.utc)
            if event_time > since:
                new_events.append(event)
        except Exception:
            continue

    return new_events

def main(req=None):
    console_id = os.getenv("CANARY_CONSOLE_ID")
    auth_token = os.getenv("CANARY_AUTH_TOKEN")

    if not console_id or not auth_token:
        raise RuntimeError("Missing CANARY_CONSOLE_ID or CANARY_AUTH_TOKEN.")

    last_run_time = load_last_run_timestamp()
    events = get_canary_audit_logs(console_id, auth_token, last_run_time)

    if events:
        ingest.ingest(events, LOG_TYPE)
        print(f"[INFO] Ingested {len(events)} events.")
    else:
        print("[INFO] No new events found.")

    now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    save_last_run_timestamp(now)

if __name__ == "__main__":
    main()

