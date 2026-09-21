import os
import snowflake.connector
from datetime import datetime
from common import ingest, utils

LOG_TYPE = "SNOWFLAKE"

VIEW_TIMESTAMP_COLUMNS = {
    "LOGIN_HISTORY": "EVENT_TIMESTAMP",
    "QUERY_HISTORY": "START_TIME",
    "ACCESS_HISTORY": "QUERY_START_TIME",
    "TASK_HISTORY": "QUERY_START_TIME",
    "MATERIALIZED_VIEW_REFRESH_HISTORY": "START_TIME",
    "PIPE_USAGE_HISTORY": "START_TIME",
    "REPLICATION_USAGE_HISTORY": "START_TIME",
    "WAREHOUSE_LOAD_HISTORY": "START_TIME",
    "WAREHOUSE_METERING_HISTORY": "START_TIME",
}

def connect_to_snowflake():
    print("[INFO] Connecting to Snowflake...")
    return snowflake.connector.connect(
        user=os.getenv("SNOWFLAKE_USER"),
        password=os.getenv("SNOWFLAKE_PASSWORD"),
        account=os.getenv("SNOWFLAKE_ACCOUNT"),
        warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
        role=os.getenv("SNOWFLAKE_ROLE"),
        database="SNOWFLAKE",
        schema="ACCOUNT_USAGE"
    )

def fetch_view_data(conn, view_name, since):
    timestamp_column = VIEW_TIMESTAMP_COLUMNS.get(view_name)
    if not timestamp_column:
        print(f"[WARNING] No timestamp column configured for view {view_name}")
        return []

    query = f"""
    SELECT *
    FROM SNOWFLAKE.ACCOUNT_USAGE.{view_name}
    WHERE {timestamp_column} >= DATEADD(minute, -15, CURRENT_TIMESTAMP())
    """

    cursor = conn.cursor()
    try:
        cursor.execute(query)
        query_id = cursor.sfqid
        print(f"[INFO] Querying: {view_name}")
        print(f"[INFO] Snowflake Query ID: {query_id}")

        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        logs = [dict(zip(columns, row)) for row in rows]

        for log in logs:
            log["log_source"] = view_name

        print(f"[INFO] Retrieved {len(logs)} rows from {view_name}.")
        return logs
    except Exception as e:
        print(f"[ERROR] Fetching from {view_name}: {e}")
        return []
    finally:
        cursor.close()

def serialize_for_json(obj):
    if isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_for_json(i) for i in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    return obj

def main():
    print("[INFO] Starting Snowflake audit ingestion...")
    conn = connect_to_snowflake()

    all_logs = []
    for view in VIEW_TIMESTAMP_COLUMNS:
        logs = fetch_view_data(conn, view, utils.get_last_run_at())
        print(f"[INFO] Ingesting {len(logs)} logs from {view}")
        all_logs.extend([serialize_for_json(log) for log in logs])

    ingest.ingest(all_logs, LOG_TYPE)

if __name__ == "__main__":
    main()

