# Palo Alto Cortex XDR

This script retrieves the Palo Alto Cortex XDR exported logs from the google cloud bucket and ingest them in Chronicle.
The Palo Alto Cortex XDR exported log file is a gzipped multiple lines of JSON.

## Platform Specific Environment Variables

| Variable | Description | Required | Default | Secret |
|---|---|---|---|---|
| POLL_INTERVAL | Frequency interval at which the function executes to get additional log data (in minutes). This duration must be the same as the Cloud Scheduler job interval. | No  | 60 | No |
| GCS_BUCKET_NAME | Name of the GCS Bucket from which to fetch the data. | Yes | - | No |
| GCP_SERVICE_ACCOUNT_SECRET_PATH | Path to the secret in Secret Manager that stores the GCP Service Account JSON file. | Yes | - | Yes |
| CHRONICLE_DATA_TYPE | Log type to push data into the Chronicle platform. | Yes | - | No |
