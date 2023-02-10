# Trend Micro Vision One

This script retrieves the audit logs from Trend Micro Vision One platform, and ingests them into the Chronicle platform.

## Platform Specific Environment Variables

| Variable | Description | Required | Default | Secret |
|---|---|---|---|---|
| POLL_INTERVAL | Frequency interval at which the function executes to get additional log data (in minutes). This duration must be the same as the Cloud Scheduler job interval. | No | 10 | No |
| TREND_MICRO_AUTHENTICATION_TOKEN | Path of the Google Secret Manager with the version, where the authentication token for Trend Micro Vision One Server is stored. | Yes | - | Yes |
| TREND_MICRO_DOMAIN | Trend Micro Vision One region where the service endpoint is located. For example: api.in.xdr.trendmicro.com | Yes | - | No |
| TREND_MICRO_DATA_TYPE | Type of data to ingest in Chronicle. Possible Values: AUDIT_LOGS, ALERTS. | No | AUDIT_LOGS, ALERTS | No |
