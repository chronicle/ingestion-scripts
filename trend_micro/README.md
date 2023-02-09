# Trend Micro

This script retrieves the security logs from Trend Micro platform, and ingests them into the Chronicle platform.

## Platform Specific Environment Variables

| Variable | Description | Required | Default | Secret |
|---|---|---|---|---|
| POLL_INTERVAL | Frequency interval at which the function executes to get additional log data (in minutes). This duration must be the same as the Cloud Scheduler job interval. | No | 10 | No |
| CHRONICLE_DATA_TYPE | Log type according to the service to push data into the Chronicle platform. | Yes | - | No |
| TREND_MICRO_AUTHENTICATION_TOKEN | Path of the Google Secret Manager with the version, where the authentication token for Trend Micro Server is stored. | Yes | - | Yes |
| TREND_MICRO_SERVICE_URL | Service URL of the Cloud App Security service. | Yes | - | No |
| TREND_MICRO_SERVICE | The name of the protected service, whose logs to retrieve. Supports comma-separated values. Possible values: exchange, sharepoint, onedrive, dropbox, box, googledrive, gmail, teams, exchangeserver, salesforce_sandbox, salesforce_production, teams_chat. | No | exchange, sharepoint, onedrive, dropbox, box, googledrive, gmail, teams, exchangeserver, salesforce_sandbox, salesforce_production, teams_chat | No |
| TREND_MICRO_EVENT | The type of the security event, whose logs to retrieve. Supports comma-separated values. Possible values: securityrisk, virtualanalyzer, ransomware, dlp. | No | securityrisk, virtualanalyzer, ransomware, dlp | No |
