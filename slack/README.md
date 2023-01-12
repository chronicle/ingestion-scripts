# Slack

This script is for fetching the audit logs from SLACK platform and ingesting to Chronicle.

## Platform Specific Environment Variables
| Variable | Description | Required | Default | Secret |
| --- | --- | --- | --- | --- |
| SLACK_ADMIN_TOKEN | Authentication token. | Yes | - | Yes |
| POLL_INTERVAL | Frequency interval(in minutes) at which the Cloud Function executes. This duration must be same as the cloud scheduler job. | No | 5 | No |
