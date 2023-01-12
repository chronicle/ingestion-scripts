# Malware Information Sharing Platform

This script is for fetching the logs from MISP platform and ingesting to Chronicle.

## Platform Specific Environment Variables
| Variable                  | Description                                                                                  | Required | Default | Secret |
| ------------------------- | -------------------------------------------------------------------------------------------- | -------- | ------- | ------ |
| TARGET_SERVER             | Your IP address, getting after creating MISP instance.                                       | Yes      | -       | No     |
| API_KEY                   | Pass API key's secret manager path to authentication.                                        | Yes      | -       | Yes    |
| POLL_INTERVAL             | Frequency interval(in minutes) at which the Cloud Function executes. This duration must be same as the cloud scheduler job. | No      | 5       | No     |
| ORG_NAME                  | Organization name for filtering events.                                                      | Yes      | -       | No     |
