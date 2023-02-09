# Tenable IO

This script retrieves the Assets and Vulnerabilities from Tenable.io, and ingest them into the Chronicle platform.

## Platform Specific Environment Variables

| Variable                | Description                                   | Required | Default                 | Secret |
|-------------------------|-----------------------------------------------|----------|-------------------------|--------|
| POLL_INTERVAL           | Frequency interval (in minutes) at which the Cloud Function executes. This duration must be same as the Cloud Scheduler job.                                                  | No       | 360                     | No     |
| TENABLE_ACCESS_KEY      | The access key to be used for authentication. | Yes      | -                       | No     |
| TENABLE_SECRET_KEY_PATH | Path of the Google Secret Manager with the version, where the password for Tenable server is stored.                                                                   | Yes      | -                       | Yes    |
| TENABLE_DATA_TYPE       | Type of data to fetch from Tenable. Supported data types are ASSETS and VULNERABILITIES.                                                          | No       | ASSETS, VULNERABILITIES | No     |
| TENABLE_VULNERABILITY   | The state of vulnerabilities to fetch from Tenable. Supported states are OPEN, REOPENED, and FIXED.                                                                    | No       | OPEN, REOPENED          | No     |
