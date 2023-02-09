# Aruba Central

This script fetches audit logs from Aruba Central platform and ingests them into Chronicle.

## Platform Specific Environment Variables

| Variable | Description | Required | Default | Secret |
| --- | ---| --- | --- | --- |
| ARUBA_CLIENT_ID |Aruba Central API gateway client ID. | Yes | - | No |
| ARUBA_CLIENT_SECRET_SECRET_PATH | Aruba Central API gateway client secret. | Yes | - | Yes |
| ARUBA_USERNAME | Username of Aruba Central platform. | Yes | - | No |
| ARUBA_PASSWORD_SECRET_PATH | Password of Aruba Central platform. | Yes | - | Yes |
| ARUBA_BASE_URL | Base URL of Aruba Central API gateway. | Yes | - | No |
| ARUBA_CUSTOMER_ID | Customer ID of Aruba Central platform. | Yes | - | No |
| POLL_INTERVAL | Frequency interval at which the function executes to get additional log data (in minutes). This duration must be the same as the Cloud Scheduler job interval. | Yes | 10 | No |