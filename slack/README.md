## DESCRIPTION
---

**This script is for fetching the audit logs from SLACK platform and ingesting to Chronicle.**

## PREREQUISITE
---

**List of Environment variables:**
| Variable | Description | Required | Default | Secret |
| --- | --- | --- | --- | --- |
| SLACK_ADMIN_TOKEN | Authentication token. | Yes | - | Yes |
| POLL_INTERVAL | Frequency interval(in minutes) at which the Cloud Function executes. This duration must be same as the cloud scheduler job. | No | 5 | No |
| CHRONICLE_CUSTOMER_ID | your customer UUID | Yes | - | No |
| CHRONICLE_REGION | add region, you can add 'US' as region and it is considered as default. | No | us | No |
| CHRONICLE_SERVICE_ACCOUNT | provide service account secret manager path for authenticating to chronicle. | Yes | - | Yes |
