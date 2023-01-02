# DESCRIPTION
---

**This script is for fetching the logs from MISP platform and ingesting to Chronicle.**


# PREREQUISITE
---

**List of Environment variables:**


## Platform Specific Environment Variables

| Variable                  | Description                                                                                  | Required | Default | Secret |
| ------------------------- | -------------------------------------------------------------------------------------------- | -------- | ------- | ------ |
| TARGET_SERVER             | Your IP address, getting after creating MISP instance.                                       | Yes      | -       | No     |
| API_KEY                   | Pass API key's secret manager path to authentication.                                        | Yes      | -       | Yes    |
| POLL_INTERVAL             | Frequency interval(in minutes) at which the Cloud Function executes. This duration must be same as the cloud scheduler job. | No      | 5       | No     |
| ORG_NAME                  | Organization name for filtering events.                                                      | Yes      | -       | No     |
| CHRONICLE_CUSTOMER_ID     | Your customer UUID.                                                                          | Yes      | -       | No     |
| CHRONICLE_REGION          | Add region, you can add 'US' as region and it is considered as default.                      | No       | us      | No     |
| CHRONICLE_SERVICE_ACCOUNT | Provide service account secret manager path for authenticating to Chronicle.                 | Yes      | -       | Yes    |


## Steps required to run this code

1. Add above mentioned Environment variable in .env.yml file.
2. And you are ready to deploy the code.


# REFERENCES
---

[MISP reference link](https://www.misp-project.org/openapi)<br>
[Ingestion reference link](https://cloud.google.com/chronicle/docs/reference/ingestion-api#unstructuredlogentries)