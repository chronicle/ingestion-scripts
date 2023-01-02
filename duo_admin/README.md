# Duo Admin
---

**This script is for fetching the logs from DUO platform and ingesting to Chronicle.**


## List of Environment variables:

| Variable                  | Description                                                                                  | Required | Default | Secret |
| ------------------------- | -------------------------------------------------------------------------------------------- | -------- | ------- | ------ |
| CHRONICLE_CUSTOMER_ID     | your customer UUID.                                                                          | Yes      | -       | No     |
| CHRONICLE_REGION          | add region, you can add 'US' as region and it is considered as default.                      | No       | us      | No     |
| CHRONICLE_SERVICE_ACCOUNT | provide service account secret manager path for authenticating to chronicle.                 | Yes      | -       | Yes    |
| DUO_API_DETAILS           | Content of DUO account JSON file.                                                            | Yes      | -       | Yes    |
| POLL_INTERVAL             | Fetch within the last x amount of time, where x can be defined in minutes (for example : 30) | Yes      | -       | No     |
