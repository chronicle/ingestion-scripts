# DESCRIPTION
---

**This script is for fetching the logs from MISP platform and ingesting to chronicle.**


# PREREQUISITE
---

**List of Environment variables:**

* **TARGET_SERVER**
  * Description: your IP address , getting after creating MISP instance.
  * where can we get: From MISP platform link.
  * data_type: str

* **API_KEY**
  * Description: pass API key's secret manager path to authentication.
  * Where can we get: After login to MISP GUI API_KEY is generated. we can found on:
      MISP platform > Home > Administration > List Users
  * It has no expiration.
  * data_type: str

* **POOL_INTERVAL**
  * Description: Fetch within the last x amount of time, where x can be defined in minutes(for example : 30m)
  * data_type: str

* **CHRONICLE_CUSTOMER_ID** 
  * Description: your customer UUID
  * data_type: str

* **CHRONICLE_REGION**
  * Description: add region, you can add 'US' as region and it is considered as default.
  * data_type: str

* **ORG_NAME**
  * Description: organization name for filtering events.
  * data_type: str

* **CHRONICLE_SERVICE_ACCOUNT**
  * Description: provide service account secret manager path for authenticating to chronicle.
  * data_type: str


## Steps required to run this code

1. Add above mentioned Environment variable in .env.yml file.
2. And you are ready to deploy the code.


# REFERENCES
---

MISP  reference link : https://www.misp-project.org/openapi
Ingestion reference link: https://cloud.google.com/chronicle/docs/reference/ingestion-api#unstructuredlogentries
