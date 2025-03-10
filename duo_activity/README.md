# Duo Activity

This script is for fetching the logs API calls from DUO platform.
Furthermore, the collected data will be ingested into Chronicle and parsed by corresponding parsers.

### The overall flow of the script:
- Deploying the script to Cloud Function
- Data collection using ingestion script
- Ingest collected data into Chronicle
- Collected data will be parsed through corresponding parsers in Chronicle

### Pre-Requisites
- Chronicle console and Chronicle service account.
- Duo Activity API credentials (API url, API key)
- GCP Project with the below required permissions:
  - GCP user and project service account should have Owner permissions
- GCP Services
   - Cloud function
   - Secret Manager
   - Cloud Scheduler

### Environment Variables

| Variable | Description | Required | Default | Secret |
| --- | --- | --- | --- | --- |
| CHRONICLE_CUSTOMER_ID | Chronicle customer Id. | Yes | - | No |
| CHRONICLE_REGION | Chronicle region. | Yes | us | No |
| SERVICE_ACCOUNT_FILE | Path of the Google Secret Manager with the version, where the Service Account is stored. | Yes | - | Yes |
| CHRONICLE_NAMESPACE | The namespace that the Chronicle logs are labeled with. | No | - | No |
| BACKSTORY_API_V1_URL | Duo Activity API URL | Yes | - | No |
| DUO_SECRET_KEY | Duo secret key required to authenticate. | Yes | - | Yes |
| DUO_INTEGRATION_KEY | Duo integration key required to authenticate. | Yes | - | Yes |
| LOG_FETCH_DURATION | The total duration for which the logs are fetched in one API call | No | 1 | No |
| CHECKPOINT_FILE_PATH | The path of file where checkpoint timestamp information is stored | No | checkpoint.json | No |

### Setting up the directory
Create a zip file of the cloud function with the contents of the following files:

1. *Content*s of the ingestion script (i.e. `duo_activity`)
2. `common` directory

### Setting the required runtime environment variables

Edit the .env.yml file to populate all the required environment variables.
Information related to all the environment variables can be found in the
README.md file.

#### Using secrets

Environment variables marked as **Secret** must be configured as secrets on
Google Secret Manager. Refer [this](https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets#create)
page to learn how to create secrets.

Once the secrets are created on Secret Manager, use the secret's resource name
as the value for environment variables. For example:

```
CHRONICLE_SERVICE_ACCOUNT: projects/{project_id}/secrets/{secret_id}/versions/{version_id}
```

#### Configuring the namespace

The namespace that the Chronicle logs are ingested into can be configured by
setting the `CHRONICLE_NAMESPACE` environment variable.

### Deploying the cloud function

The directory containing duo_activity ingestion script should be uploaded as a ZIP file in the Source code field in the Google Cloud Console. 
Refer [this](https://cloud.google.com/functions/docs/console-quickstart)
page to learn how to create and deploy a cloud function.

