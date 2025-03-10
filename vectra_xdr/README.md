# Vectra XDR Google SecOps Integration

This integration aims to enable seamless ingestion, parsing, and
visualization of Vectra network intelligence data within Google SecOps SIEM.
This integration will allow Google SecOps SIEM to receive real-time
detections, hosts, accounts, health, audit, and lockdown data from Vectra
using Vectra API , enriching the SIEM’s threat detection and response
capabilities with comprehensive network data.

### The overall flow of the script:

- Deploying the script to Cloud Function
- Data collection using ingestion script from the Google SecOps
- Vectra data ingested into Google SecOps
- Collected data will be parsed through corresponding parsers in Google SecOps

### Pre-Requisites

- Google SecOps console and Google SecOps service account.
- Vectra credentials (Vectra Portal URL, API Client, API Secret)
- GCP Project with the below required permissions:
  - GCP user and project service account should have Owner permissions
- GCP Services
  - Cloud function (4-core CPU or higher is recommended for cloud function configuration)
  - GCS bucket
  - Secret Manager
  - Cloud Scheduler

### Environment Variables

| **Variable** | **Description** |  **Required** | **Type** | **Default** | **Secret** |
| --- | --- | --- | --- | --- | --- |
| VECTRA_PORTAL_URL | Vectra Portal URL. | Yes | string | - | No |
| CLIENT_ID | Copied resource name value of Client ID generated from API Client. | Yes | string| -  | Yes|
| SECRET_KEY | Copied resource name value of Secret Key generated from API Client. | Yes | string| -  | Yes|
| CHRONICLE_CUSTOMER_ID | Google SecOps Platform Customer ID. | Yes | string| -  | No |
| CHRONICLE_SERVICE_ACCOUNT | Copied resource name value of service account secret from the secret manager. | Yes | string| -  | Yes|
| GCP_BUCKET_NAME |  Name of the created GCP bucket. | Yes | string| -  | No |
| GCP_PROJECT_NUMBER | GCP project number where secrets are created. | Yes | string| - | No |
| CHRONICLE_REGION | Google SecOps platform region. | No | string | us | No |
| INCLUDE_TRIAGED | Whether to include Detection events that have been triaged. | No | bool | false | No |
| INCLUDE_SCORE_DECREASES | Whether to include a score decreases the entity events. | No | bool | false | No |
| INCLUDE_INFO_CATEGORY | Whether to include Detection events with info category. | No | bool | true | No |
| VLANS | Configure v_lans for Health data. | No | bool | false | No |
| HISTORICAL | If set true, collect 24Hr Historical data. | No  | bool | false | No |
| ENABLE_SCORING | Enables the ingestion and processing of scoring events. | No | bool | true | No |
| ENABLE_DETECTIO | Enables the ingestion and processing of detection events. | No | bool | true | No |
| ENABLE_HEALTH | Enables the ingestion and processing of health events. | No | bool  | true | No |
| ENABLE_AUDIT | Enables the ingestion and processing of audit events. | No | bool  | true | No |
| ENABLE_LOCKDOWN | Enables the ingestion and processing of lockdown events. | No | bool | true | No |

### Creating zip of the cloud function
Create a zip file of the cloud function with the contents of the following
files:

1. Contents of the ingestion script (i.e. `vectra_xdr`)
2. `common` directory

### Using Secrets

- Environment variables marked as secret must be configured as secrets on Google Secret Manager.
- Once the secrets are created on Secret Manager, use the secret's resource ID as the value for environment variables.

For example:
CHRONICLE_SERVICE_ACCOUNT:
projects/{project_id}/secrets/{secret_id}/versions/{version_id}

### Create a GCP Bucket

1. Log in to the [GCP Console]("https://console.cloud.google.com/) using valid credentials.
2. Navigate to Buckets in GCP.
3. Click on the Create button.
4. Enter the name of the bucket.
5. Users can select the region and modify the optional parameters if required and then click on the Create button.

Copy the bucket name and provide it in the GCP_BUCKET_NAME environment variable.

### Cloud Function Deployment
1. Log in to the [GCP Console]("https://console.cloud.google.com/) using valid credentials.
2. Navigate to the ‘Cloud Functions’
3. Click on Create Function. Set the configuration section. Add environment, function name, region.
   1. Select Cloud Run function in the Environment dropdown.
   2. Enter the unique function name and select your region from the region dropdown
   3. Keep Require Authentication as selected in the Trigger section.
4. Click on the dropdown for Runtime, build, connections, and security settings.
5. Select the below options in the RUNTIME.
   - Memory allocated - 8 GiB (Recommended)
   - CPU (preview) - 4 (Recommended)
   - Timeout - 3600 seconds
   - Keep autoscaling configurations as default.
   - Concurrency - 1
   - Service account - Select your current GCP project service account
   - Click on 'Add Variables' and add the environment variables. Ensure you include the secret resource ID for any variable where 'Secret' is set to 'Yes'.
6. Click on next and Go to the Code upload section.
7. Select Python 3.12 in the Runtime dropdown.
8. Select ZIP Upload from the Source code.
9. Keep the entry point as main.
10. Select the created bucket in the Destination bucket dropdown.
11. Browse and select the downloaded application zip.
12. Click on the Deploy button.

After a few minutes, the cloud function will be deployed successfully.

### Configure Scheduler

1. Log in to the [GCP Console]("https://console.cloud.google.com/) using valid credentials.
2. Navigate to 'Cloud scheduler'.
3. Click on 'Create a Job'.
4. Enter a unique name for the scheduler and select your region in Region.
5. Enter the unix-cron format for the Frequency, when the scheduler job should invoke. Sample value( */20 * * * *). It is recommended to set the frequency to a minimum of 5 minutes and not less, as there are five types of events being collected and ingested.
6. Select the timezone and click on 'Continue'.
7. Select the target type as "HTTP".
8. In the GCP Cloud interface, navigate to created cloud function details and under trigger sections and copy the trigger URL of the cloud function that the user creates a scheduler and paste it into the URL.
9. Keep POST as it is in the HTTP method.
10. Select "Add OIDC Token" in Auth Header.
11. In the service account field, select your current GCP project service account.
12. Enter 30m in the Attempt deadline config.
13. Click on the 'Create' button.

Cloud function will be executed as per the frequency provided in the Cloud
Scheduler.

### View Events in Google SecOps
1. Log in to Google SecOps:
   - Open a web browser and navigate to the Google SecOps instance URL. For example: https://test.backstory.chronicle.security/
   - Replace test with your actual Google SecOps instance name.
2. Access SIEM Search:
   - From the top left corner of the Google SecOps console, select the "Investigation" option.
   - Within the Investigation section, choose "SIEM Search".
3. Filter Events by Log Type:
   - In the SIEM Search interface, locate the "UDM Search" section.
   - Apply a filter for the metadata field "log_type". Set the filter value to metadata.log_type="VECTRA_XDR".
4. View Vectra Events:
   - The SIEM Search results will display Vectra events within the "Events" section.

## Resources

- [Cloud Function](https://cloud.google.com/functions)
- [Cloud Scheduler](https://cloud.google.com/scheduler/docs/overview)
- [Cloud Secret Manager](https://cloud.google.com/security/products/secret-manager)
