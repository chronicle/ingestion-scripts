# GreyNoise Google SecOps SIEM Integration

This integration enables seamless ingestion, parsing, and visualization of
GreyNoise threat intelligence Indicator data within Google SecOps SIEM. The
integration allows Google SecOps SIEM to receive real-time IP reputation data,
GNQL query results, and internet scanner intelligence from the GreyNoise API.

## The overall flow of the script:

- Deploying the script to Cloud Function
- Data collection using ingestion script from GreyNoise API
- GreyNoise data ingested into Google SecOps SIEM
- Collected data will be parsed through corresponding parsers in Google SecOps

## Prerequisites

- Google SecOps SIEM instance
- GreyNoise Intelligence platform (API Key)
- GCP Project with the below required permissions:
  - GCP user and project service account should have below permissions. Follow [these steps](#update-service-account-permission) to assign these permissions to the service account used for accessing other GCP services within your project.
    - Cloud Scheduler Job Runner
    - Secret Manager Secret Access
    - Storage Admin
    - Chronicle API Editor
    - Role Viewer
    - Cloud Run Invoker
- GCP Services
  - Before using the below services, ensure the [Google APIs](#google-apis) are enabled in your GCP project
  - Cloud Run Function (4-core CPU or higher is recommended)
  - GCS bucket
  - Secret Manager
  - Cloud Scheduler

## Automatic deployment of the required resources

This section explains the use of the provided bash script to automate the
deployment of the GreyNoise Intelligence ingestion function and related
resources within your GCP project.

### Prerequisites For Script Execution :

- Access to a GCP project with sufficient permissions to enable APIs, create service accounts, IAM bindings, GCS buckets, Cloud Functions, Cloud Scheduler jobs, and Secret Manager secrets.
- The Cloud Function source code packaged as a ZIP file in [this](#creating-zip-of-the-cloud-function) format, available on your local machine or accessible within the Cloud Shell environment.

### Steps:
1. **Open Google Cloud Shell**:
    - Navigate to the Google Cloud Console (https://console.cloud.google.com).
    - Click the "Activate Cloud Shell" in the upper right corner of the console. A terminal window will open within your browser.

2. **Create the Script File**:
    - Choose a name for the script, for example, `greynoise_deploy.sh`.
    - Use a text editor like nano to create the file in your Cloud Shell home directory: `nano greynoise_deploy.sh`

3. **Paste the Script Content**:
    - Copy the entire content of the bash script provided from GitHub repo.
    - Paste the script content into the nano editor. In Cloud Shell, you can typically right-click and select "Paste" or use Ctrl+Shift+V.

4. **Save and Exit**:
    - Press Ctrl+X to exit nano.
    - When prompted to save, press Y.
    - Press Enter to confirm the filename (`greynoise_deploy.sh`).

5. **Upload Your Cloud Function ZIP (if not already in Cloud Shell)**:
    - If your function ZIP file is on your local machine, you need to upload it to Cloud Shell.
    - Click the three-dot menu in the Cloud Shell terminal window.
    - Select "Upload" and choose your ZIP file. It will be uploaded to your Cloud Shell home directory. Note the filename.

6. **Make the Script Executable**:
    - Grant execute permissions to the script file: `chmod +x greynoise_deploy.sh`

7. **Run the Deployment Script**:
    - Execute the script: `./greynoise_deploy.sh`

8. **Follow the Prompts**:
    - The script will prompt you to enter various configuration details, such as:
      - GCP Project ID & Region
      - Local path to your Cloud Function ZIP file (e.g., `/home/username/your-function.zip`)
      - Chronicle Customer ID
      - Chronicle Region
      - GreyNoise API Key Value (this will be stored securely in Secret Manager)
      - Other optional environment variables.
    - Provide the requested information at each prompt. Required fields must be filled. Optional fields can be left blank to use defaults where applicable. These values can be obtained by following [these steps](#locate-environment-variables).

9. **Monitor the Output**:
    - The script will display progress messages, indicating which steps are being performed (e.g., enabling APIs, creating resources, deploying the function).
    - Error messages will be shown in red. If an error occurs, the script is designed to stop. Review the error message to troubleshoot.

10. **Post-Deployment**:
    - Once the script completes successfully, verify the resources in the GCP Console:
      - Check Cloud Functions to see your deployed function.
      - Check Cloud Scheduler to see the scheduled job.
      - Check GCS for the bucket and upload ZIP.
      - Check the Secret Manager for the GreyNoise API Key secret.
      - Review Cloud Logging for any function execution logs or errors.

## Manual deployment of the required resources

### Google APIs

Ensure the following Google APIs are enabled in your GCP project (via APIs & Services → Library).

| **Service**             | **APIs needs to enable**                                                                                                                                |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Google SecOps           | chronicle.googleapis.com                                                                                                                                |
| Cloud Functions         | cloudfunctions.googleapis.com<br>run.googleapis.com<br>cloudbuild.googleapis.com<br>artifactregistry.googleapis.com<br>logging.googleapis.com          |
| Cloud Scheduler         | cloudscheduler.googleapis.com<br>pubsub.googleapis.com                                                                                                  |
| Cloud Storage (Bucket)  | storage-component.googleapis.com                                                                                                                        |
| Secret Manager          | secretmanager.googleapis.com                                                                                                                            |

### Environment Variables

These values can be obtained by following steps: [Locate Environment Variables](#locate-environment-variables).

| **Variable** | **Description** | **Default value** | **Required** | **Secret Manager** |
|--------------|-----------------|-------------------|--------------|--------------------|
| CHRONICLE_CUSTOMER_ID | Google SecOps customer id. Navigate to settings in the Google SecOps console for the customer id. | - | Yes | No |
| CHRONICLE_REGION | A region where the Google SecOps instance is located. | us | No | No |
| CHRONICLE_PROJECT_NUMBER | Specifies the GCP project identifier associated with your Google SecOps environment. | - | Yes | No |
| GCP_BUCKET_NAME | Name of the created GCP bucket. | - | Yes | No |
| GREYNOISE_API_KEY | Copied resource name value of API KEY of GreyNoise from secret manager.<br><br>Generate an API Key from the GreyNoise platform's API key section. | - | Yes | Yes |
| QUERY | A query to filter GreyNoise Indicators. [More details](https://docs.greynoise.io/docs/using-the-greynoise-query-language-gnql).<br><br>Examples are below:<br>`actor:Censys classification:benign` | - | No | No |

### Creating zip of the cloud function

- Create a zip file with the contents of the following files:
  - Download the common directory from [Git repository](https://github.com/chronicle/ingestion-scripts/tree/main/common).
  - Download the contents of the greynoise ingestion script.
  - Create a zip in the following structure.
  ```
    ├── README.md
    ├── common
    │   ├── __init__.py
    │   ├── auth.py
    │   ├── auth_test.py
    │   ├── env_constants.py
    │   ├── ingest.py
    │   ├── ingest_test.py
    │   ├── ingest_v1.py
    │   ├── ingest_v1_test.py
    │   ├── status.py
    │   ├── utils.py
    │   └── utils_test.py
    ├── constant.py
    ├── exception_handler.py
    ├── main.py
    ├── main_test.py
    ├── requirements.txt
    ├── utility.py
    ├── utility_test.py
    ├── greynoise_client.py
    └── greynoise_client_test.py
  ```

### Using Secrets

- [Environment variables](#environment-variables) marked as secret must be configured as secrets on Google Secret Manager. [[REF]](https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets#create)
- Once the secrets are created on Secret Manager, use the secret's resource ID as the value for environment variables.

For example:
```bash
SECRET_KEY=projects/{project_id}/secrets/{secret_id}/versions/{version_id}
```

### Add the GreyNoise API Key in Secret Manager
1. Log in to the `https://console.cloud.google.com/` using valid credentials.
2. Navigate to `Secret Manager`.
3. Click on `Create Secret`.
4. Provide the name for the secret in the `Name` field (e.g., `greynoise_api_key`).
5. Provide your GreyNoise API key value in the `Secret Value` field.
6. Keep the other configurations as default, Click on the `Create Secret`
button.
Similarly, Create a secret for **Google SecOps Service Account**.

### Create a GCP Bucket

1. Log in to the [GCP Console](https://console.cloud.google.com/) using valid credentials.
2. Navigate to Buckets in GCP.
3. Click on the Create button.
4. Enter the name of the bucket.
5. Users can select the region and modify the optional parameters if required and then click on the Create button.

Copy the bucket name and provide it in the `GCP_BUCKET_NAME` environment
variable.

### Cloud Function Deployment

#### Command based deployment
1. Navigate to the bucket and open the bucket created for GreyNoise in [these](#create-a-gcp-bucket) steps. Upload the created cloud function [zip](#creating-zip-of-the-cloud-function) file in the bucket.
2. Click Activate Cloud Shell at the top right corner of the Google Cloud console.
3. Modify the below command based on your value and run in the terminal.

#### Command Format
```bash
gcloud functions deploy CLOUD_FUNCTION_NAME --set-env-vars “ENV_NAME1=ENV_VALUE1,ENV_NAME2=ENV_VALUE2,ENV_NAME3=ENV_VALUE3” --gen2 --runtime=python312 --region=REGION --source=SOURCE_OF_FUNCTION  --entry-point=main --service-account=SERVICE_ACCOUNT_EMAIL --trigger-http --no-allow-unauthenticated --memory=8GiB --timeout=3600s
```

* **CLOUD_FUNCTION_NAME**: Unique name of the cloud function.
* **REGION**: A region for your cloud function. (Ex : us-central1, us-west1, etc.)
* **SOURCE_OF_FUNCTION**: gsutil URI of the cloud function zip in cloud
storage. (e.g: gs://greynoise_test_bucket/greynoise_test.zip) where the
greynoise_test_bucket is the name of the created bucket and greynoise_test.zip
is the cloud function zip file.
* **SERVICE_ACCOUNT_EMAIL**: Email of the created service account of the project. Make sure the selected Service account must have a required permission. Update Service Account Permission [following these steps](#update-service-account-permission).
* **ENV_NAME1=ENV_VALUE1**: Name and value of the environment variable to be created. [Environment variables](#environment-variables)

#### Note:
When deploying a [Cloud Function](#cloud-function-deployment), ensure that the **--timeout** parameter in the deployment command matches the frequency specified in the [Cloud Scheduler](#configure-scheduler) **--schedule** parameter. Aligning these values prevents overlapping executions, which could lead to data duplication.

* For example, if you set --timeout=3600s when deploying the Cloud Function,
configure the Cloud Scheduler with: --schedule="*/60 * * * *".
* This ensures that each scheduled run starts only after the previous execution has completed.

#### Example Command,
```bash
gcloud functions deploy funcusingcmd --set-env-vars "CHRONICLE_CUSTOMER_ID=ed19f037-2354-43df-bfbf-350362b45844,CHRONICLE_PROJECT_NUMBER=2134567,CHRONICLE_REGION=us,GCP_BUCKET_NAME=greynoise_test_bucket,GREYNOISE_API_KEY=projects/1234567890/secrets/gn_api_key/versions/1," --gen2 --runtime=python312 --region=us-central1 --source=gs://gn_test_bucket/greynoise_test.zip  --entry-point=main --service-account=1234567890-compute@developer.gserviceaccount.com --trigger-http --no-allow-unauthenticated --memory=8GiB --timeout=3600s
```

### Configure Scheduler

#### Command based deployment
1. Click Activate Cloud Shell at the top right corner of the Google Cloud console.
2. Modify the below command based on your value and run in the terminal.

#### Command Format
```bash
gcloud scheduler jobs create http SCHEDULER_NAME --schedule="CRON_TIME" --uri="CLOUD_FUNCTION_URL" --attempt-deadline=30m --oidc-service-account-email=SERVICE_ACCOUNT_EMAIL --location=LOCATION --time-zone=TIME_ZONE
```

* **SCHEDULER_NAME**: Unique name of the cloud scheduler.
* **CRON_TIME**: Cron time format for the scheduler to run in every interval. (eg. */60 * * * *)
* **CLOUD_FUNCTION_URL**: URL of the created cloud function. Navigate to create cloud function details.
* **SERVICE_ACCOUNT_EMAIL**: Email of the created service account of the project. Make sure the selected Service account must have a required Permission. Update Service Account Permission [following these steps](#update-service-account-permission).
* **LOCATION**: A region for your connector. (Ex : us-central1, us-west1, etc)
* **TIME_ZONE**: The time zone of your region. (Ex : UTC)

#### Note:
When deploying a [Cloud Function](#cloud-function-deployment), ensure that the **--timeout** parameter in the deployment command matches the frequency specified in the [Cloud Scheduler](#configure-scheduler) **--schedule** parameter. Aligning these values prevents overlapping executions, which could lead to data duplication.

* For example, if you set --timeout=3600s when deploying the Cloud Function,
configure the Cloud Scheduler with: --schedule="*/60 * * * *".
* This ensures that each scheduled run starts only after the previous execution has completed.

#### Example Command,
```bash
gcloud scheduler jobs create http funcusingcmdschedular --schedule="*/60 * * * *" --uri="https://us-central1-test.cloudfunctions.net/funcusingcmd" --attempt-deadline=30m --oidc-service-account-email=1234567890-compute@developer.gserviceaccount.com --location=us-central1 --time-zone=UTC
```

### Update Service Account Permission
1. Open **GCP Console**, Then go to **IAM**.
2. In View By **Main Tab** > Click **GRANT ACCESS**.
3. Add Service Account name in **New Principals**. (Example : service_account_name.gserviceaccount.com)
4. In **Assign Role**, assign below roles to service accounts.
   * Cloud Scheduler Job Runner
   * Secret Manager Secret Access
   * Storage Admin
   * Chronicle API Editor
   * Cloud Run Invoker
   * Role Viewer
5. Click **Save**.

## Locate Environment Variables

### CHRONICLE_CUSTOMER_ID
**Steps to find:**
1. Log in to the GCP console (https://console.cloud.google.com).
2. From the GCP Navigation Menu, Navigate to **Security > Google SecOps**.
3. Expand **Instance details**.
4. Copy the **Customer ID** value.

### CHRONICLE_REGION
**Steps to find:**
1. Log in to the GCP console (https://console.cloud.google.com).
2. Navigate to **Security > Google SecOps**.
3. Expand **Instance details**.
4. Copy the **Region** value.

### CHRONICLE_PROJECT_NUMBER
**Steps to find:**
1. Log in to the GCP console (https://console.cloud.google.com).
2. On the home page you can find **Project number**.

### GCP_BUCKET_NAME
**Steps to find:**
1. Log in to the GCP console (https://console.cloud.google.com).
2. From the GCP Navigation Menu, **Cloud Storage > Buckets**.
3. Copy the bucket name (e.g., `greynoise-bucket`).

### GREYNOISE_API_KEY
**Steps to find:**
1. Navigate to: https://viz.greynoise.io/account/api-key
2. Copy the **API Key**.

### QUERY
**Steps to find:**
1. Refer to the [GreyNoise Query Language documentation](https://docs.greynoise.io/docs/using-the-greynoise-query-language-gnql).
2. Construct your query based on filtering requirements.

### Limitations

* We suggest using the second generation of Cloud Function. The first
generation of Cloud Function has a maximum execution time of 9 minutes and the
second generation of Cloud Function has a maximum execution time of 60 minutes. If the execution time of the Cloud Function exceeds timeout then there are chances that the complete data won’t be ingested in the Google SecOps.
* The rate limit for a GreyNoise account depends on the user's subscription
tier (Community, Enterprise, etc.). Based on this API rate limit, the
integration will be able to collect data and ingest into Google SecOps. Once
the API rate limit is exceeded, data collection will only resume when the limit
is reset after a specific interval.

* The Google SecOps Ingestion API has a payload limit of 1 MB. Logs exceeding
this limit will not be ingested and will be skipped. To minimize data loss,
please ensure that log sizes remain within the allowed limit.
* If an optional environment variable is not provided during the Cloud Function deployment, default values will be used, and data collection will start accordingly.
* The chunk limit for data collection is set to 100 to minimize data duplication in case of errors during ingestion, as the Google SecOps Ingestion API processes data in chunks of 100.
* We recommend setting the timeout in the RUNTIME variable to the maximum value (3600) to prevent the Cloud Function from terminating during data collection.

### Known Behaviors

* When Cloud Run functions execute for more than 30 minutes, Cloud Scheduler
will show a "Failed" status with 504 Gateway Timeout errors. This is expected
behavior and does not indicate actual function failure. The Cloud Run function
continues execution despite the timeout in Cloud Scheduler.

**Error Message Example:**
```
ERROR <timestamp> [httpRequest.requestMethod:POST] [httpRequest.status: 504] [httpRequest.responseSize: 72 B] [httpRequest.latency:1,799.798 s] [httpRequest.userAgent:Google-Cloud-Scheduler] https://<cloud_function_uri>
```

### Troubleshooting
This section describes the common issues that might happen during the
deployment or the running of the app and the steps to resolve the issues.

1. GCloud logs can be used for troubleshooting.
    1. Log in to the `https://console.cloud.google.com/` using valid credentials.
    1. Navigate to 'Cloud functions' and click on the deployed function where you can find the logs module.
    1. Logs can be filtered using severity.

    **Currently, this logs feature is disabled by the google team in some GCP
    projects. We are currently checking with the google team regarding this.**
2. If you test the cloud function immediately after deploying it on gcloud, It
might be possible that the cloud function will not work as expected. To resolve
this, wait for a few seconds and then test it.
3. If the cloud function stops its execution because memory exceeds the limit, reconfigure the cloud function’s memory configuration and increase the memory limit.
4. If you notice duplicate events or overlapping Cloud Function executions, ensure that the --timeout parameter in [Cloud Function](#cloud-function-deployment) command and --schedule parameter in [Cloud Scheduler](#configure-scheduler) deployment command should be the same.
<br> **For example,** if you set --timeout=3600s when deploying the Cloud
Function, configure the Cloud Scheduler with: --schedule="*/60 * * * *".

### Resources

- [Cloud Function](https://cloud.google.com/functions)
- [Cloud Scheduler](https://cloud.google.com/scheduler/docs/overview)
- [Cloud Secret Manager](https://cloud.google.com/security/products/secret-manager)
- [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install)
- [Deploying cloud functions from local machine](https://cloud.google.com/functions/docs/deploying/filesystem)
- [Google SecOps Ingestion API Payload Limit](https://cloud.google.com/chronicle/docs/reference/ingestion-api#unstructuredlogentries)
- [GreyNoise Documentation](https://docs.greynoise.io/)
- [GreyNoise GNQL Documentation](https://docs.greynoise.io/docs/using-the-greynoise-query-language-gnql)