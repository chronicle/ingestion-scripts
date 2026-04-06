# Cyjax Google SecOps SIEM Integration

This integration enables seamless ingestion, parsing, and visualization of Cyjax
threat intelligence Indicator of Compromise (IOC) data within Google SecOps
SIEM. The integration allows Google SecOps SIEM to receive real-time IOC data,
filtered query results, and enriched indicator intelligence from the Cyjax API.

## The overall flow of the script:

- Deploying the script to Cloud Function
- Data collection using ingestion script from Cyjax API
- Cyjax data ingested into Google SecOps SIEM
- Collected data will be parsed through corresponding parsers in Google SecOps

## Pre-Requisites

- Google SecOps SIEM instance
- Cyjax Intelligence platform (API Key)
- GCP Project with the below required permissions:
  - GCP user and project service account should have below permissions. Follow
    [these steps](#update-service-account-permission) to assign these
    permissions to the service account used for accessing other GCP services
    within your project.
    - Cloud Scheduler Job Runner
    - Secret Manager Secret Accessor
    - Storage Admin
    - Chronicle API Editor
    - Role Viewer
    - Cloud Run Invoker
- GCP Services
  - Before using the below services, ensure the [Google APIs](#google-apis) are
    enabled in your GCP project
  - Cloud Run Function (4-core CPU or higher is recommended)
  - GCS bucket
  - Secret Manager
  - Cloud Scheduler

## Automatic deployment of the required resources

This section explains the use of the provided bash script to automate the
deployment of the Cyjax Intelligence ingestion function and related resources
within your GCP project.

### Prerequisites For Script Execution :

- Access to a GCP project with owner role to enable APIs, create service
  accounts, IAM bindings, GCS buckets, Cloud Functions, Cloud Scheduler jobs,
  and Secret Manager secrets.
- The Cloud Function source code packaged as a ZIP file in
  [this](#creating-zip-of-the-cloud-function) format, available on your local
  machine or accessible within the Cloud Shell environment.

### Steps:

1.  **Open Google Cloud Shell**:
    - Navigate to the Google Cloud Console (https://console.cloud.google.com).
    - Click the "Activate Cloud Shell" in the upper right corner of the console.
      A terminal window will open within your browser.

2.  **Create the Script File**:
    - Choose a name for the script, for example, `cyjax_deploy.sh`.
    - Use a text editor like nano to create the file in your Cloud Shell home
      directory: `nano cyjax_deploy.sh`

3.  **Paste the Script Content**:
    - Copy the entire content of the bash script provided from GitHub repo.
    - Paste the script content into the nano editor. In Cloud Shell, you can
      typically right-click and select "Paste" or use Ctrl+Shift+V.

4.  **Save and Exit**:
    - Press Ctrl+X to exit nano.
    - When prompted to save, press Y.
    - Press Enter to confirm the filename (`cyjax_deploy.sh`).

5.  **Upload Your Cloud Function ZIP (if not already in Cloud Shell)**:
    - If your function ZIP file is on your local machine, you need to upload it
      to Cloud Shell.
    - Click the three-dot menu in the Cloud Shell terminal window.
    - Select "Upload" and choose your ZIP file. It will be uploaded to your
      Cloud Shell home directory. Note the filename.

6.  **Make the Script Executable**:
    - Grant execute permissions to the script file: `chmod +x cyjax_deploy.sh`

7.  **Run the Deployment Script**:
    - Execute the script: `./cyjax_deploy.sh`

8.  **Follow the Prompts**:
    - The script will prompt you to enter various configuration details, such as:
      - GCP Project ID & Region
      - Local path to your Cloud Function ZIP file
        (e.g., `/home/username/your-function.zip`)
      - Chronicle Customer ID
      - Chronicle Region
      - Chronicle Project Number (optional for cross-project deployments)
      - Chronicle Service Account JSON (optional for cross-project deployments)
      - Cyjax API Token Value (this will be stored securely in Secret Manager)
      - Other optional environment variables (HISTORICAL_IOC_DURATION, QUERY,
        ENABLE_ENRICHMENT, INDICATOR_TYPES).
    - Provide the requested information at each prompt. Required fields must be
      filled. Optional fields can be left blank to use defaults where
      applicable. These values can be obtained by following
      [these steps](#locate-environment-variables).

9.  **Monitor the Output**:
    - The script will display progress messages, indicating which steps are
    being performed (e.g., enabling APIs, creating resources, deploying the
      function).
    - Error messages will be shown in red. If an error occurs, the script is
      designed to stop. Review the error message to troubleshoot.

10. **Post-Deployment**:
    - Once the script completes successfully, verify the resources in the GCP
      Console:
      - Check Cloud Functions to see your deployed function.
      - Check Cloud Scheduler to see the scheduled job.
      - Check GCS for the bucket and uploaded ZIP.
      - Check the Secret Manager for the Cyjax API Key secret.
      - Review Cloud Logging for any function execution logs or errors.

## Manual deployment of the required resources

### Google APIs

Ensure the following Google APIs are enabled in your GCP project (via APIs &
Services → Library).

| **Service** | **APIs needs to enable** |
|---|---|
| Google SecOps | chronicle.googleapis.com |
| Cloud Functions | cloudfunctions.googleapis.com<br>run.googleapis.com<br>cloudbuild.googleapis.com<br>artifactregistry.googleapis.com<br>logging.googleapis.com |
| Cloud Scheduler | cloudscheduler.googleapis.com<br>pubsub.googleapis.com |
| Cloud Storage (Bucket) | storage-component.googleapis.com |
| Secret Manager | secretmanager.googleapis.com |
| Cloud Resource Manager | cloudresourcemanager.googleapis.com |

#### Enable APIs via Cloud Shell CLI

You can enable all required APIs using the following commands:

```bash
# Set your project ID
export PROJECT_ID="your-project-id"
gcloud config set project $PROJECT_ID

# Enable all required APIs
gcloud services enable cloudfunctions.googleapis.com \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  logging.googleapis.com \
  cloudscheduler.googleapis.com \
  pubsub.googleapis.com \
  storage-component.googleapis.com \
  secretmanager.googleapis.com \
  chronicle.googleapis.com \
  cloudresourcemanager.googleapis.com \
  --project=$PROJECT_ID
```

### Manual Cloud Shell CLI Deployment (Step-by-Step)

This section provides complete step-by-step CLI commands to deploy the Cyjax
integration without using the automated deployment script.

#### Step 1: Set Up Environment Variables

Open Cloud Shell and set the following environment variables with your values:

```bash
# GCP Project Configuration
export PROJECT_ID="your-project-id"
export REGION="us-central1"
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")

# GCS Bucket Configuration
export GCS_BUCKET_NAME="cyjax-bucket-${PROJECT_NUMBER}"
export LOCAL_ZIP_PATH="./cyjax_function.zip"  # Path to your uploaded zip file

# Cloud Function Configuration
export CF_NAME="cyjax-secops-function"
export SCHEDULER_NAME="cyjax-secops-scheduler"
export CRON_SCHEDULE="0 * * * *"  # Every hour

# Chronicle Configuration
export CHRONICLE_CUSTOMER_ID="your-chronicle-customer-id"
export CHRONICLE_PROJECT_NUMBER="${PROJECT_NUMBER}"  # Or specify different if needed
export CHRONICLE_REGION="us"

# Cyjax Configuration
export HISTORICAL_IOC_DURATION="1"
export QUERY=""  # Optional query filter
export ENABLE_ENRICHMENT="false"
export INDICATOR_TYPES=""  # Optional: Domain|Email|IPv4

# Credentials (will be stored in Secret Manager)
export CYJAX_API_TOKEN_VALUE="your-cyjax-api-token"
# Optional: Path to Chronicle service account JSON file
export CHRONICLE_SA_PATH=""  # Leave empty if using default service account
```

#### Step 2: Configure gcloud

```bash
gcloud config set project $PROJECT_ID
```

#### Step 3: Enable Required APIs

```bash
gcloud services enable cloudfunctions.googleapis.com \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  logging.googleapis.com \
  cloudscheduler.googleapis.com \
  pubsub.googleapis.com \
  storage-component.googleapis.com \
  secretmanager.googleapis.com \
  chronicle.googleapis.com \
  cloudresourcemanager.googleapis.com \
  --project=$PROJECT_ID

echo "APIs enabled successfully"
```

#### Step 4: Configure Service Account Permissions

```bash
# Get the default compute service account email
export SERVICE_ACCOUNT_EMAIL="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

# Assign required roles to the service account
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/chronicle.editor" \
  --condition=None

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/cloudscheduler.jobRunner" \
  --condition=None

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/secretmanager.secretAccessor" \
  --condition=None

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/storage.admin" \
  --condition=None

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/run.invoker" \
  --condition=None

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/viewer" \
  --condition=None

echo "Service account permissions configured"
```

#### Step 5: Create Secrets in Secret Manager

```bash
# Create and store Cyjax API Token
echo -n "$CYJAX_API_TOKEN_VALUE" | gcloud secrets create cyjax-api-token \
  --replication-policy="automatic" \
  --data-file=- \
  --project=$PROJECT_ID

export CYJAX_API_TOKEN_SECRET=$(gcloud secrets versions describe latest \
  --secret="cyjax-api-token" \
  --project=$PROJECT_ID \
  --format='value(name)')

echo "Cyjax API Token Secret: $CYJAX_API_TOKEN_SECRET"

# Optional: Create Chronicle Service Account secret (if using custom SA)
if [ -n "$CHRONICLE_SA_PATH" ] && [ -f "$CHRONICLE_SA_PATH" ]; then
  gcloud secrets create chronicle-service-account \
    --replication-policy="automatic" \
    --data-file="$CHRONICLE_SA_PATH" \
    --project=$PROJECT_ID

  export CHRONICLE_SA_SECRET=$(gcloud secrets versions describe latest \
    --secret="chronicle-service-account" \
    --project=$PROJECT_ID \
    --format='value(name)')

  echo "Chronicle Service Account Secret: $CHRONICLE_SA_SECRET"
fi

echo "Secrets created successfully"
```

#### Step 6: Create GCS Bucket

```bash
# Check if bucket exists, create if not
if ! gsutil ls -b "gs://$GCS_BUCKET_NAME" &>/dev/null; then
  gsutil mb -p $PROJECT_ID -l $REGION "gs://$GCS_BUCKET_NAME"
  echo "Bucket gs://$GCS_BUCKET_NAME created"
else
  echo "Bucket gs://$GCS_BUCKET_NAME already exists"
fi
```

#### Step 7: Upload Cloud Function ZIP

First, ensure you have uploaded your ZIP file to Cloud Shell. Then:

```bash
# Upload the ZIP file to GCS bucket
gsutil cp $LOCAL_ZIP_PATH "gs://$GCS_BUCKET_NAME/cyjax_function.zip"

echo "Cloud Function ZIP uploaded to gs://$GCS_BUCKET_NAME/cyjax_function.zip"
```

#### Step 8: Deploy Cloud Function

```bash
# Build environment variables string for Cloud Function
ENV_VARS="CHRONICLE_CUSTOMER_ID=${CHRONICLE_CUSTOMER_ID}"
ENV_VARS="${ENV_VARS},CHRONICLE_PROJECT_NUMBER=${CHRONICLE_PROJECT_NUMBER}"
ENV_VARS="${ENV_VARS},CHRONICLE_REGION=${CHRONICLE_REGION}"
ENV_VARS="${ENV_VARS},GCP_BUCKET_NAME=${GCS_BUCKET_NAME}"
ENV_VARS="${ENV_VARS},CYJAX_API_TOKEN=${CYJAX_API_TOKEN_SECRET}"
ENV_VARS="${ENV_VARS},HISTORICAL_IOC_DURATION=${HISTORICAL_IOC_DURATION}"
ENV_VARS="${ENV_VARS},ENABLE_ENRICHMENT=${ENABLE_ENRICHMENT}"

# Add optional environment variables if provided
[ -n "$CHRONICLE_SA_SECRET" ] && ENV_VARS="${ENV_VARS},CHRONICLE_SERVICE_ACCOUNT=${CHRONICLE_SA_SECRET}"
[ -n "$QUERY" ] && ENV_VARS="${ENV_VARS},QUERY=${QUERY}"
[ -n "$INDICATOR_TYPES" ] && ENV_VARS="${ENV_VARS},INDICATOR_TYPES=${INDICATOR_TYPES}"

# Deploy the Cloud Function
gcloud functions deploy $CF_NAME \
  --set-env-vars "$ENV_VARS" \
  --gen2 \
  --runtime=python312 \
  --region=$REGION \
  --source="gs://$GCS_BUCKET_NAME/cyjax_function.zip" \
  --entry-point=main \
  --service-account=$SERVICE_ACCOUNT_EMAIL \
  --trigger-http \
  --no-allow-unauthenticated \
  --memory=8GiB \
  --timeout=3600s

echo "Cloud Function deployed successfully"

# Get the Cloud Function URL
export CLOUD_FUNCTION_URL=$(gcloud functions describe $CF_NAME \
  --region=$REGION \
  --gen2 \
  --format='value(serviceConfig.uri)')

echo "Cloud Function URL: $CLOUD_FUNCTION_URL"
```

#### Step 9: Create Cloud Scheduler Job

```bash
# Delete existing scheduler job if it exists
if gcloud scheduler jobs describe $SCHEDULER_NAME \
  --location=$REGION \
  --project=$PROJECT_ID &>/dev/null; then
  echo "Deleting existing scheduler job..."
  gcloud scheduler jobs delete $SCHEDULER_NAME \
    --location=$REGION \
    --project=$PROJECT_ID \
    --quiet
fi

# Create the Cloud Scheduler job
gcloud scheduler jobs create http $SCHEDULER_NAME \
  --schedule="$CRON_SCHEDULE" \
  --uri="$CLOUD_FUNCTION_URL" \
  --http-method=POST \
  --attempt-deadline=30m \
  --oidc-service-account-email=$SERVICE_ACCOUNT_EMAIL \
  --location=$REGION \
  --time-zone=UTC \
  --project=$PROJECT_ID

echo "Cloud Scheduler job created successfully"
```

#### Step 10: Verify Deployment

```bash
# Verify Cloud Function
echo "=== Cloud Function Status ==="
gcloud functions describe $CF_NAME --region=$REGION --gen2

# Verify Cloud Scheduler
echo "=== Cloud Scheduler Status ==="
gcloud scheduler jobs describe $SCHEDULER_NAME --location=$REGION

# Verify Secrets
echo "=== Secrets Created ==="
gcloud secrets list --project=$PROJECT_ID --filter="name:cyjax OR name:chronicle"

# Verify Bucket
echo "=== GCS Bucket Contents ==="
gsutil ls "gs://$GCS_BUCKET_NAME/"

echo ""
echo "Deployment completed successfully!"
echo "Cloud Function URL: $CLOUD_FUNCTION_URL"
echo "Next Steps:"
echo "1. Monitor Cloud Function logs: gcloud functions logs read $CF_NAME --region=$REGION --gen2"
echo "2. Test the function manually from the GCP Console"
echo "3. Wait for the scheduled job to execute and verify data ingestion in Google SecOps"
```

### Environment Variables

These values can be obtained by following steps:
[Locate Environment Variables](#locate-environment-variables).

| **Variable** | **Description** | **Default value** | **Required** | **Secret Manager** |
|---|---|---|---|---|
| CHRONICLE_CUSTOMER_ID | Google SecOps customer id. Navigate to settings in the Google SecOps console for the customer id. | - | Yes | No |
| CHRONICLE_REGION | A region where the Google SecOps instance is located. | us | No | No |
| CHRONICLE_PROJECT_NUMBER | Specifies the GCP project identifier associated with your Google SecOps environment. | - | Yes | No |
| CHRONICLE_SERVICE_ACCOUNT | Optional. Service account JSON for cross-project deployments. If the GCP project where the Cloud Scheduler is deployed is different from the GCP project hosting the Google SecOps instance, provide the Service Account JSON. | - | No | Yes |
| GCP_BUCKET_NAME | Name of the created GCP bucket. | - | Yes | No |
| CYJAX_API_TOKEN | Copied resource name value of API TOKEN of Cyjax from secret manager.<br><br>Generate an API Key from the Cyjax platform's API key section. | - | Yes | Yes |
| HISTORICAL_IOC_DURATION | Number of days of historical IOC data to fetch on first run (maximum 7 days). | 1 | No | No |
| QUERY | A query to filter Cyjax Indicators.<br><br>Example: `malware` | - | No | No |
| ENABLE_ENRICHMENT | Enable enrichment of indicators with additional metadata. | false | No | No |
| INDICATOR_TYPES | Pipe-separated list of indicator types to fetch.<br><br>Allowed values: Domain, Email, Hostname, FileHash-MD5, FileHash-SHA1, FileHash-SHA256, FileHash-SSDEEP, IPv4, IPv6, URL<br><br>Example: `Domain\|Email\|IPv4` | - | No | No |

### Creating zip of the cloud function

- Create a zip file with the contents of the following files:
  - Download the common directory from
    [Git repository](https://github.com/chronicle/ingestion-scripts/tree/main/common).
  - Download the contents of the Cyjax ingestion script.
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
    ├── exception_handler_test.py
    ├── main.py
    ├── main_test.py
    ├── requirements.txt
    ├── utility.py
    ├── utility_test.py
    ├── cyjax_client.py
    └── cyjax_client_test.py
  ```

### Using Secrets

- [Environment variables](#environment-variables) marked as secret must be
  configured as secrets on Google Secret Manager.
  [[REF]](https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets#create)
- Once the secrets are created on Secret Manager, use the secret's resource ID
  as the value for environment variables.

For example:

```bash
SECRET_KEY=projects/{project_id}/secrets/{secret_id}/versions/{version_id}
```

### Add the Cyjax API Token in Secret Manager

1. Log in to the `https://console.cloud.google.com/` using valid credentials.
2. Navigate to `Secret Manager`.
3. Click on `Create Secret`.
4. Provide the name for the secret in the `Name` field (e.g., `cyjax_api_token`).
5. Provide your Cyjax API token value in the `Secret Value` field.
6. Keep the other configurations as default, Click on the `Create Secret`
button. Similarly, Create a secret for **Google SecOps Service Account**
if needed for cross-project deployments.

### Create a GCP Bucket

1. Log in to the [GCP Console](https://console.cloud.google.com/) using valid
   credentials.
2. Navigate to Buckets in GCP.
3. Click on the Create button.
4. Enter the name of the bucket.
5. Users can select the region and modify the optional parameters if required
and then click on the Create button.

Copy the bucket name and provide it in the `GCP_BUCKET_NAME` environment
variable.

### Cloud Function Deployment

#### Command based deployment

1. Navigate to the bucket and open the bucket created for Cyjax in
   [these](#create-a-gcp-bucket) steps. Upload the created cloud function
   [zip](#creating-zip-of-the-cloud-function) file in the bucket.
2. Click Activate Cloud Shell at the top right corner of the Google Cloud console.
3. Modify the below command based on your value and run in the terminal.

##### Command Format :

```bash
gcloud functions deploy CLOUD_FUNCTION_NAME --set-env-vars "ENV_NAME1=ENV_VALUE1,ENV_NAME2=ENV_VALUE2,ENV_NAME3=ENV_VALUE3" --gen2 --runtime=python312 --region=REGION --source=SOURCE_OF_FUNCTION  --entry-point=main --service-account=SERVICE_ACCOUNT_EMAIL --trigger-http --no-allow-unauthenticated --memory=8GiB --timeout=3600s
```

* **CLOUD_FUNCTION_NAME**: Unique name of the cloud function.
* **REGION**: A region for your cloud function. (Ex : us-central1, us-west1,
  etc.)
* **SOURCE_OF_FUNCTION**: gsutil URI of the cloud function zip in cloud storage.
  (e.g. gs://cyjax_test_bucket/cyjax_test.zip) where the cyjax_test_bucket is
  the name of the created bucket and cyjax_test.zip is the cloud function zip
  file.
* **SERVICE_ACCOUNT_EMAIL**: Email of the created service account of the
project. Make sure the selected Service account must have a required permission.
Update Service Account Permission
  [following these steps](#update-service-account-permission).
* **ENV_NAME1=ENV_VALUE1**: Name and value of the environment variable to be
  created. [Environment variables](#environment-variables)

##### Note:

1. When deploying a [Cloud Function](#cloud-function-deployment), ensure that
   the **--timeout** parameter in the deployment command matches the frequency
   specified in the [Cloud Scheduler](#configure-scheduler) **--schedule**
   parameter. Aligning these values prevents overlapping executions, which could
   lead to data duplication.
   - **For example**, if you set --timeout=3600s when deploying the Cloud
     Function, configure the Cloud Scheduler with: --schedule="0 * * * *" (every
     hour).
   - This ensures that each scheduled run starts only after the previous
     execution has completed.

##### Example Command,

```bash
gcloud functions deploy cyjax-secops-function --set-env-vars "CHRONICLE_CUSTOMER_ID=ed19f037-2354-43df-bfbf-350362b45844,CHRONICLE_PROJECT_NUMBER=2134567,CHRONICLE_REGION=us,GCP_BUCKET_NAME=cyjax_test_bucket,CYJAX_API_TOKEN=projects/1234567890/secrets/cyjax_api_token/versions/1," --gen2 --runtime=python312 --region=us-central1 --source=gs://cyjax_test_bucket/cyjax_test.zip  --entry-point=main --service-account=1234567890-compute@developer.gserviceaccount.com --trigger-http --no-allow-unauthenticated --memory=8GiB --timeout=3600s
```

### Configure Scheduler

#### Command based deployment

1. Click Activate Cloud Shell at the top right corner of the Google Cloud
console.
2. Modify the below command based on your value and run in the terminal.

##### Command Format :

```bash
gcloud scheduler jobs create http SCHEDULER_NAME --schedule="CRON_TIME" --uri="CLOUD_FUNCTION_URL" --attempt-deadline=30m --oidc-service-account-email=SERVICE_ACCOUNT_EMAIL --location=LOCATION --time-zone=TIME_ZONE
```

* **SCHEDULER_NAME**: Unique name of the cloud scheduler.
* **CRON_TIME**: Cron time format for the scheduler to run in every interval.
  (eg. 0 * * * * for hourly)
* **CLOUD_FUNCTION_URL**: URL of the created cloud function. Navigate to created
  cloud function details.
* **SERVICE_ACCOUNT_EMAIL**: Email of the created service account of the
project. Make sure the selected Service account must have a required Permission.
Update Service Account Permission
  [following these steps](#update-service-account-permission).
* **LOCATION**: A region for your connector. (Ex : us-central1, us-west1, etc)
* **TIME_ZONE**: The time zone of your region. (Ex : UTC)

##### Note:

1. When deploying a [Cloud Function](#cloud-function-deployment), ensure that
   the **--timeout** parameter in the deployment command matches the frequency
   specified in the [Cloud Scheduler](#configure-scheduler) **--schedule**
   parameter. Aligning these values prevents overlapping executions, which could
   lead to data duplication.
   - **For example**, if you set --timeout=3600s when deploying the Cloud
     Function, configure the Cloud Scheduler with: --schedule="0 * * * *" (every
     hour).
   - This ensures that each scheduled run starts only after the previous
     execution has completed.

##### Example Command,

```bash
gcloud scheduler jobs create http cyjax-secops-scheduler --schedule="0 * * * *" --uri="https://us-central1-test.cloudfunctions.net/cyjax-secops-function" --attempt-deadline=30m --oidc-service-account-email=1234567890-compute@developer.gserviceaccount.com --location=us-central1 --time-zone=UTC
```

### Update Service Account Permission

1. Open **GCP Console**, Then go to **IAM**.
2. In View By **Main Tab** > Click **GRANT ACCESS**.
3. Add Service Account name in **New Principals**. (Example :
   service_account_name.gserviceaccount.com)
4. In **Assign Role**, assign below roles to service accounts.
  1. Cloud Scheduler Job Runner
  2. Secret Manager Secret Accessor
  3. Storage Admin
  4. Chronicle API Editor
  5. Role Viewer
  6. Cloud Run Invoker
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
3. Copy the bucket name (e.g., `cyjax-bucket`).

### CYJAX_API_TOKEN

**Steps to find:**

1. Navigate to your Cyjax platform.
2. Go to the `Profile > API tokens` section.
3. Generate and Copy the **API Token**.

### HISTORICAL_IOC_DURATION

**Description:**

- Number of days of historical IOC data to fetch on first run.
- Maximum value: 7 days
- Default value: 1 day

### QUERY

**Description:**

- A query string to filter Cyjax Indicators.
- Optional parameter to narrow down the indicators fetched.

### ENABLE_ENRICHMENT

**Description:**

- Enable enrichment of indicators with additional metadata.
- Allowed values: `true`, `false`
- Default: `false`

### INDICATOR_TYPES

**Description:**

- Pipe-separated list of indicator types to fetch.
- Allowed values: Domain, Email, Hostname, FileHash-MD5, FileHash-SHA1,
  FileHash-SHA256, FileHash-SSDEEP, IPv4, IPv6, URL
- Example: `Domain|Email|IPv4`
- When providing multiple types in the deployment script, use pipe separator (|)

## Redeploying an Upgraded Build

Run the same
[Automatic](#automatic-deployment-of-the-required-resources) or
[Manual](#manual-deployment-of-the-required-resources) steps with the new Cloud
Function ZIP. Use the same function name so GCP updates the code automatically.

### Deployment Steps

* **Automatic:** Rerun the
  [bash script](#automatic-deployment-of-the-required-resources), provide the
  **updated ZIP**, and reuse the earlier configuration values (Project ID, API
  key, etc.).
* **Manual:** Rerun the
  [gcloud functions deploy command](#cloud-function-deployment), point the
  source flag to the **latest ZIP**, and keep the **function name unchanged**.

### Important Notes

* Same function name means the old build is overwritten, no extra cleanup
  required.
* Cloud Scheduler, Secret Manager, and service-account settings stay valid.
* After redeploying, check
  [Cloud Logging](https://console.cloud.google.com/logs) to confirm everything
  runs without errors.

---

### Limitations

* We suggest using the second generation of Cloud Function. The first generation
  of Cloud Function has a maximum execution time of 9 minutes and the second
  generation of Cloud Function has a maximum execution time of 60 minutes. If
  the execution time of the Cloud Function exceeds timeout then there are
  chances that the complete data won't be ingested in the Google SecOps.
* The rate limit for a Cyjax account depends on the user's subscription tier.
  Based on this API rate limit, the integration will be able to collect data and
  ingest into Google SecOps. Once the API rate limit is exceeded, data
  collection will only resume when the limit is reset after a specific interval.
* The Google SecOps Ingestion API has a payload limit of 1 MB. Logs exceeding
  this limit will not be ingested and will be skipped. To minimize data loss,
  please ensure that log sizes remain within the allowed limit.
* If an optional environment variable is not provided during the Cloud Function
  deployment, default values will be used, and data collection will start
  accordingly.
* The chunk limit for data collection is set to 100 to minimize data
  duplication in case of errors during ingestion, as the Google SecOps Ingestion
  API processes data in chunks of 100.
* We recommend setting the timeout in the RUNTIME variable to the maximum value
  (3600) to prevent the Cloud Function from terminating during data collection.
* HISTORICAL_IOC_DURATION cannot exceed 7 days. If a value greater than 7 is
  provided, the function will raise an error.

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

This section describes the common issues that might happen during the deployment
or the running of the app and the steps to resolve the issues.

1.  GCloud logs can be used for troubleshooting.
    1.  Log in to the `https://console.cloud.google.com/` using valid
        credentials.
    2.  Navigate to 'Cloud functions' and click on the deployed function where
        you can find the logs module.
    3.  Logs can be filtered using severity.
2.  If you test the cloud function immediately after deploying it on gcloud, It
    might be possible that the cloud function will not work as expected. To
    resolve this, wait for a few seconds and then test it.
3.  If the cloud function stops its execution because memory exceeds the limit,
    reconfigure the cloud function's memory configuration and increase the
    memory limit.
4.  If you notice duplicate events or overlapping Cloud Function executions,
    ensure that the --timeout parameter in
    [Cloud Function](#cloud-function-deployment) command and --schedule
    parameter in [Cloud Scheduler](#configure-scheduler) deployment command
    should be the same.
    <br> **For example,** if you set --timeout=3600s when deploying the Cloud
    Function, configure the Cloud Scheduler with: --schedule="0 * * * *" (every
    hour).
5.  **"Another process is already running"** error:
    - **Cause**: Process lock is active from previous execution.
    - **Solution**: Check if function is still running. If stuck, manually
      release lock by updating the checkpoint file in GCS bucket.
6.  **Configuration changed but old data still processing**:
    - **Cause**: Page number was > 0 when config changed.
    - **Solution**: Checkpoint automatically resets page_number to 0 and starts
      fresh window.
7.  **Execution time exceeded**:
    - **Cause**: Function timeout (max 50 minutes for safety check).
    - **Solution**: Function will resume from last checkpoint on next execution.
8.  **Permission denied errors**:
    - **Cause**: Service account lacks required permissions.
    - **Solution**: Grant required IAM roles listed in
      [Prerequisites](#pre-requisites).

### Resources

- [Cloud Function](https://cloud.google.com/functions)
- [Cloud Scheduler](https://cloud.google.com/scheduler/docs/overview)
- [Cloud Secret Manager](https://cloud.google.com/security/products/secret-manager)
- [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install)
- [Deploying cloud functions from local machine](https://cloud.google.com/functions/docs/deploying/filesystem)
- [Google SecOps Ingestion API Payload Limit](https://cloud.google.com/chronicle/docs/reference/ingestion-api#unstructuredlogentries)
- [Cyjax Platform](https://www.cyjax.com/)
