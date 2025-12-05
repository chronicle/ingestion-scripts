#!/bin/bash
# --- Configuration Variables ---
PROJECT_ID=""
REGION=""
GCS_BUCKET_NAME="gti-bucket"
LOCAL_ZIP_PATH=""
CF_ZIP_FILE="gti_function.zip" # Default zip file name in bucket
CF_NAME="gti-secops-function"
SCHEDULER_NAME="gti-secops-scheduler"
PROJECT_NUMBER=""
DEFAULT_SA_EMAIL=""
CRON_TIME="0 * * * *" # Every 60 minutes
TIMEOUT_SECONDS="3600s" # 60 minutes

# --- Cloud Function Environment Variables ---
CHRONICLE_CUSTOMER_ID=""
CHRONICLE_REGION="us"
CHRONICLE_PROJECT_ID=""
GTI_API_TOKEN_VALUE=""
GTI_API_TOKEN_SECRET_ID=""
THREAT_LISTS=""
THREAT_LISTS_START_TIME=""
THREAT_LIST_QUERY=""
FETCH_IOC_STREAM_ENABLED="true"
HISTORICAL_IOC_STREAM_DURATION="1"
IOC_STREAM_FILTER=""

print_message() {
    local color="$1"
    local message="$2"
    case "$color" in
        "green") echo -e "\033[32m${message}\033[0m" ;;
        "red") echo -e "\033[31m${message}\033[0m" >&2 ;;
        "yellow") echo -e "\033[33m${message}\033[0m" ;;
        *) echo "${message}" ;;
    esac
}

check_error() {
    local exit_code=$?
    local step_name="$1"

    if [ $exit_code -ne 0 ]; then
        print_message "red" "\nERROR: Step '$step_name' failed with exit code $exit_code."
        print_message "red" "Exiting script due to error."
        exit $exit_code
    else
        print_message "green" "SUCCESS: Step '$step_name' completed."
    fi
}

prompt_for_input() {
    print_message "yellow" "--- GCP Deployment Configuration ---"

    read -r -p "Enter your GCP Project ID (e.g., my-project-12345): " PROJECT_ID
    [[ -z "$PROJECT_ID" ]] && { print_message "red" "ERROR: Project ID cannot be empty."; exit 1; }

    read -r -p "Enter your GCP Region (e.g., us-central1): " REGION
    [[ -z "$REGION" ]] && { print_message "red" "ERROR: Region cannot be empty."; exit 1; }

    print_message "yellow" "NOTE: You MUST first create the Cloud Function zip file and upload to cloud."
    read -r -p "Enter local full path to the zip file (e.g., /home/user_name/gti_source.zip): " LOCAL_ZIP_PATH
    [[ -z "$LOCAL_ZIP_PATH" ]] && { print_message "red" "ERROR: Local ZIP Path cannot be empty."; exit 1; }
    [[ ! -f "$LOCAL_ZIP_PATH" ]] && { print_message "red" "ERROR: File not found at $LOCAL_ZIP_PATH."; exit 1; }

    print_message "yellow" "\n--- Cloud Function Environment Variables ---"
    read -r -p "Enter Chronicle Customer ID: " CHRONICLE_CUSTOMER_ID
    [[ -z "$CHRONICLE_CUSTOMER_ID" ]] && { print_message "red" "ERROR: Chronicle Customer ID cannot be empty."; exit 1; }

    local default_chronicle_region="us"
    read -r -p "Enter CHRONICLE_REGION [default: $default_chronicle_region]: " temp_var
    CHRONICLE_REGION=${temp_var:-$default_chronicle_region}

    read -r -p "Enter Raw GTI API Token Value (Required, will be stored in Secret Manager): " GTI_API_TOKEN_VALUE
    echo
    [[ -z "$GTI_API_TOKEN_VALUE" ]] && { print_message "red" "ERROR: GTI API Token Value cannot be empty."; exit 1; }

    local default_threat_lists=""
    read -r -p "Enter THREAT_LISTS ids need to be collected (pipe-separated, Optional, e.g., mobile|trending): " temp_var
    THREAT_LISTS=${temp_var:-$default_threat_lists}
    if [[ -n "$THREAT_LISTS" ]]; then
        read -r -p "  Enter THREAT_LISTS_START_TIME (Optional, YYYYMMDDHH, max 7 days ago): " THREAT_LISTS_START_TIME
        read -r -p "  Enter THREAT_LIST_QUERY (Optional): " THREAT_LIST_QUERY
    else
        print_message "yellow" "  THREAT_LISTS is empty, skipping related start time and query."
        THREAT_LISTS_START_TIME=""
        THREAT_LIST_QUERY=""
    fi

    local default_ioc_enabled="true"
    read -r -p "Enter FETCH_IOC_STREAM_ENABLED (true/false) [default: $default_ioc_enabled]: " temp_var
    FETCH_IOC_STREAM_ENABLED=${temp_var:-$default_ioc_enabled}
    [[ ! "$FETCH_IOC_STREAM_ENABLED" =~ ^(true|false)$ ]] && { print_message "red" "ERROR: FETCH_IOC_STREAM_ENABLED must be true or false."; exit 1; }

    if [[ "$FETCH_IOC_STREAM_ENABLED" == "true" ]]; then
        local default_ioc_duration="1"
        read -r -p "  Enter HISTORICAL_IOC_STREAM_DURATION (Days)(max 7 days ago)[default: $default_ioc_duration]: " temp_var
        HISTORICAL_IOC_STREAM_DURATION=${temp_var:-$default_ioc_duration}
        [[ ! "$HISTORICAL_IOC_STREAM_DURATION" =~ ^[0-9]+$ ]] && { print_message "red" "ERROR: HISTORICAL_IOC_STREAM_DURATION must be a number."; exit 1; }

        read -r -p "  Enter IOC_STREAM_FILTER (Optional): " IOC_STREAM_FILTER
    else
        print_message "yellow" "  FETCH_IOC_STREAM_ENABLED is false, skipping related duration and filter."
        HISTORICAL_IOC_STREAM_DURATION=""
        IOC_STREAM_FILTER=""
    fi

    print_message "green" "Configuration collected."
}

enable_apis() {
    print_message "yellow" "\n--- Enabling Required GCP APIs ---"
    local APIS=(
        cloudfunctions.googleapis.com
        run.googleapis.com
        cloudbuild.googleapis.com
        artifactregistry.googleapis.com
        logging.googleapis.com
        cloudscheduler.googleapis.com
        pubsub.googleapis.com
        storage-component.googleapis.com
        secretmanager.googleapis.com
        chronicle.googleapis.com
    )
    for api in "${APIS[@]}"; do
        if ! gcloud services list --project="$PROJECT_ID" --filter="NAME:$api" --format="value(NAME)" | grep -q "$api"; then
            print_message "yellow" "Enabling $api..."
            gcloud services enable "$api" --project="$PROJECT_ID"
            check_error "Enabling API $api"
        else
            print_message "green" "$api is already enabled."
        fi
    done
}

configure_default_service_account() {
    print_message "yellow" "\n--- Configuring Permissions for Default Compute Engine Service Account ---"
    PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
    CHRONICLE_PROJECT_ID=$PROJECT_NUMBER
    check_error "Fetching Project Number"
    DEFAULT_SA_EMAIL="$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
    print_message "yellow" "Target Service Account: $DEFAULT_SA_EMAIL"

    local ROLES=(
        "roles/chronicle.editor"
        "roles/cloudscheduler.jobRunner"
        "roles/secretmanager.secretAccessor"
        "roles/storage.admin"
        "roles/run.invoker"
        "roles/viewer"
    )

    for ROLE in "${ROLES[@]}"; do
        print_message "yellow" "Ensuring role $ROLE on $DEFAULT_SA_EMAIL..."
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
            --member="serviceAccount:$DEFAULT_SA_EMAIL" \
            --role="$ROLE" \
            --condition=None --no-user-output-enabled
        echo "Attempted to add $ROLE."
    done
    print_message "green" "IAM role binding attempts for $DEFAULT_SA_EMAIL complete. Verify in IAM console if needed."
}

create_api_token_secret() {
    local SECRET_NAME="gti-api-token"
    print_message "yellow" "\n--- Managing Secret Manager Secret ($SECRET_NAME) ---"

    if ! gcloud secrets describe "$SECRET_NAME" --project="$PROJECT_ID" &>/dev/null; then
        print_message "yellow" "Creating secret $SECRET_NAME..."
        gcloud secrets create "$SECRET_NAME" \
            --replication-policy="automatic" \
            --project="$PROJECT_ID"
        check_error "Creating Secret $SECRET_NAME"
    else
        print_message "green" "Secret $SECRET_NAME already exists."
    fi

    print_message "yellow" "Adding new version to Secret $SECRET_NAME..."
    echo -n "$GTI_API_TOKEN_VALUE" | gcloud secrets versions add "$SECRET_NAME" \
        --data-file=- \
        --project="$PROJECT_ID"
    check_error "Adding new version to Secret $SECRET_NAME"

    GTI_API_TOKEN_SECRET_ID=$(gcloud secrets versions describe "latest" \
        --secret="$SECRET_NAME" \
        --project="$PROJECT_ID" \
        --format='value(name)')
    check_error "Fetching latest secret version ID"

    if [[ ! "$GTI_API_TOKEN_SECRET_ID" =~ ^projects/.*/secrets/.*/versions/.* ]]; then
        print_message "red" "ERROR: Could not retrieve a valid Secret Resource ID. Got: $GTI_API_TOKEN_SECRET_ID"
        exit 1
    fi
    print_message "green" "GTI_API_TOKEN Secret ID: $GTI_API_TOKEN_SECRET_ID"
}

create_bucket() {
    print_message "yellow" "\n--- Managing GCS Bucket ($GCS_BUCKET_NAME) ---"
    if ! gsutil ls -b "gs://$GCS_BUCKET_NAME" &>/dev/null; then
        print_message "yellow" "Creating GCS bucket gs://$GCS_BUCKET_NAME in $REGION..."
        gsutil mb -p "$PROJECT_ID" -l "$REGION" "gs://$GCS_BUCKET_NAME"
        check_error "Creating GCS bucket gs://$GCS_BUCKET_NAME"
    else
        print_message "green" "Bucket gs://$GCS_BUCKET_NAME already exists."
    fi
}

upload_cf_zip() {
    print_message "yellow" "\n--- Uploading Cloud Function ZIP file ---"
    local GCS_URI="gs://$GCS_BUCKET_NAME/$CF_ZIP_FILE"
    print_message "yellow" "Uploading $LOCAL_ZIP_PATH to $GCS_URI"
    gsutil cp "$LOCAL_ZIP_PATH" "$GCS_URI"
    check_error "Uploading $LOCAL_ZIP_PATH to $GCS_URI"
}

deploy_cloud_function() {
    print_message "yellow" "\n--- Deploying Cloud Function ($CF_NAME) ---"

    local ENV_VARS_ARRAY=(
        "CHRONICLE_CUSTOMER_ID=${CHRONICLE_CUSTOMER_ID}"
        "CHRONICLE_PROJECT_NUMBER=${CHRONICLE_PROJECT_ID}"
        "CHRONICLE_REGION=${CHRONICLE_REGION}"
        "GCP_BUCKET_NAME=${GCS_BUCKET_NAME}"
        "GTI_API_TOKEN=${GTI_API_TOKEN_SECRET_ID}"
        "FETCH_IOC_STREAM_ENABLED=${FETCH_IOC_STREAM_ENABLED}"
    )

    [[ -n "$THREAT_LISTS" ]] && ENV_VARS_ARRAY+=("THREAT_LISTS=${THREAT_LISTS}")
    [[ -n "$THREAT_LISTS_START_TIME" ]] && ENV_VARS_ARRAY+=("THREAT_LISTS_START_TIME=${THREAT_LISTS_START_TIME}")
    [[ -n "$THREAT_LIST_QUERY" ]] && ENV_VARS_ARRAY+=("THREAT_LIST_QUERY=${THREAT_LIST_QUERY}")
    [[ -n "$HISTORICAL_IOC_STREAM_DURATION" ]] && ENV_VARS_ARRAY+=("HISTORICAL_IOC_STREAM_DURATION=${HISTORICAL_IOC_STREAM_DURATION}")
    [[ -n "$IOC_STREAM_FILTER" ]] && ENV_VARS_ARRAY+=("IOC_STREAM_FILTER=${IOC_STREAM_FILTER}")

    local ENV_VARS_STRING=$(IFS=,; echo "${ENV_VARS_ARRAY[*]}")
    local GCS_SOURCE="gs://$GCS_BUCKET_NAME/$CF_ZIP_FILE"

    print_message "yellow" "Using Env Vars: $ENV_VARS_STRING"
    print_message "yellow" "Using Source: $GCS_SOURCE"
    print_message "yellow" "Using Service Account: $DEFAULT_SA_EMAIL"

    gcloud functions deploy "$CF_NAME" \
        --set-env-vars "$ENV_VARS_STRING" \
        --gen2 \
        --runtime python312 \
        --region="$REGION" \
        --source="$GCS_SOURCE" \
        --entry-point=main \
        --service-account="$DEFAULT_SA_EMAIL" \
        --trigger-http \
        --no-allow-unauthenticated \
        --memory=8GiB \
        --timeout="$TIMEOUT_SECONDS"
    check_error "Deploying Cloud Function $CF_NAME"
}

configure_scheduler() {
    print_message "yellow" "\n--- Configuring Cloud Scheduler ($SCHEDULER_NAME) ---"
    local CLOUD_FUNCTION_URL="https://${REGION}-${PROJECT_ID}.cloudfunctions.net/${CF_NAME}"
    print_message "yellow" "Cloud Function URL: $CLOUD_FUNCTION_URL"
    print_message "yellow" "Schedule: $CRON_TIME (Timeout: $TIMEOUT_SECONDS)"

    if gcloud scheduler jobs describe "$SCHEDULER_NAME" --location="$REGION" --project="$PROJECT_ID" &>/dev/null; then
        print_message "yellow" "Scheduler job $SCHEDULER_NAME already exists. Deleting to recreate..."
        gcloud scheduler jobs delete "$SCHEDULER_NAME" --location="$REGION" --project="$PROJECT_ID" --quiet
        check_error "Deleting existing Scheduler job $SCHEDULER_NAME"
    fi

    print_message "yellow" "Creating Scheduler job $SCHEDULER_NAME..."
    gcloud scheduler jobs create http "$SCHEDULER_NAME" \
        --schedule="$CRON_TIME" \
        --uri="$CLOUD_FUNCTION_URL" \
        --http-method=POST \
        --attempt-deadline=30m \
        --oidc-service-account-email="$DEFAULT_SA_EMAIL" \
        --location="$REGION" \
        --time-zone=UTC \
        --project="$PROJECT_ID"
    check_error "Creating Cloud Scheduler job $SCHEDULER_NAME"
}

main() {
    print_message "green" "Starting GCP Deployment Script for Google Threat Intelligence..."
    prompt_for_input

    print_message "yellow" "\n--- Setting gcloud Configuration ---"
    gcloud config set project "$PROJECT_ID"
    check_error "Setting gcloud project to $PROJECT_ID"

    enable_apis
    configure_default_service_account
    create_bucket
    create_api_token_secret
    upload_cf_zip
    deploy_cloud_function
    configure_scheduler

    print_message "green" "\n--- Deployment Script Complete ---"
    print_message "green" "All components deployed and configured."
    print_message "yellow" "Next Steps:"
    print_message "yellow" "1. Verify Cloud Function logs for any errors."
    print_message "yellow" "2. Check Cloud Scheduler job for successful runs."
    print_message "yellow" "3. Import dashboards into Google SecOps as per the guide."
}

main