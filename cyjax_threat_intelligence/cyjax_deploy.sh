# --- Configuration Variables ---
PROJECT_ID=""
REGION=""
GCS_BUCKET_NAME="cyjax-bucket"
LOCAL_ZIP_PATH=""
CF_ZIP_FILE="cyjax_function.zip" # Default zip file name in bucket
CF_NAME="cyjax-secops-function"
SCHEDULER_NAME="cyjax-secops-scheduler"
PROJECT_NUMBER=""
DEFAULT_SA_EMAIL=""
CRON_TIME="0 * * * *" # Every 60 minutes
TIMEOUT_SECONDS="3600s" # 60 minutes

# --- Cloud Function Environment Variables ---
CHRONICLE_CUSTOMER_ID=""
CHRONICLE_SERVICE_ACCOUNT=""
CHRONICLE_REGION="us"
CHRONICLE_PROJECT_NUMBER=""
CHRONICLE_SERVICE_ACCOUNT_SECRET_ID=""
CYJAX_API_TOKEN_VALUE=""
CYJAX_API_TOKEN_SECRET_ID=""
HISTORICAL_IOC_DURATION="1"
QUERY=""
ENABLE_ENRICHMENT="false"
INDICATOR_TYPES=""

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

escape_yaml_value() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    echo "$value"
}

prompt_for_input() {
    print_message "yellow" "--- GCP Deployment Configuration ---"

    read -r -p "Enter your GCP Project ID (e.g., my-project-12345) (Required) : " PROJECT_ID
    [[ -z "$PROJECT_ID" ]] && { print_message "red" "ERROR: Project ID cannot be empty."; exit 1; }

    local default_region="us-central1"
    read -r -p "Enter your GCP Region [default: $default_region]: " temp_var
    REGION=${temp_var:-$default_region}

    print_message "yellow" "NOTE: You MUST first create the Cloud Function Code zip file and upload to cloud."
    read -r -p "Enter local full path to the zip file (e.g., /home/user_name/cyjax_source.zip): " LOCAL_ZIP_PATH
    [[ -z "$LOCAL_ZIP_PATH" ]] && { print_message "red" "ERROR: Local ZIP Path cannot be empty."; exit 1; }
    [[ ! -f "$LOCAL_ZIP_PATH" ]] && { print_message "red" "ERROR: File not found at $LOCAL_ZIP_PATH."; exit 1; }

    print_message "yellow" "\n--- Cloud Function Environment Variables ---"
    read -r -p "Enter CHRONICLE_CUSTOMER_ID (Required) : " CHRONICLE_CUSTOMER_ID
    [[ -z "$CHRONICLE_CUSTOMER_ID" ]] && { print_message "red" "ERROR: Chronicle Customer ID cannot be empty."; exit 1; }

    print_message "yellow" "IMPORTANT: If the GCP project where the Cloud Scheduler is deployed is different from the GCP project hosting the Google SecOps instance, the Chronicle Project Number must be provided."
    read -r -p "Enter CHRONICLE_PROJECT_NUMBER (Optional, press Enter to use current project number): " CHRONICLE_PROJECT_NUMBER

    local default_chronicle_region="us"
    read -r -p "Enter CHRONICLE_REGION [default: $default_chronicle_region]: " temp_var
    CHRONICLE_REGION=${temp_var:-$default_chronicle_region}

    print_message "yellow" "NOTE: You MUST first create the Chronicle Service Account json and upload to cloud."
    print_message "yellow" "IMPORTANT: If the GCP project where the Cloud Scheduler is deployed is different from the GCP project hosting the Google SecOps instance, the Service Account JSON must be provided."
    read -r -p "Enter path to CHRONICLE_SERVICE_ACCOUNT JSON file (Optional, press Enter to skip, will be stored in Secret Manager.): " CHRONICLE_SA_PATH
    if [[ -n "$CHRONICLE_SA_PATH" ]]; then
        [[ ! -f "$CHRONICLE_SA_PATH" ]] && { print_message "red" "ERROR: Service account JSON file not found at $CHRONICLE_SA_PATH."; exit 1; }
        CHRONICLE_SERVICE_ACCOUNT=$(<"$CHRONICLE_SA_PATH")
    fi

    print_message "yellow" "\n--- Cyjax Configuration ---"
    read -r -p "Enter CYJAX_API_TOKEN Value (Required, will be stored in Secret Manager): " CYJAX_API_TOKEN_VALUE
    [[ -z "$CYJAX_API_TOKEN_VALUE" ]] && { print_message "red" "ERROR: Cyjax API Token cannot be empty."; exit 1; }

    local default_historical_ioc_duration="1"
    read -r -p "Enter HISTORICAL_IOC_DURATION in days [default: $default_historical_ioc_duration]: " temp_var
    HISTORICAL_IOC_DURATION=${temp_var:-$default_historical_ioc_duration}

    read -r -p "Enter QUERY (Optional, press Enter to skip): " QUERY

    local default_enrichment="false"
    read -r -p "Enable Enrichment of Indicators? (true/false) [default: $default_enrichment]: " temp_var
    ENABLE_ENRICHMENT=${temp_var:-$default_enrichment}

    print_message "yellow" "Allowed INDICATOR_TYPES values: Domain, Email, Hostname, FileHash-MD5, FileHash-SHA1, FileHash-SHA256, FileHash-SSDEEP, IPv4, IPv6, URL (pipe-separated, e.g., Domain|Email|IPv4)"
    read -r -p "Enter INDICATOR_TYPES (Optional, press Enter to skip): " INDICATOR_TYPES

    local default_schedule="0 * * * *"
    read -r -p "Enter CRON Schedule (Optional, default: $default_schedule): " temp_var
    CRON_TIME=${temp_var:-$default_schedule}
    if [[ -z "$temp_var" ]]; then
        print_message "yellow" "  CRON Schedule is empty, use the default schedule: $default_schedule."
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
        cloudresourcemanager.googleapis.com
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
    
    # Use input CHRONICLE_PROJECT_NUMBER if provided, otherwise use PROJECT_NUMBER
    if [[ -n "$CHRONICLE_PROJECT_NUMBER" ]]; then
        print_message "yellow" "Using provided Chronicle Project Number: $CHRONICLE_PROJECT_NUMBER"
    else
        CHRONICLE_PROJECT_NUMBER=$PROJECT_NUMBER
        print_message "yellow" "Using current Project Number as Chronicle Project Number: $CHRONICLE_PROJECT_NUMBER"
    fi
    
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

create_secrets() {
    print_message "yellow" "\n--- Managing Cyjax Secrets in Secret Manager ---"

    # Create Cyjax API Token Secret
    local API_TOKEN_SECRET_NAME="cyjax-api-token"
    if ! gcloud secrets describe "$API_TOKEN_SECRET_NAME" --project="$PROJECT_ID" &>/dev/null; then
        print_message "yellow" "Creating secret $API_TOKEN_SECRET_NAME..."
        gcloud secrets create "$API_TOKEN_SECRET_NAME" \
            --replication-policy="automatic" \
            --project="$PROJECT_ID"
        check_error "Creating Secret $API_TOKEN_SECRET_NAME"
    else
        print_message "green" "Secret $API_TOKEN_SECRET_NAME already exists."
    fi

    print_message "yellow" "Adding new version to Secret $API_TOKEN_SECRET_NAME..."
    echo -n "$CYJAX_API_TOKEN_VALUE" | gcloud secrets versions add "$API_TOKEN_SECRET_NAME" \
        --data-file=- \
        --project="$PROJECT_ID"
    check_error "Adding new version to Secret $API_TOKEN_SECRET_NAME"

    CYJAX_API_TOKEN_SECRET_ID=$(gcloud secrets versions describe "latest" \
        --secret="$API_TOKEN_SECRET_NAME" \
        --project="$PROJECT_ID" \
        --format='value(name)')
    check_error "Fetching latest API Token secret version ID"

    if [[ ! "$CYJAX_API_TOKEN_SECRET_ID" =~ ^projects/.*/secrets/.*/versions/.* ]]; then
        print_message "red" "ERROR: Could not retrieve a valid API Token Secret Resource ID. Got: $CYJAX_API_TOKEN_SECRET_ID"
        exit 1
    fi
    print_message "green" "CYJAX_API_TOKEN Secret ID: $CYJAX_API_TOKEN_SECRET_ID"

    if [[ -n "$CHRONICLE_SERVICE_ACCOUNT" ]]; then
        # Create Chronicle Service Account Secret
        local CHRONICLE_SA_SECRET_NAME="chronicle-service-account"
        if ! gcloud secrets describe "$CHRONICLE_SA_SECRET_NAME" --project="$PROJECT_ID" &>/dev/null; then
            print_message "yellow" "Creating secret $CHRONICLE_SA_SECRET_NAME..."
            gcloud secrets create "$CHRONICLE_SA_SECRET_NAME" \
                --replication-policy="automatic" \
                --project="$PROJECT_ID"
            check_error "Creating Secret $CHRONICLE_SA_SECRET_NAME"
        else
            print_message "green" "Secret $CHRONICLE_SA_SECRET_NAME already exists."
        fi

        print_message "yellow" "Adding new version to Secret $CHRONICLE_SA_SECRET_NAME..."
        echo -n "$CHRONICLE_SERVICE_ACCOUNT" | gcloud secrets versions add "$CHRONICLE_SA_SECRET_NAME" \
            --data-file=- \
            --project="$PROJECT_ID"
        check_error "Adding new version to Secret $CHRONICLE_SA_SECRET_NAME"

        CHRONICLE_SERVICE_ACCOUNT_SECRET_ID=$(gcloud secrets versions describe "latest" \
            --secret="$CHRONICLE_SA_SECRET_NAME" \
            --project="$PROJECT_ID" \
            --format='value(name)')
        check_error "Fetching latest Chronicle SA secret version ID"

        if [[ ! "$CHRONICLE_SERVICE_ACCOUNT_SECRET_ID" =~ ^projects/.*/secrets/.*/versions/.* ]]; then
            print_message "red" "ERROR: Could not retrieve a valid Chronicle SA Secret Resource ID. Got: $CHRONICLE_SERVICE_ACCOUNT_SECRET_ID"
            exit 1
        fi
        print_message "green" "CHRONICLE_SERVICE_ACCOUNT Secret ID: $CHRONICLE_SERVICE_ACCOUNT_SECRET_ID"
    fi
}

create_bucket() {
    GCS_BUCKET_NAME="${GCS_BUCKET_NAME}-${PROJECT_NUMBER}"
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

    local ENV_VARS_FILE=".env_vars_temp.yaml"
    
    local ESC_CHRONICLE_CUSTOMER_ID=$(escape_yaml_value "${CHRONICLE_CUSTOMER_ID}")
    local ESC_CHRONICLE_PROJECT_NUMBER=$(escape_yaml_value "${CHRONICLE_PROJECT_NUMBER}")
    local ESC_CHRONICLE_REGION=$(escape_yaml_value "${CHRONICLE_REGION}")
    local ESC_GCS_BUCKET_NAME=$(escape_yaml_value "${GCS_BUCKET_NAME}")
    local ESC_CYJAX_API_TOKEN_SECRET_ID=$(escape_yaml_value "${CYJAX_API_TOKEN_SECRET_ID}")
    local ESC_HISTORICAL_IOC_DURATION=$(escape_yaml_value "${HISTORICAL_IOC_DURATION}")
    local ESC_ENABLE_ENRICHMENT=$(escape_yaml_value "${ENABLE_ENRICHMENT}")
    
    cat > "$ENV_VARS_FILE" <<EOF
CHRONICLE_CUSTOMER_ID: "${ESC_CHRONICLE_CUSTOMER_ID}"
CHRONICLE_PROJECT_NUMBER: "${ESC_CHRONICLE_PROJECT_NUMBER}"
CHRONICLE_REGION: "${ESC_CHRONICLE_REGION}"
GCP_BUCKET_NAME: "${ESC_GCS_BUCKET_NAME}"
CYJAX_API_TOKEN: "${ESC_CYJAX_API_TOKEN_SECRET_ID}"
HISTORICAL_IOC_DURATION: "${ESC_HISTORICAL_IOC_DURATION}"
ENABLE_ENRICHMENT: "${ESC_ENABLE_ENRICHMENT}"
EOF

    if [[ -n "$CHRONICLE_SERVICE_ACCOUNT_SECRET_ID" ]]; then
        local ESC_CHRONICLE_SERVICE_ACCOUNT_SECRET_ID=$(escape_yaml_value "${CHRONICLE_SERVICE_ACCOUNT_SECRET_ID}")
        echo "CHRONICLE_SERVICE_ACCOUNT: \"${ESC_CHRONICLE_SERVICE_ACCOUNT_SECRET_ID}\"" >> "$ENV_VARS_FILE"
    fi
    
    if [[ -n "$QUERY" ]]; then
        local ESC_QUERY=$(escape_yaml_value "${QUERY}")
        echo "QUERY: \"${ESC_QUERY}\"" >> "$ENV_VARS_FILE"
    fi
    
    if [[ -n "$INDICATOR_TYPES" ]]; then
        local ESC_INDICATOR_TYPES=$(escape_yaml_value "${INDICATOR_TYPES}")
        echo "INDICATOR_TYPES: \"${ESC_INDICATOR_TYPES}\"" >> "$ENV_VARS_FILE"
    fi

    local GCS_SOURCE="gs://$GCS_BUCKET_NAME/$CF_ZIP_FILE"

    print_message "yellow" "Using env vars file: $ENV_VARS_FILE"
    print_message "yellow" "Using Source: $GCS_SOURCE"
    print_message "yellow" "Using Service Account: $DEFAULT_SA_EMAIL"

    gcloud functions deploy "$CF_NAME" \
        --env-vars-file="$ENV_VARS_FILE" \
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
    local deploy_exit_code=$?
    
    rm -f "$ENV_VARS_FILE"
    
    if [ $deploy_exit_code -ne 0 ]; then
        print_message "red" "\nERROR: Step 'Deploying Cloud Function $CF_NAME' failed with exit code $deploy_exit_code."
        print_message "red" "Exiting script due to error."
        exit $deploy_exit_code
    else
        print_message "green" "SUCCESS: Step 'Deploying Cloud Function $CF_NAME' completed."
    fi
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
        --attempt-deadline=1m \
        --oidc-service-account-email="$DEFAULT_SA_EMAIL" \
        --location="$REGION" \
        --time-zone=UTC \
        --project="$PROJECT_ID"
    check_error "Creating Cloud Scheduler job $SCHEDULER_NAME"
}

main() {
    print_message "green" "Starting GCP Deployment Script for Cyjax..."
    prompt_for_input

    print_message "yellow" "\n--- Setting gcloud Configuration ---"
    gcloud config set project "$PROJECT_ID"
    check_error "Setting gcloud project to $PROJECT_ID"
    
    enable_apis
    configure_default_service_account
    create_bucket
    create_secrets
    upload_cf_zip
    deploy_cloud_function
    configure_scheduler

    print_message "green" "\n--- Deployment Script Complete ---"
    print_message "green" "All components deployed and configured."
    print_message "yellow" "Next Steps:"
    print_message "yellow" "1. Verify Cloud Function logs for any errors."
    print_message "yellow" "2. Check Cloud Scheduler job for successful runs."
    print_message "yellow" "3. Monitor Cyjax indicator ingestion in Google SecOps."
}

main
