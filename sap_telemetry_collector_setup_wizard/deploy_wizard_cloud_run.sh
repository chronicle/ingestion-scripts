#!/bin/bash
# ==============================================================================
# SAP Telemetry Collector Setup Wizard - Cloud Run Deployment Script
# Uses "gcloud run deploy --source ." for zero-config managed source build & deploy
# ==============================================================================
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}==============================================================================${NC}"
echo -e "${BLUE}  SAP Telemetry Collector Setup Wizard - Cloud Run Automated Deployment  ${NC}"
echo -e "${BLUE}==============================================================================${NC}"

# 1. Detect Active GCP Project
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null || true)
if [ -n "$CURRENT_PROJECT" ] && [ "$CURRENT_PROJECT" != "(unset)" ]; then
  read -p "Use active GCP Project [${CURRENT_PROJECT}]? (Y/n): " USE_ACTIVE
  USE_ACTIVE=${USE_ACTIVE:-Y}
  if [[ "$USE_ACTIVE" =~ ^[Yy]$ ]]; then
    PROJECT_ID="$CURRENT_PROJECT"
  fi
fi

if [ -z "$PROJECT_ID" ]; then
  read -p "Enter Google Cloud Project ID: " PROJECT_ID
fi

if [ -z "$PROJECT_ID" ]; then
  echo -e "${RED}[ERROR] GCP Project ID is required. Exiting.${NC}"
  exit 1
fi

gcloud config set project "$PROJECT_ID" --quiet

REGION="us-central1"
SERVICE_NAME="sap-telemetry-collector-setup-wizard"
SA_NAME="sap-collector-wizard-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo -e "\n${BLUE}[1/4] Enabling required Google Cloud APIs...${NC}"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  secretmanager.googleapis.com \
  iam.googleapis.com \
  --project="${PROJECT_ID}"
echo -e "${GREEN}[OK] Required Google Cloud APIs enabled successfully.${NC}"

echo -e "\n${BLUE}[2/4] Configuring Cloud Run Service Account (${SA_EMAIL})...${NC}"
if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo -e "${GREEN}[OK] Service account ${SA_EMAIL} already exists.${NC}"
else
  echo -e "${YELLOW}Creating Service Account ${SA_EMAIL}...${NC}"
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="SAP Telemetry Collector Wizard Service Account" \
    --project="${PROJECT_ID}"
  echo -e "${GREEN}[OK] Service account created successfully.${NC}"
fi

echo -e "\n${BLUE}[3/4] Binding Least-Privilege Runtime IAM Permissions to Cloud Run SA...${NC}"
# In accordance with GCP security best practices, the Cloud Run web service
# runs with minimal runtime permissions (logging only). Administrative roles
# (e.g. securityAdmin, serviceAccountAdmin) are never granted to the web container.
# Infrastructure provisioning is executed via Terraform or deploy.sh in the admin's session.
ROLES=(
  "roles/logging.logWriter"
)

IAM_FAILED=0
for ROLE in "${ROLES[@]}"; do
  echo -e "Binding role: ${YELLOW}${ROLE}${NC}"
  if gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --quiet >/dev/null 2>&1; then
    echo -e "${GREEN}  -> [OK] Bound ${ROLE}${NC}"
  else
    IAM_FAILED=1
    echo -e "${YELLOW}  -> [NOTE] User session lacks permission to bind ${ROLE} directly.${NC}"
  fi
done

if [ $IAM_FAILED -eq 1 ]; then
  echo -e "\n${YELLOW}==============================================================================${NC}"
  echo -e "${YELLOW}[NOTE] If any IAM bindings were skipped, ask a GCP Project Admin to run:${NC}"
  for ROLE in "${ROLES[@]}"; do
    echo -e "  gcloud projects add-iam-policy-binding ${PROJECT_ID} --member=\"serviceAccount:${SA_EMAIL}\" --role=\"${ROLE}\""
  done
  echo -e "${YELLOW}==============================================================================${NC}\n"
else
  echo -e "${GREEN}[OK] All required IAM permissions bound successfully.${NC}"
fi

echo -e "\n${BLUE}[4/4] Building & Deploying Setup Wizard Service to Cloud Run (gcloud run deploy --source .)...${NC}"
gcloud run deploy "${SERVICE_NAME}" \
  --source . \
  --region="${REGION}" \
  --service-account="${SA_EMAIL}" \
  --port=8080 \
  --no-allow-unauthenticated \
  --project="${PROJECT_ID}"

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')

echo -e "\n${GREEN}==============================================================================${NC}"
echo -e "${GREEN}  SAP Telemetry Collector Setup Wizard Deployed Successfully to Cloud Run!  ${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo -e "  Cloud Run Service Name : ${SERVICE_NAME}"
echo -e "  GCP Region             : ${REGION}"
echo -e "  Service Account        : ${SA_EMAIL}"
echo -e "  Wizard Service URL     : ${SERVICE_URL}"
echo -e "  Security Policy        : IAM Authenticated (--no-allow-unauthenticated)"
echo -e "${GREEN}==============================================================================${NC}"
echo -e "\n${BLUE}[Access Instructions]${NC}"
echo -e "The wizard is protected with Cloud Run IAM authentication."
echo -e "To access the web interface securely from your local workstation:"
echo -e "\n1. Run the local authenticated proxy:"
echo -e "   ${YELLOW}gcloud run services proxy ${SERVICE_NAME} --region ${REGION} --port 8080${NC}"
echo -e "\n2. Open the wizard in your web browser:"
echo -e "   ${GREEN}http://127.0.0.1:8080${NC}"
echo -e "${GREEN}==============================================================================${NC}"
