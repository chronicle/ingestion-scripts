#!/bin/bash
# ==============================================================================
# SAP Telemetry Collector Setup Wizard - Cloud Run & Infrastructure Teardown Script
# Purges all GCP resources provisioned by the deployment script and setup wizard.
# ==============================================================================
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${RED}==============================================================================${NC}"
echo -e "${RED}  SAP Telemetry Collector Setup Wizard - GCP Artifact Teardown & Purge  ${NC}"
echo -e "${RED}==============================================================================${NC}"

# 1. Detect Active GCP Project
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null || true)
if [ -n "$CURRENT_PROJECT" ] && [ "$CURRENT_PROJECT" != "(unset)" ]; then
  read -p "Target GCP Project ID for Purge [${CURRENT_PROJECT}]? (Y/n): " USE_ACTIVE
  USE_ACTIVE=${USE_ACTIVE:-Y}
  if [[ "$USE_ACTIVE" =~ ^[Yy]$ ]]; then
    PROJECT_ID="$CURRENT_PROJECT"
  fi
fi

if [ -z "$PROJECT_ID" ]; then
  read -p "Enter Google Cloud Project ID to purge: " PROJECT_ID
fi

if [ -z "$PROJECT_ID" ]; then
  echo -e "${RED}[ERROR] GCP Project ID is required. Exiting.${NC}"
  exit 1
fi

# Prompt for custom GCS Bucket Name
read -p "Enter GCS Bucket Name to purge (e.g. sap-telemetry-collector-configuration) [press Enter to auto-detect]: " TARGET_BUCKET_NAME
TARGET_BUCKET_NAME=$(echo "$TARGET_BUCKET_NAME" | sed 's|^gs://||')

REGION="${REGION:-us-central1}"
SERVICE_NAME="sap-telemetry-collector-setup-wizard"
SA_EMAIL="sap-collector-wizard-sa@${PROJECT_ID}.iam.gserviceaccount.com"
GCE_VM_NAME="sap-telemetry-collector-vm"

# Dynamically resolve GCE VM Zone if instance exists
DETECTED_ZONE=$(gcloud compute instances list --filter="name=${GCE_VM_NAME}" --project="${PROJECT_ID}" --format="value(zone.basename())" 2>/dev/null | head -n 1 || true)
ZONE="${DETECTED_ZONE:-${ZONE:-us-central1-a}}"

# Resolve candidate GCS bucket(s) before prompting for confirmation
BUCKETS_TO_DELETE=()
if [ -n "$TARGET_BUCKET_NAME" ]; then
  BUCKETS_TO_DELETE+=("$TARGET_BUCKET_NAME")
else
  echo -e "\n${YELLOW}Detecting GCS buckets matching 'sap-telemetry-collector-*' in project '${PROJECT_ID}'...${NC}"
  DETECTED=$(gcloud storage buckets list --project="${PROJECT_ID}" --format="value(name)" 2>/dev/null | grep -E "sap-telemetry-collector-|secops-sap-telemetry-collector-wizard" || true)
  if [ -n "$DETECTED" ]; then
    while IFS= read -r b; do
      if [ -n "$b" ]; then
        BUCKETS_TO_DELETE+=("$b")
      fi
    done <<< "$DETECTED"
  fi
fi

echo -e "\n${RED}[WARNING] This script will permanently delete the following GCP resources in project '${PROJECT_ID}':${NC}"
echo -e "  1. Cloud Run Service: ${SERVICE_NAME} in region ${REGION}"
echo -e "  2. Compute Engine VM: ${GCE_VM_NAME} in zone ${ZONE}"
echo -e "  3. Service Account IAM Policy Bindings (Core Roles)"
echo -e "  4. Service Account: ${SA_EMAIL}"
if [ ${#BUCKETS_TO_DELETE[@]} -gt 0 ]; then
  echo -e "  5. Target GCS Bucket(s) to delete:"
  for b in "${BUCKETS_TO_DELETE[@]}"; do
    echo -e "     - gs://${b}"
  done
else
  echo -e "  5. Target GCS Bucket(s): None detected"
fi
echo -e ""

read -p "Are you sure you want to proceed with resource deletion? (y/N): " CONFIRM_PURGE
if [[ ! "$CONFIRM_PURGE" =~ ^[Yy]$ ]]; then
  echo -e "${YELLOW}Purge cancelled by user. Exiting without changes.${NC}"
  exit 0
fi

# 1. Delete Cloud Run Service
echo -e "\n${BLUE}[1/5] Deleting Cloud Run Service '${SERVICE_NAME}' in ${REGION}...${NC}"
if gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud run services delete "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --quiet
  echo -e "${GREEN}[OK] Cloud Run service deleted.${NC}"
else
  echo -e "${YELLOW}[SKIP] Cloud Run service '${SERVICE_NAME}' not found.${NC}"
fi

# 2. Delete Provisioned Compute Engine VM
echo -e "\n${BLUE}[2/5] Deleting Compute Engine VM '${GCE_VM_NAME}' in zone ${ZONE}...${NC}"
if gcloud compute instances describe "${GCE_VM_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute instances delete "${GCE_VM_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" --quiet
  echo -e "${GREEN}[OK] Compute Engine VM deleted.${NC}"
else
  echo -e "${YELLOW}[SKIP] Compute Engine VM '${GCE_VM_NAME}' not found in zone ${ZONE}.${NC}"
fi

# 3. Revoke Service Account IAM Policy Bindings
echo -e "\n${BLUE}[3/5] Revoking IAM Policy Bindings for '${SA_EMAIL}'...${NC}"
ROLES=(
  "roles/compute.instanceAdmin.v1"
  "roles/storage.admin"
  "roles/iam.serviceAccountAdmin"
  "roles/iam.securityAdmin"
  "roles/iam.serviceAccountUser"
  "roles/logging.logWriter"
)

for ROLE in "${ROLES[@]}"; do
  echo -e "Revoking role binding: ${YELLOW}${ROLE}${NC}"
  gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --quiet >/dev/null 2>&1 || true
done
echo -e "${GREEN}[OK] IAM Policy Bindings revoked successfully.${NC}"

# 4. Delete Service Account
echo -e "\n${BLUE}[4/5] Deleting Service Account '${SA_EMAIL}'...${NC}"
if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts delete "${SA_EMAIL}" --project="${PROJECT_ID}" --quiet
  echo -e "${GREEN}[OK] Service account deleted.${NC}"
else
  echo -e "${YELLOW}[SKIP] Service account '${SA_EMAIL}' not found.${NC}"
fi

# 5. Delete GCS Config & State Bucket(s)
echo -e "\n${BLUE}[5/5] Purging GCS Configuration & State Bucket(s)...${NC}"
BUCKETS_TO_DELETE=()

if [ -n "$TARGET_BUCKET_NAME" ]; then
  BUCKETS_TO_DELETE+=("$TARGET_BUCKET_NAME")
else
  echo -e "${YELLOW}Auto-detecting GCS buckets matching 'sap-telemetry-collector-*' in project ${PROJECT_ID}...${NC}"
  DETECTED=$(gcloud storage buckets list --project="${PROJECT_ID}" --format="value(name)" 2>/dev/null | grep -E "sap-telemetry-collector-|secops-sap-telemetry-collector-wizard" || true)
  if [ -n "$DETECTED" ]; then
    while IFS= read -r b; do
      if [ -n "$b" ]; then
        BUCKETS_TO_DELETE+=("$b")
      fi
    done <<< "$DETECTED"
  fi
fi

if [ ${#BUCKETS_TO_DELETE[@]} -eq 0 ]; then
  echo -e "${YELLOW}[SKIP] No matching GCS buckets found to purge.${NC}"
else
  for BUCKET in "${BUCKETS_TO_DELETE[@]}"; do
    echo -e "Purging GCS Bucket: ${YELLOW}gs://${BUCKET}${NC}"
    if gcloud storage buckets describe "gs://${BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      gcloud storage rm -r "gs://${BUCKET}" --quiet
      echo -e "${GREEN}[OK] GCS Bucket gs://${BUCKET} deleted.${NC}"
    else
      echo -e "${YELLOW}[SKIP] Bucket gs://${BUCKET} not found.${NC}"
    fi
  done
fi

echo -e "\n${GREEN}==============================================================================${NC}"
echo -e "${GREEN}  SAP Telemetry Collector Setup Wizard Resources Teardown Complete!  ${NC}"
echo -e "${GREEN}==============================================================================${NC}"
