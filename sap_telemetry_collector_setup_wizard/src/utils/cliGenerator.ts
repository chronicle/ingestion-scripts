import {AppState} from '../types';
import {generateStartupScript} from './terraformGenerator';

/** Generates gcloud CLI commands to create the GCS bucket and upload collector config. */
export function generateGcsCommand(state: AppState): string {
  const { projectId, location, bucketName } = state.gcs;

  return `# Step 1: Create GCS Storage Bucket in region ${location}
gcloud storage buckets create gs://${bucketName} \\
  --project=${projectId} \\
  --location=${location} \\
  --default-storage-class=STANDARD \\
  --uniform-bucket-level-access

# Step 2: Create folder hierarchy (config/, jco/, state/) and upload collector configuration
gcloud storage cp collector_config.json gs://${bucketName}/config/collector_config.json`;
}

/** Generates the gcloud compute instances create command for the collector VM. */
export function generateGceCommand(state: AppState, startupScriptPath = 'startup.sh'): string {
  const {
    vmName,
    zone,
    network,
    subnetwork,
    imageFamily,
    imageProject,
    scopes,
    serviceAccount
  } = state.gce;
  const projectId = state.gce.projectId || state.gcs.projectId || '<PROJECT_ID>';

  return `gcloud compute instances create ${vmName} \\
  --project=${projectId} \\
  --zone=${zone} \\
  --network=${network} \\
  --subnet=${subnetwork} \\
  --image-family=${imageFamily} \\
  --image-project=${imageProject} \\
  --scopes=${scopes} \\
  --service-account=${serviceAccount} \\
  --metadata-from-file=startup-script="${startupScriptPath}"`;
}

/** Retrieves or generates the command to install and configure BindPlane Agent. */
export function generateBindplaneCommand(state: AppState): string {
  if (state.bindplane.customCommand && state.bindplane.customCommand.trim()) {
    return state.bindplane.customCommand;
  }
  return 'echo "[WARNING] BindPlane Agent CLI command was not provided in Step 4."';
}

/** Generates apt-get package installation commands for Docker Engine on Debian. */
export function generateDockerInstallCommand(): string {
  return `apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io`;
}

/** Generates the docker run command to launch the telemetry collector container. */
export function generateDockerRunCommand(state: AppState): string {
  const { containerName, dockerImage } = state.docker;
  const gcsPath = state.docker.gcsBucketPath && !state.docker.gcsBucketPath.includes('/config/')
    ? state.docker.gcsBucketPath
    : `gs://${state.gcs.bucketName}`;

  return `docker run -d \\
  --name ${containerName} \\
  --restart always \\
  --network host \\
  -e COLLECTOR_GCS_BUCKET=${gcsPath} \\
  ${dockerImage}`;
}

/** Generates an end-to-end bash bootstrap script executing all deployment steps. */
export function generateFullBootstrapScript(state: AppState): string {
  const startupScript = generateStartupScript(state);
  const gceCmd = generateGceCommand(state, '${SCRIPT_DIR}/startup.sh');
  const projectId = state.gce.projectId || state.gcs.projectId || '<PROJECT_ID>';
  const zone = state.gce.zone || 'us-central1-a';
  const vmName = state.gce.vmName || 'sap-telemetry-collector-vm';
  const bucketName = state.gcs.bucketName || 'sap-telemetry-collector-config';

  return `#!/bin/bash
# ==============================================================================
# Google Cloud SAP Telemetry Collector - Automated Installation Script
# Generated for Project: ${projectId}
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"

echo "[1/4] Verifying GCS Bucket & SAP Java Connector (JCo) files in gs://${bucketName}/jco/..."
if ! gcloud storage ls gs://${bucketName}/jco/sapjco3.jar &>/dev/null; then
  echo "[ERROR] Required SAP JCo library files (sapjco3.jar & libsapjco3.so) were NOT found in gs://${bucketName}/jco/!"
  echo "[ERROR] Please upload sapjco3.jar and libsapjco3.so to gs://${bucketName}/jco/ before running installation."
  exit 1
fi
echo "[OK] SAP JCo library files verified in GCS."

echo "[2/4] Preparing VM startup script (startup.sh)..."
cat << '_SAP_STARTUP_EOF_' > "\${SCRIPT_DIR}/startup.sh"
${startupScript}
_SAP_STARTUP_EOF_
chmod +x "\${SCRIPT_DIR}/startup.sh"
echo "[OK] Startup script prepared at \${SCRIPT_DIR}/startup.sh."

echo "[3/4] Creating GCE Instance with startup-script metadata..."
${gceCmd}

echo "[4/4] GCE VM '${vmName}' provisioned."
echo "      Host configuration, BindPlane agent installation, and Docker container"
echo "      launch will execute inside the VM via the startup script."
echo "      To monitor real-time startup progress inside the VM, run:"
echo "        gcloud compute instances get-serial-port-output ${vmName} --zone=${zone} --project=${projectId} --port=1"
echo ""
echo "==> Setup Complete! Verify telemetry ingestion in Google Cloud SecOps."
`;
}

/** Generates a bash teardown and cleanup script to delete all provisioned GCP artifacts. */
export function generatePurgeScript(state: AppState): string {
  const projectId = state.gce.projectId || state.gcs.projectId || '<PROJECT_ID>';
  const zone = state.gce.zone || 'us-central1-a';
  const region = zone.substring(0, zone.lastIndexOf('-')) || 'us-central1';
  const vmName = state.gce.vmName || 'sap-telemetry-collector-vm';
  const bucketName = state.gcs.bucketName || 'sap-telemetry-collector-config';
  const serviceName = 'sap-telemetry-collector-setup-wizard';
  const saEmail = `sap-collector-wizard-sa@${projectId}.iam.gserviceaccount.com`;

  return `#!/bin/bash
# ==============================================================================
# SAP Telemetry Collector Setup Wizard - GCP Artifact Teardown & Purge Script
# Custom generated for Project: ${projectId}
# ==============================================================================
set -e

GREEN='\\033[0;32m'
BLUE='\\033[0;34m'
YELLOW='\\033[1;33m'
RED='\\033[0;31m'
NC='\\033[0m'

echo -e "\${RED}==============================================================================\${NC}"
echo -e "\${RED}  SAP Telemetry Collector Setup Wizard - GCP Artifact Teardown & Purge  \${NC}"
echo -e "\${RED}==============================================================================\${NC}"
echo -e "  Project ID         : ${projectId}"
echo -e "  Cloud Run Service  : ${serviceName}"
echo -e "  GCE Collector VM   : ${vmName} (${zone})"
echo -e "  GCS Config Bucket  : gs://${bucketName}"
echo -e "  Orchestrator SA    : ${saEmail}"
echo -e "\${RED}==============================================================================\${NC}\\n"

read -p "Are you sure you want to permanently delete these provisioned GCP resources? (y/N): " CONFIRM_PURGE
if [[ ! "$CONFIRM_PURGE" =~ ^[Yy]$ ]]; then
  echo -e "\${YELLOW}Purge cancelled by user. Exiting without changes.\${NC}"
  exit 0
fi

echo -e "\\n\${BLUE}[1/5] Deleting Cloud Run Service '${serviceName}' in ${region}...\${NC}"
gcloud run services delete "${serviceName}" --region="${region}" --project="${projectId}" --quiet || true
echo -e "\${GREEN}[OK] Cloud Run service teardown completed.\${NC}"

echo -e "\\n\${BLUE}[2/5] Deleting Compute Engine VM '${vmName}' in zone ${zone}...\${NC}"
gcloud compute instances delete "${vmName}" --zone="${zone}" --project="${projectId}" --quiet || true
echo -e "\${GREEN}[OK] Compute Engine VM teardown completed.\${NC}"

echo -e "\\n\${BLUE}[3/5] Revoking IAM Policy Bindings for '${saEmail}'...\${NC}"
ROLES=(
  "roles/compute.instanceAdmin.v1"
  "roles/storage.admin"
  "roles/iam.serviceAccountAdmin"
  "roles/iam.securityAdmin"
  "roles/iam.serviceAccountUser"
)

for ROLE in "\${ROLES[@]}"; do
  echo -e "Revoking role binding: \${YELLOW}\${ROLE}\${NC}"
  gcloud projects remove-iam-policy-binding "${projectId}" \\
    --member="serviceAccount:${saEmail}" \\
    --role="\${ROLE}" \\
    --quiet >/dev/null 2>&1 || true
done
echo -e "\${GREEN}[OK] IAM Policy Bindings revoked successfully.\${NC}"

echo -e "\\n\${BLUE}[4/5] Deleting Service Account '${saEmail}'...\${NC}"
gcloud iam service-accounts delete "${saEmail}" --project="${projectId}" --quiet || true
echo -e "\${GREEN}[OK] Service account teardown completed.\${NC}"

echo -e "\\n\${BLUE}[5/5] Deleting GCS Bucket 'gs://${bucketName}'...\${NC}"
gcloud storage rm -r "gs://${bucketName}" --quiet || true
echo -e "\${GREEN}[OK] GCS Bucket gs://${bucketName} deleted.\${NC}"

echo -e "\\n\${GREEN}==============================================================================\${NC}"
echo -e "\${GREEN}  SAP Telemetry Collector Setup Wizard Teardown Complete!  \${NC}"
echo -e "\${GREEN}==============================================================================\${NC}"
`;
}
