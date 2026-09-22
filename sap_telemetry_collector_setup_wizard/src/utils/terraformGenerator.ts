import {AppState} from '../types';

/** Generates the main.tf Terraform file defining GCS, GCE, and IAM resources. */
export function generateMainTf(state: AppState): string {
  const { gcs, gce, bindplane, docker } = state;

  return `# ==============================================================================
# Terraform configuration for Google Cloud SAP Telemetry Collector & BindPlane Agent
# Ingesting SAP Application Logs into SecOps / Chronicle
# ==============================================================================

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ------------------------------------------------------------------------------
# 1. Google Cloud Storage Bucket for Telemetry Collector Configuration
# ------------------------------------------------------------------------------
resource "google_storage_bucket" "collector_config_bucket" {
  name                        = var.bucket_name
  location                    = var.region
  storage_class               = "${gcs.storageClass}"
  force_destroy               = false
  uniform_bucket_level_access = ${gcs.uniformBucketLevelAccess}

  versioning {
    enabled = ${gcs.enableVersioning}
  }

  labels = {
    environment = "secops-telemetry"
    managed_by  = "sap-telemetry-wizard"
  }
}

resource "google_storage_bucket_object" "folder_config" {
  name    = "config/"
  content = " "
  bucket  = google_storage_bucket.collector_config_bucket.name
}

resource "google_storage_bucket_object" "folder_jco" {
  name    = "jco/"
  content = " "
  bucket  = google_storage_bucket.collector_config_bucket.name
}

resource "google_storage_bucket_object" "folder_state" {
  name    = "state/"
  content = " "
  bucket  = google_storage_bucket.collector_config_bucket.name
}

resource "google_storage_bucket_object" "collector_json" {
  name   = "config/collector_config.json"
  bucket = google_storage_bucket.collector_config_bucket.name
  content = jsonencode(${JSON.stringify(state.collector, null, 2)})
  content_type = "application/json"
}

# ------------------------------------------------------------------------------
# 2. Service Account & IAM Roles for Telemetry Collector GCE Instance
# ------------------------------------------------------------------------------
resource "google_service_account" "collector_sa" {
  account_id   = "sap-telemetry-collector-sa"
  display_name = "SAP Telemetry Collector Service Account"
  project      = var.project_id
}

resource "google_storage_bucket_iam_member" "gcs_reader" {
  bucket = google_storage_bucket.collector_config_bucket.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:\${google_service_account.collector_sa.email}"
}

resource "google_project_iam_member" "secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:\${google_service_account.collector_sa.email}"
}

resource "google_project_iam_member" "metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:\${google_service_account.collector_sa.email}"
}

# ------------------------------------------------------------------------------
# 3. Google Compute Engine (GCE) Instance with Startup Script
# ------------------------------------------------------------------------------
resource "google_compute_instance" "collector_vm" {
  name         = var.vm_name
  machine_type = var.machine_type
  zone         = var.zone
  project      = var.project_id

  tags = ${JSON.stringify(gce.tags)}

  boot_disk {
    initialize_params {
      image = "${gce.imageProject}/${gce.imageFamily}"
      size  = ${gce.diskSizeGb}
      type  = "pd-balanced"
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork

    ${gce.enableExternalIP ? `access_config {
      // Ephemeral public IP assigned
    }` : '// Private IP only'}
  }

  service_account {
    email  = google_service_account.collector_sa.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    startup-script = templatefile("\${path.module}/startup.sh", {
      BINDPLANE_SERVER_URL = "${bindplane.serverUrl}"
      BINDPLANE_SECRET     = "${bindplane.secretKey}"
      BINDPLANE_VERSION    = "${bindplane.agentVersion}"
      BINDPLANE_LABELS     = "${bindplane.labels}"
      COLLECTOR_GCS_PATH   = "gs://\${google_storage_bucket.collector_config_bucket.name}/${gcs.subfolderPath}/collector_config.json"
      DOCKER_IMAGE         = "${docker.dockerImage}"
      CONTAINER_NAME       = "${docker.containerName}"
    })
  }

  depends_on = [
    google_storage_bucket_object.collector_json
  ]
}

# ------------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------------
output "instance_name" {
  value = google_compute_instance.collector_vm.name
}

output "instance_ip" {
  value = ${gce.enableExternalIP ? 'google_compute_instance.collector_vm.network_interface[0].access_config[0].nat_ip' : 'google_compute_instance.collector_vm.network_interface[0].network_ip'}
}

output "config_gcs_uri" {
  value = "gs://\${google_storage_bucket.collector_config_bucket.name}/${gcs.subfolderPath}/collector_config.json"
}
`;
}

/** Generates variables.tf declaring input variables for the Terraform configuration. */
export function generateVariablesTf(state: AppState): string {
  return `variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
  default     = "${state.gcs.projectId}"
}

variable "region" {
  type        = string
  description = "GCP Region"
  default     = "${state.gcs.location}"
}

variable "zone" {
  type        = string
  description = "GCP Zone"
  default     = "${state.gce.zone}"
}

variable "bucket_name" {
  type        = string
  description = "GCS bucket name for storing collector JSON"
  default     = "${state.gcs.bucketName}"
}

variable "vm_name" {
  type        = string
  description = "GCE VM instance name"
  default     = "${state.gce.vmName}"
}

variable "machine_type" {
  type        = string
  description = "Compute Instance Machine Type"
  default     = "${state.gce.machineType}"
}

variable "network" {
  type        = string
  description = "VPC Network name"
  default     = "${state.gce.network}"
}

variable "subnetwork" {
  type        = string
  description = "Subnet name"
  default     = "${state.gce.subnetwork}"
}
`;
}

/** Generates terraform.tfvars containing the concrete variable values. */
export function generateTfVars(state: AppState): string {
  return `project_id   = "${state.gcs.projectId}"
region       = "${state.gcs.location}"
zone         = "${state.gce.zone}"
bucket_name  = "${state.gcs.bucketName}"
vm_name      = "${state.gce.vmName}"
machine_type = "${state.gce.machineType}"
network      = "${state.gce.network}"
subnetwork   = "${state.gce.subnetwork}"
`;
}

/** Generates the startup-script.sh used by GCE metadata to initialize the VM. */
export function generateStartupScript(state: AppState): string {
  const bindplaneCmd = state.bindplane.customCommand && state.bindplane.customCommand.trim()
    ? state.bindplane.customCommand
    : 'echo "[WARNING] No BindPlane Agent installation CLI command provided in Step 4. Skipping agent installation."';

  const ip = state.bindplane.bindplaneServerIp ? state.bindplane.bindplaneServerIp.trim() : '';
  const name = state.bindplane.bindplaneServerName ? state.bindplane.bindplaneServerName.trim() : '';

  const hostsUpdateSection = (ip && name)
    ? `log_event "==> [Event 1/7] Updating /etc/hosts for BindPlane Server resolution (${ip} -> ${name})..."\necho "${ip} ${name}" | sudo tee -a /etc/hosts >/dev/null\nlog_event "[SUCCESS] /etc/hosts updated: ${ip} ${name}"`
    : `log_event "==> [Event 1/7] Skipping /etc/hosts update (No BindPlane Server IP / Hostname specified)..."`;

  return `#!/bin/bash
# ==============================================================================
# GCE Startup Script for SAP Telemetry Collector & BindPlane Agent
# ==============================================================================
set -euo pipefail

log_event() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%SZ')] [MILESTONE] $1"
}

log_event "=============================================================================="
log_event "Starting SAP Telemetry Collector Host Deployment"
log_event "=============================================================================="

${hostsUpdateSection}

log_event "==> [Event 2/7] Installing BindPlane Collector Agent..."
set +e
BINDPLANE_OUT=$(${bindplaneCmd} 2>&1)
BINDPLANE_STATUS=$?
set -e

if [ $BINDPLANE_STATUS -eq 0 ]; then
  log_event "[SUCCESS] BindPlane Collector Agent installed successfully."
else
  log_event "[ERROR] BindPlane Agent installation failed (Code $BINDPLANE_STATUS): $(echo "$BINDPLANE_OUT" | tail -n 3)"
fi

log_event "==> [Event 3/7] Waiting 30 seconds for BindPlane Collector Agent to initialize and register..."
sleep 30

log_event "==> [Event 4/7] Checking BindPlane Agent Service Status (observiq-otel-collector)..."
if systemctl is-active --quiet observiq-otel-collector 2>/dev/null || systemctl is-active --quiet bindplane-agent 2>/dev/null; then
  log_event "[SUCCESS] BindPlane Agent (observiq-otel-collector) is ACTIVE and RUNNING."
else
  log_event "[ERROR] BindPlane Agent service is NOT running. Run 'sudo systemctl status observiq-otel-collector' to inspect."
fi

log_event "==> [Event 5/7] Installing Docker Container Engine & Dependencies..."
sudo apt-get update -y >/dev/null 2>&1 || true
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release net-tools >/dev/null 2>&1 || true
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg >/dev/null 2>&1 || true
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y >/dev/null 2>&1 || true
sudo apt-get install -y docker-ce docker-ce-cli containerd.io >/dev/null 2>&1 || true

sudo systemctl enable docker >/dev/null 2>&1 || true
sudo systemctl start docker >/dev/null 2>&1 || true

if systemctl is-active --quiet docker 2>/dev/null; then
  log_event "[SUCCESS] Docker Engine installed and daemon is ACTIVE."
else
  log_event "[ERROR] Docker daemon is not active. Check 'sudo systemctl status docker'."
fi

log_event "==> [Event 6/7] Launching Telemetry Collector Container (${state.docker.containerName})..."
sudo docker rm -f ${state.docker.containerName} >/dev/null 2>&1 || true

sudo docker run -d \\
  --name ${state.docker.containerName} \\
  --restart always \\
  --network host \\
  -e COLLECTOR_GCS_BUCKET="gs://${state.gcs.bucketName}" \\
  ${state.docker.dockerImage} >/dev/null 2>&1

log_event "==> [Event 7/7] Polling Telemetry Collector Container status..."
CONTAINER_IS_UP=false
for i in {1..10}; do
  CONTAINER_INFO=$(sudo docker ps --filter "name=${state.docker.containerName}" --format '{{.ID}} {{.Image}} {{.Status}}')
  if echo "$CONTAINER_INFO" | grep -q "Up"; then
    CONTAINER_IS_UP=true
    log_event "[SUCCESS] Container ${state.docker.containerName} is RUNNING: $CONTAINER_INFO"
    break
  fi
  sleep 3
done

if [ "$CONTAINER_IS_UP" = false ]; then
  CONTAINER_ALL=$(sudo docker ps -a --filter "name=${state.docker.containerName}" --format '{{.ID}} {{.Image}} {{.Status}}')
  log_event "[ERROR] Container failed to start. Current status: $CONTAINER_ALL"
fi

log_event "=============================================================================="
log_event "SAP Telemetry Collector Host Deployment Complete!"
log_event "=============================================================================="
`;
}
