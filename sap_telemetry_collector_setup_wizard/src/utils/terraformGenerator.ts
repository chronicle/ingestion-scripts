import {AppState} from '../types';

/**
 * Generates the main.tf Terraform file defining the GCE VM instance with the
 * telemetry collector startup script.
 */
export function generateMainTf(state: AppState): string {
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
# Google Compute Engine (GCE) Instance with Startup Script
# ------------------------------------------------------------------------------
resource "google_compute_instance" "collector_vm" {
  name         = var.vm_name
  machine_type = var.machine_type
  zone         = var.zone
  project      = var.project_id

  tags = var.tags

  boot_disk {
    initialize_params {
      image = "\${var.image_project}/\${var.image_family}"
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork != "" ? var.subnetwork : null

    dynamic "access_config" {
      for_each = var.enable_external_ip ? [1] : []
      content {
        // Ephemeral public IP assigned
      }
    }
  }

  service_account {
    email  = var.service_account
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    startup-script = file("\${path.module}/startup.sh")
  }
}

# ------------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------------
output "instance_name" {
  description = "The name of the GCE VM instance"
  value       = google_compute_instance.collector_vm.name
}

output "instance_ip" {
  description = "The IP address of the GCE VM instance"
  value       = try(google_compute_instance.collector_vm.network_interface[0].access_config[0].nat_ip, google_compute_instance.collector_vm.network_interface[0].network_ip)
}

output "service_account_email" {
  description = "The service account email attached to the GCE VM instance"
  value       = google_compute_instance.collector_vm.service_account[0].email
}
`;
}

/** Generates variables.tf declaring input variables for the Terraform configuration. */
export function generateVariablesTf(state: AppState): string {
  const projectId = state.gce.projectId || state.gcs.projectId || '';
  const zone = state.gce.zone || 'us-central1-a';
  const region = state.gcs.location ||
      (zone.includes('-') ? zone.substring(0, zone.lastIndexOf('-')) :
                            'us-central1');
  const serviceAccount =
      (state.gce.serviceAccount && state.gce.serviceAccount !== 'default') ?
      state.gce.serviceAccount :
      (state.cloudRunServiceAccount || state.gce.serviceAccount || 'default');

  return `variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
  default     = "${projectId}"
}

variable "region" {
  type        = string
  description = "GCP Region"
  default     = "${region}"
}

variable "zone" {
  type        = string
  description = "GCP Zone"
  default     = "${zone}"
}

variable "vm_name" {
  type        = string
  description = "GCE VM instance name"
  default     = "${state.gce.vmName || 'sap-telemetry-collector-vm'}"
}

variable "machine_type" {
  type        = string
  description = "Compute Instance Machine Type"
  default     = "${state.gce.machineType || 'e2-standard-4'}"
}

variable "network" {
  type        = string
  description = "VPC Network name"
  default     = "${state.gce.network || 'default'}"
}

variable "subnetwork" {
  type        = string
  description = "Subnet name"
  default     = "${state.gce.subnetwork || 'default'}"
}

variable "disk_size_gb" {
  type        = number
  description = "Boot disk size in GB"
  default     = ${state.gce.diskSizeGb || 50}
}

variable "image_project" {
  type        = string
  description = "OS Image Project"
  default     = "${state.gce.imageProject || 'debian-cloud'}"
}

variable "image_family" {
  type        = string
  description = "OS Image Family"
  default     = "${state.gce.imageFamily || 'debian-12'}"
}

variable "enable_external_ip" {
  type        = bool
  description = "Whether to assign an ephemeral external public IP to the VM"
  default     = ${state.gce.enableExternalIP ? 'true' : 'false'}
}

variable "tags" {
  type        = list(string)
  description = "Network tags for the VM instance"
  default     = ${JSON.stringify(state.gce.tags || [
    'sap-telemetry', 'secops-collector'
  ])}
}

variable "service_account" {
  type        = string
  description = "Service account email attached to the telemetry collector GCE VM"
  default     = "${serviceAccount}"
}
`;
}

/** Generates terraform.tfvars containing the concrete variable values. */
export function generateTfVars(state: AppState): string {
  const projectId = state.gce.projectId || state.gcs.projectId || '';
  const zone = state.gce.zone || 'us-central1-a';
  const region = state.gcs.location ||
      (zone.includes('-') ? zone.substring(0, zone.lastIndexOf('-')) :
                            'us-central1');
  const serviceAccount =
      (state.gce.serviceAccount && state.gce.serviceAccount !== 'default') ?
      state.gce.serviceAccount :
      (state.cloudRunServiceAccount || state.gce.serviceAccount || 'default');

  return `project_id         = "${projectId}"
region             = "${region}"
zone               = "${zone}"
vm_name            = "${state.gce.vmName || 'sap-telemetry-collector-vm'}"
machine_type       = "${state.gce.machineType || 'e2-standard-4'}"
network            = "${state.gce.network || 'default'}"
subnetwork         = "${state.gce.subnetwork || 'default'}"
disk_size_gb       = ${state.gce.diskSizeGb || 50}
image_project      = "${state.gce.imageProject || 'debian-cloud'}"
image_family       = "${state.gce.imageFamily || 'debian-12'}"
enable_external_ip = ${state.gce.enableExternalIP ? 'true' : 'false'}
tags               = ${JSON.stringify(state.gce.tags || [
    'sap-telemetry', 'secops-collector'
  ])}
service_account    = "${serviceAccount}"
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

  const effectiveGcsBucket =
      (state.docker.gcsBucketPath &&
       !state.docker.gcsBucketPath.includes('/config/')) ?
      state.docker.gcsBucketPath :
      `gs://${state.gcs.bucketName}`;
  const containerName = state.docker.containerName || 'sap-telemetry-collector';
  const dockerImage = state.docker.dockerImage ||
      'us-docker.pkg.dev/sap-core-eng-products/sap-application-telemetry/google-cloud-sap-application-telemetry:latest';
  const restartPolicy = state.docker.restartPolicy || 'always';
  const networkMode = state.docker.networkMode || 'host';

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

log_event "==> [Event 6/7] Launching Telemetry Collector Container (${
      containerName})..."
sudo docker rm -f ${containerName} >/dev/null 2>&1 || true

sudo docker run -d \\
  --name ${containerName} \\
  --restart ${restartPolicy} \\
  --network ${networkMode} \\
  -e COLLECTOR_GCS_BUCKET="${effectiveGcsBucket}" \\
  ${dockerImage} >/dev/null 2>&1

log_event "==> [Event 7/7] Polling Telemetry Collector Container status..."
CONTAINER_IS_UP=false
for i in {1..10}; do
  CONTAINER_INFO=$(sudo docker ps --filter "name=${
      containerName}" --format '{{.ID}} {{.Image}} {{.Status}}')
  if echo "$CONTAINER_INFO" | grep -q "Up"; then
    CONTAINER_IS_UP=true
    log_event "[SUCCESS] Container ${containerName} is RUNNING: $CONTAINER_INFO"
    break
  fi
  sleep 3
done

if [ "$CONTAINER_IS_UP" = false ]; then
  CONTAINER_ALL=$(sudo docker ps -a --filter "name=${
      containerName}" --format '{{.ID}} {{.Image}} {{.Status}}')
  log_event "[ERROR] Container failed to start. Current status: $CONTAINER_ALL"
fi

log_event "=============================================================================="
log_event "SAP Telemetry Collector Host Deployment Complete!"
log_event "=============================================================================="
`;
}
