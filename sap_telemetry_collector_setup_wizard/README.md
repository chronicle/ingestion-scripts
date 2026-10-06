# SAP Telemetry Collector Setup Wizard

An interactive deployment wizard and configuration hub for setting up the
**SAP Telemetry Collector for Google Cloud SecOps**. It guides administrators
through configuring, provisioning, and deploying telemetry ingestion pipelines
from SAP NetWeaver systems into Google Cloud SecOps.

> [!IMPORTANT]
> **Disclaimer**: This is not an officially supported Google product. This
> project is open source software provided as-is without SLA or technical
> support from Google Cloud Support. The Cloud Run instance and related
> resources created in the customer GCP environment to host this wizard are
> owned and managed by the customer.

---

## Automated Deployment to Google Cloud Run

To deploy the wizard as a web application on Google Cloud Run inside your
GCP project:

### Prerequisites

- [Google Cloud CLI (`gcloud`)](https://cloud.google.com/sdk/docs/install)
  installed and authenticated (`gcloud auth login`).
- A GCP project with permissions to create Cloud Run services and service
  accounts.

### Deployment Steps

```bash
# 1. Clone the repository and navigate to the wizard directory
git clone https://github.com/chronicle/ingestion-scripts.git
cd ingestion-scripts/sap_telemetry_collector_setup_wizard

# 2. Make the deployment script executable and run
chmod +x deploy_wizard_cloud_run.sh
./deploy_wizard_cloud_run.sh
```

**What the deployment script does automatically:**
1. **Detects GCP Project**: Identifies the active project from `gcloud config`
   or prompts you to enter the target GCP Project ID.
2. **Enables APIs**: Activates required Google Cloud APIs (`run.googleapis.com`,
   `cloudbuild.googleapis.com`, `compute.googleapis.com`,
   `storage.googleapis.com`, `secretmanager.googleapis.com`,
   `iam.googleapis.com`).
3. **Creates Service Account**: Provisions a dedicated Cloud Run runtime
   service account
   (`sap-collector-wizard-sa@<PROJECT_ID>.iam.gserviceaccount.com`).
4. **Binds Minimal IAM**: Grants least-privilege runtime logging permissions
   (`roles/logging.logWriter`). Administrative provisioning roles are reserved
   for the operator running Terraform or shell deployment scripts
   (`deploy.sh`).
5. **Builds & Deploys**: Builds the container via Google Cloud Build and deploys
   the service `sap-telemetry-collector-setup-wizard` to Cloud Run in
   `us-central1` with `--no-allow-unauthenticated`.
6. **Outputs Connection Details**: Displays the deployed service URL and proxy
   access instructions.

### Accessing the Deployed Wizard

The wizard is deployed with Cloud Run IAM authentication enforced
(`--no-allow-unauthenticated`) to protect the service from unauthorized
access.

To access the web interface securely from your local workstation, run Google
Cloud's built-in authenticated proxy:

```bash
# 1. Start the local authenticated proxy
gcloud run services proxy sap-telemetry-collector-setup-wizard \
  --region us-central1 --port 8080

# 2. Open the wizard in your web browser
http://127.0.0.1:8080
```

The proxy attaches your active `gcloud` identity credentials to requests,
allowing you to securely navigate the wizard in your browser without exposing
the service to unauthenticated public traffic.

### Teardown and Cleanup

Once you have completed configuring and provisioning the SAP Telemetry
Collector, you can tear down the setup wizard and its staging resources:

```bash
chmod +x purge_wizard_artifacts.sh
./purge_wizard_artifacts.sh
```

---

## License

This project is licensed under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).
