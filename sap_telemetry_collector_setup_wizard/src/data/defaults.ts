import {AppState, WizardStepMeta} from '../types';

/** Default initial state for the wizard configuration form fields. */
export const INITIAL_APP_STATE: AppState = {
  collector: {
    bindplaneHost: "0.0.0.0",
    bindplanePort: "4317",
    heartbeat_enabled: true,
    systems: [
      {
        systemId: "",
        connection: {
          host: "",
          client: "",
          systemNumber: ""
        },
        auth: {
          basic: {
            usernameSecret: "",
            passwordSecret: ""
          }
        },
        logSources: [
          {
            logType: "SAP_SECURITY_AUDIT",
            interval: "600s"
          }
        ],
        initialLookbackWindow: ""
      }
    ]
  },
  gcs: {
    projectId: "",
    location: "",
    bucketName: "",
    subfolderPath: "config",
    storageClass: "STANDARD",
    enableVersioning: true,
    uniformBucketLevelAccess: true,
    bucketCreated: false,
    jcoFilesUploaded: false
  },
  gce: {
    vmName: "sap-telemetry-collector-vm",
    projectId: "",
    zone: "",
    network: "default",
    subnetwork: "default",
    machineType: "e2-standard-4",
    imageFamily: "debian-12",
    imageProject: "debian-cloud",
    diskSizeGb: 50,
    scopes: "cloud-platform",
    serviceAccount: "default",
    enableExternalIP: true,
    tags: ["sap-telemetry", "secops-collector"]
  },
  bindplane: {
    serverUrl: "",
    secretKey: "",
    agentVersion: "1.105.1",
    labels: "",
    installScriptUrl: "",
    customCommand: "",
    bindplaneServerIp: "",
    bindplaneServerName: ""
  },
  docker: {
    containerName: "sap-telemetry-collector",
    restartPolicy: "always",
    networkMode: "host",
    gcsBucketPath: "",
    dockerImage: "us-docker.pkg.dev/sap-core-eng-products/sap-application-telemetry/google-cloud-sap-application-telemetry:latest"
  },
  cloudRunServiceAccount: ""
};

/** Step definition metadata for the wizard stages. */
export const WIZARD_STEPS: WizardStepMeta[] = [
  {
    id: 1,
    title: "1. SAP Telemetry Configuration",
    shortTitle: "JSON Config",
    description: "Configure SAP systems, connection properties, Secret Manager credentials, and log sources.",
    badgeText: "Step 1/6"
  },
  {
    id: 2,
    title: "2. Google Cloud Storage Setup",
    shortTitle: "GCS Bucket",
    description: "Define GCS bucket location & path to store collector configuration file.",
    badgeText: "Step 2/6"
  },
  {
    id: 3,
    title: "3. Compute Engine VM Setup",
    shortTitle: "GCE Instance",
    description: "Specify GCE VM instance details, zone, machine specs, network & subnetwork.",
    badgeText: "Step 3/6"
  },
  {
    id: 4,
    title: "4. BindPlane Agent Setup",
    shortTitle: "BindPlane Agent",
    description: "Provide BindPlane server OpAMP URL, secret key, version, and labels.",
    badgeText: "Step 4/6"
  },
  {
    id: 5,
    title: "5. Telemetry Collector Container",
    shortTitle: "Docker Setup",
    description: "Configure Docker container parameters and GCS bucket environment variable.",
    badgeText: "Step 5/6"
  },
  {
    id: 6,
    title: "6. Review and Install Collector",
    shortTitle: "Review and Install",
    description: "Review deployment settings, simulate backend installation script, or export Terraform files.",
    badgeText: "Step 6/6"
  }
];

/** Preset architecture landscapes for quick population of sample configurations. */
export const PRESET_LANDSCAPES = {
  defaultPrompt: {
    name: "User Spec Default (Single System DOC)",
    description: "Matches prompt example with system DOC, PFCG & IDENTITY change documents.",
    state: INITIAL_APP_STATE
  },
  multiSystemProd: {
    name: "Multi-System Production Landscape (PRD, QAS, DEV)",
    description: "High-availability multi-system SAP landscape with security audit, change document, and HTTP logs.",
    state: {
      ...INITIAL_APP_STATE,
      collector: {
        bindplaneHost: "0.0.0.0",
        bindplanePort: "4317",
        heartbeat_enabled: true,
        systems: [
          {
            systemId: "PRD",
            connection: {
              host: "10.140.0.12",
              client: "100",
              systemNumber: "00"
            },
            auth: {
              basic: {
                usernameSecret: "projects/sap-secops-prod/secrets/sap-prd-secops-username/versions/latest",
                passwordSecret: "projects/sap-secops-prod/secrets/sap-prd-secops-password/versions/latest"
              }
            },
            logSources: [
              { logType: "SAP_SECURITY_AUDIT", interval: "1800s" },
              { logType: "SAP_CHANGE_DOCUMENT", interval: "1800s", changeDocumentObjectClasses: ["PFCG", "IDENTITY", "USER"] }
            ],
            initialLookbackWindow: "1800s"
          },
          {
            systemId: "QAS",
            connection: {
              host: "10.140.1.25",
              client: "200",
              systemNumber: "01"
            },
            auth: {
              basic: {
                usernameSecret: "projects/sap-secops-prod/secrets/sap-qas-secops-username/versions/latest",
                passwordSecret: "projects/sap-secops-prod/secrets/sap-qas-secops-password/versions/latest"
              }
            },
            logSources: [
              { logType: "SAP_SECURITY_AUDIT", interval: "3600s" },
              { logType: "SAP_CHANGE_DOCUMENT", interval: "3600s", changeDocumentObjectClasses: ["PFCG"] }
            ],
            initialLookbackWindow: "600s"
          }
        ]
      },
      gcs: {
        projectId: "sap-secops-prod",
        location: "europe-west3",
        bucketName: "sap-prod-secops-telemetry-config",
        subfolderPath: "config",
        storageClass: "STANDARD",
        enableVersioning: true,
        uniformBucketLevelAccess: true
      },
      gce: {
        vmName: "sap-telemetry-collector-prod-vm",
        projectId: "sap-secops-prod",
        zone: "europe-west3-a",
        network: "sap-vpc-prod",
        subnetwork: "sap-subnet-prod",
        machineType: "e2-standard-4",
        imageFamily: "debian-12",
        imageProject: "debian-cloud",
        diskSizeGb: 100,
        scopes: "cloud-platform",
        serviceAccount: "sap-collector-sa@sap-secops-prod.iam.gserviceaccount.com",
        enableExternalIP: false,
        tags: ["sap-telemetry-prod", "secops-gateways"]
      }
    }
  }
};
