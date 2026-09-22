/** Supported SAP telemetry log types for collection. */
export type LogType =
  | 'SAP_SECURITY_AUDIT'
  | 'SAP_CHANGE_DOCUMENT';

/** Configuration for an individual SAP log source ingestion stream. */
export interface LogSourceConfig {
  logType: LogType;
  interval: string;
  changeDocumentObjectClasses?: string[];
  enabled?: boolean;
}

/** Secret Manager resource names for SAP basic username and password authentication. */
export interface BasicAuth {
  usernameSecret: string;
  passwordSecret: string;
}

/** Configuration and Secret Manager reference for SAP X.509/SNC authentication. */
export interface X509Auth {
  snc_name: string;
  snc_partner_name: string;
  snc_qop?: string;
  x509_cert_secret?: string;
}

/** SAP system authentication options supporting basic credentials or X.509 certificates. */
export interface SystemAuth {
  basic?: BasicAuth;
  x509?: X509Auth;
}

/** Network connection parameters for connecting to an SAP NetWeaver instance. */
export interface SystemConnection {
  host: string;
  client: string;
  systemNumber: string;
}

/** Complete configuration representing a target SAP system to ingest logs from. */
export interface SapSystem {
  id: string;
  systemId: string;
  connection: SystemConnection;
  auth: SystemAuth;
  logSources: LogSourceConfig[];
  initialLookbackWindow: string;
}

/** Root configuration schema for the SAP Telemetry Collector configuration JSON. */
export interface CollectorConfigJSON {
  bindplaneHost: string;
  bindplanePort: number | string;
  heartbeat_enabled: boolean;
  systems: Array<{
    systemId: string;
    connection: SystemConnection;
    auth: SystemAuth;
    logSources: Array<{
      logType: LogType;
      interval: string;
      changeDocumentObjectClasses?: string[];
    }>;
    initialLookbackWindow: string;
  }>;
}

function normalizeDuration(val: string | undefined | null, defaultVal = '600s'): string {
  if (!val || typeof val !== 'string' || !val.trim()) {
    return defaultVal;
  }
  const trimmed = val.trim();
  if (/^\d+$/.test(trimmed)) {
    return `${trimmed}s`;
  }
  return trimmed;
}

/** Serializes and normalizes the CollectorConfigJSON object into formatted JSON. */
export function formatCollectorConfigJson(collector: CollectorConfigJSON): string {
  const rawPort = collector?.bindplanePort;
  let portStr = "4317";

  if (rawPort !== undefined && rawPort !== null && String(rawPort).trim() !== '') {
    portStr = String(rawPort).trim();
  }

  const normalizedSystems = (collector?.systems || []).map(sys => ({
    ...sys,
    initialLookbackWindow: normalizeDuration(sys.initialLookbackWindow, '600s'),
    logSources: (sys.logSources || []).map(log => ({
      ...log,
      interval: normalizeDuration(log.interval, '600s')
    }))
  }));

  const normalizedCollector = {
    ...collector,
    bindplanePort: portStr,
    systems: normalizedSystems
  };

  return JSON.stringify(normalizedCollector, null, 2);
}

/** Configuration options for Google Cloud Storage bucket and SAP JCo dependencies. */
export interface GcsConfig {
  projectId: string;
  location: string;
  bucketName: string;
  subfolderPath: string;
  storageClass: 'STANDARD' | 'NEARLINE' | 'COLDLINE' | 'ARCHIVE';
  enableVersioning: boolean;
  uniformBucketLevelAccess: boolean;
  bucketCreated?: boolean;
  jcoFilesUploaded?: boolean;
}

/** Provisioning parameters for the Google Compute Engine VM hosting the collector. */
export interface GceConfig {
  vmName: string;
  projectId: string;
  zone: string;
  network: string;
  subnetwork: string;
  machineType: string;
  imageFamily: string;
  imageProject: string;
  diskSizeGb: number;
  scopes: string;
  serviceAccount: string;
  enableExternalIP: boolean;
  tags: string[];
}

/** Configuration for connecting the collector to Google Cloud Observability / BindPlane agent. */
export interface BindplaneConfig {
  serverUrl: string;
  secretKey: string;
  agentVersion: string;
  labels: string;
  installScriptUrl: string;
  customCommand?: string;
  bindplaneServerIp: string;
  bindplaneServerName: string;
}

/** Runtime configuration for the SAP Telemetry Collector Docker container. */
export interface DockerConfig {
  containerName: string;
  restartPolicy: string;
  networkMode: string;
  gcsBucketPath: string;
  dockerImage: string;
}

/** Global state tree holding configuration parameters across all wizard steps. */
export interface AppState {
  collector: CollectorConfigJSON;
  gcs: GcsConfig;
  gce: GceConfig;
  bindplane: BindplaneConfig;
  docker: DockerConfig;
  cloudRunServiceAccount: string;
}

/** Distinct step identifier numbers in the setup wizard flow. */
export type WizardStepId = 1 | 2 | 3 | 4 | 5 | 6;

/** Metadata descriptor for each step in the wizard UI navigation. */
export interface WizardStepMeta {
  id: WizardStepId;
  title: string;
  shortTitle: string;
  description: string;
  badgeText: string;
}
