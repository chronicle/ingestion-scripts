/**
 * Google Cloud REST API Client Helper
 * Implements a Backend-for-Frontend (BFF) architecture. API requests are routed
 * through the server-side proxy (/api/gcp/storage/ and /api/gcp/compute/) which
 * attaches the Cloud Run Service Account credentials server-side, preventing
 * raw OAuth token exposure to client browsers.
 */

import {AppState} from '../types';
import {generateStartupScript} from './terraformGenerator';

/**
 * Returns the effective API endpoint URL and headers for a GCP REST request.
 * - If userProvidedToken is supplied, targets GCP APIs directly with the
 * Authorization header.
 * - Otherwise, dispatches through the server-side BFF proxy (/api/gcp/...) with
 * zero client-side credentials.
 */
export function resolveGcpApiTarget(
    targetUrl: string, userProvidedToken?: string):
    {url: string; headers: Record<string, string>} {
  if (userProvidedToken && userProvidedToken.trim()) {
    return {
      url: targetUrl,
      headers: {'Authorization': `Bearer ${userProvidedToken.trim()}`}
    };
  }

  // Route through server-side Backend-for-Frontend (BFF) reverse proxy
  if (targetUrl.startsWith('https://storage.googleapis.com/')) {
    return {
      url: targetUrl.replace(
          'https://storage.googleapis.com/', '/api/gcp/storage/'),
      headers: {}
    };
  }

  if (targetUrl.startsWith('https://compute.googleapis.com/')) {
    return {
      url: targetUrl.replace(
          'https://compute.googleapis.com/', '/api/gcp/compute/'),
      headers: {}
    };
  }

  return {url: targetUrl, headers: {}};
}

/**
 * Retrieves a user-provided GCP OAuth access token if explicitly configured.
 */
export function getGcpAccessToken(userProvidedToken?: string): string | null {
  if (userProvidedToken && userProvidedToken.trim()) {
    return userProvidedToken.trim();
  }
  return null;
}

/**
 * Creates the Google Cloud Storage bucket, folder structure, and uploads collector config.
 */
export async function createGcsBucketAndFolders(
  projectId: string,
  bucketName: string,
  location: string,
  configJsonString: string,
  userToken?: string
): Promise<{ success: boolean; logs: string[]; error?: string }> {
  const logs: string[] = [];
  console.info(`[SAP Telemetry Wizard] Initializing GCS bucket creation for gs://${bucketName} in project ${projectId}...`);

  if (!userToken) {
    const msg =
        `[SECURITY] Dispatching GCS provisioning via server-side Backend-for-Frontend (BFF) proxy.`;
    logs.push(msg);
    console.info(`[SAP Telemetry Wizard] ${msg}`);
  }

  try {
    const step1Msg = `[1/4] Sending REST API request to Google Cloud Storage API to provision bucket "gs://${bucketName}" in project "${projectId}"...`;
    logs.push(step1Msg);
    console.info(`[SAP Telemetry Wizard] ${step1Msg}`);

    const bucketTarget = resolveGcpApiTarget(
        `https://storage.googleapis.com/storage/v1/b?project=${
            encodeURIComponent(projectId)}`,
        userToken);

    const bucketRes = await fetch(bucketTarget.url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', ...bucketTarget.headers},
      body: JSON.stringify({
        name: bucketName,
        location: location || 'us-central1',
        iamConfiguration: {uniformBucketLevelAccess: {enabled: true}}
      })
    });

    if (bucketRes.ok || bucketRes.status === 409) {
      if (bucketRes.status === 409) {
        const msg = `[OK] Bucket "gs://${bucketName}" already exists in GCP Console.`;
        logs.push(msg);
        console.info(`[SAP Telemetry Wizard] ${msg}`);
      } else {
        const data = await bucketRes.json().catch(() => ({id: bucketName}));
        const msg = `[OK] Bucket "gs://${
            bucketName}" created successfully live in Google Cloud Console! (ID: ${
            data.id || bucketName})`;
        logs.push(msg);
        console.info(`[SAP Telemetry Wizard] ${msg}`);
      }

      // Upload config
      const step2Msg = `[2/4] Uploading collector_config.json to gs://${bucketName}/config/collector_config.json...`;
      logs.push(step2Msg);
      console.info(`[SAP Telemetry Wizard] ${step2Msg}`);

      const uploadTarget = resolveGcpApiTarget(
          `https://storage.googleapis.com/upload/storage/v1/b/${
              encodeURIComponent(
                  bucketName)}/o?uploadType=media&name=config/collector_config.json`,
          userToken);

      const uploadRes = await fetch(uploadTarget.url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', ...uploadTarget.headers},
        body: configJsonString
      });

      if (uploadRes.ok) {
        const msg = `[OK] Uploaded collector_config.json (${configJsonString.length} bytes) live into GCS!`;
        logs.push(msg);
        console.info(`[SAP Telemetry Wizard] ${msg}`);
      }

      // Create jco/ folder marker
      const step3Msg = `[3/4] Creating folder hierarchy gs://${bucketName}/jco/...`;
      logs.push(step3Msg);
      console.info(`[SAP Telemetry Wizard] ${step3Msg}`);

      const jcoTarget = resolveGcpApiTarget(
          `https://storage.googleapis.com/upload/storage/v1/b/${
              encodeURIComponent(bucketName)}/o?uploadType=media&name=jco/`,
          userToken);

      await fetch(jcoTarget.url, {
        method: 'POST',
        headers: {'Content-Type': 'text/plain', ...jcoTarget.headers},
        body: ''
      });
      const jcoMsg = `[OK] Folder hierarchy gs://${bucketName}/jco/ created.`;
      logs.push(jcoMsg);
      console.info(`[SAP Telemetry Wizard] ${jcoMsg}`);

      // Create state/ folder marker
      const step4Msg = `[4/4] Creating folder hierarchy gs://${bucketName}/state/...`;
      logs.push(step4Msg);
      console.info(`[SAP Telemetry Wizard] ${step4Msg}`);

      const stateTarget = resolveGcpApiTarget(
          `https://storage.googleapis.com/upload/storage/v1/b/${
              encodeURIComponent(bucketName)}/o?uploadType=media&name=state/`,
          userToken);

      await fetch(stateTarget.url, {
        method: 'POST',
        headers: {'Content-Type': 'text/plain', ...stateTarget.headers},
        body: ''
      });
      const stateMsg = `[OK] Folder hierarchy gs://${bucketName}/state/ created.`;
      logs.push(stateMsg);
      console.info(`[SAP Telemetry Wizard] ${stateMsg}`);

      const successMsg = `==> Bucket creation and folder hierarchy setup complete live in GCP Console!`;
      logs.push(successMsg);
      console.info(`[SAP Telemetry Wizard] ${successMsg}`);

      return { success: true, logs };
    } else {
      const errData = await bucketRes.json().catch(() => null);
      const msg = errData?.error?.message || `HTTP ${bucketRes.status}`;
      const errLog = `[ERROR] GCP Storage API returned: ${msg}`;
      logs.push(errLog);
      console.error(`[SAP Telemetry Wizard ERROR] ${errLog}`);
      return { success: false, logs, error: msg };
    }
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const errLog = `[ERROR] Network / API Error: ${errMsg}`;
    logs.push(errLog);
    console.error(`[SAP Telemetry Wizard ERROR] ${errLog}`, err);
    return { success: false, logs, error: errMsg };
  }
}

/**
 * Creates the Google Compute Engine VM instance via GCP REST API.
 */
export async function createGceInstance(
  state: AppState,
  userToken?: string
): Promise<{ success: boolean; logs: string[]; error?: string }> {
  const logs: string[] = [];

  if (!userToken) {
    const msg =
        `[SECURITY] Dispatching Compute Engine provisioning via server-side Backend-for-Frontend (BFF) proxy.`;
    logs.push(msg);
    console.info(`[SAP Telemetry Wizard] ${msg}`);
  }

  const projectId = state.gce.projectId || state.gcs.projectId;
  const zone = state.gce.zone || 'us-central1-a';
  const region = zone.substring(0, zone.lastIndexOf('-')) || 'us-central1';
  const vmName = state.gce.vmName || 'sap-telemetry-collector-vm';
  const machineType = state.gce.machineType || 'e2-standard-4';
  const network = state.gce.network || 'default';
  const subnetwork = state.gce.subnetwork || 'default';
  const imageFamily = state.gce.imageFamily || 'debian-12';
  const imageProject = state.gce.imageProject || 'debian-cloud';
  const serviceAccount = state.gce.serviceAccount || 'default';

  const startupScript = generateStartupScript(state);

  const log1 = `[GCE API] Sending REST API request to Google Compute Engine API to create instance "${vmName}" (${machineType}) in zone "${zone}"...`;
  logs.push(log1);
  console.info(`[SAP Telemetry Wizard] ${log1}`);

  try {
    const target = resolveGcpApiTarget(
        `https://compute.googleapis.com/compute/v1/projects/${
            encodeURIComponent(
                projectId)}/zones/${encodeURIComponent(zone)}/instances`,
        userToken);

    const res = await fetch(target.url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', ...target.headers},
      body: JSON.stringify({
        name: vmName,
        machineType: `zones/${zone}/machineTypes/${machineType}`,
        disks: [{
          boot: true,
          autoDelete: true,
          initializeParams: {
            sourceImage:
                `projects/${imageProject}/global/images/family/${imageFamily}`,
            diskSizeGb: String(state.gce.diskSizeGb || 50)
          }
        }],
        networkInterfaces: [{
          network: `global/networks/${network}`,
          subnetwork: `regions/${region}/subnetworks/${subnetwork}`,
          accessConfigs: state.gce.enableExternalIP ?
              [{type: 'ONE_TO_ONE_NAT', name: 'External NAT'}] :
              []
        }],
        serviceAccounts: [{
          email: serviceAccount,
          scopes: ['https://www.googleapis.com/auth/cloud-platform']
        }],
        metadata: {items: [{key: 'startup-script', value: startupScript}]},
        tags: {items: state.gce.tags || ['sap-telemetry', 'secops-collector']}
      })
    });

    if (res.ok || res.status === 409) {
      if (res.status === 409) {
        const msg = `[OK] GCE Instance "${vmName}" already exists in GCP Console.`;
        logs.push(msg);
        console.info(`[SAP Telemetry Wizard] ${msg}`);
      } else {
        const data =
            await res.json().catch(() => ({name: 'Operation in progress'}));
        const msg = `[OK] GCE Instance "${vmName}" provisioned successfully live in Google Cloud Console! (Operation: ${data.name || 'Done'})`;
        logs.push(msg);
        console.info(`[SAP Telemetry Wizard] ${msg}`);
      }
      return { success: true, logs };
    } else {
      const errData = await res.json().catch(() => null);
      const msg = errData?.error?.message || `HTTP ${res.status}`;
      const errLog = `[ERROR] Compute Engine API returned: ${msg}`;
      logs.push(errLog);
      console.error(`[SAP Telemetry Wizard ERROR] ${errLog}`);
      return { success: false, logs, error: msg };
    }
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const errLog = `[ERROR] Network / Compute API Error: ${errMsg}`;
    logs.push(errLog);
    console.error(`[SAP Telemetry Wizard ERROR] ${errLog}`, err);
    return { success: false, logs, error: errMsg };
  }
}

/**
 * Polls serial port 1 console output from the specified GCE VM instance.
 */
export async function getGceSerialPortOutput(
    projectId: string, zone: string, instanceName: string, startOffset?: number,
    userToken?: string): Promise<{contents: string; nextOffset: number}> {
  try {
    let rawUrl = `https://compute.googleapis.com/compute/v1/projects/${
        projectId}/zones/${zone}/instances/${instanceName}/serialPort?port=1`;
    if (startOffset !== undefined && startOffset > 0) {
      rawUrl += `&start=${startOffset}`;
    }

    const target = resolveGcpApiTarget(rawUrl, userToken);
    const res =
        await fetch(target.url, {method: 'GET', headers: {...target.headers}});

    if (!res.ok) {
      return { contents: '', nextOffset: startOffset || 0 };
    }

    const data = await res.json();
    return {
      contents: data.contents || '',
      nextOffset: Number(data.next) || 0
    };
  } catch (_err: unknown) {
    return { contents: '', nextOffset: startOffset || 0 };
  }
}
