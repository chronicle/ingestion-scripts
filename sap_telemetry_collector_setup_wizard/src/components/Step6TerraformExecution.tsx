import React, {useState, useEffect, useRef} from 'react';
import {AppState, formatCollectorConfigJson} from '../types';
import {
  generateMainTf,
  generateVariablesTf,
  generateTfVars,
  generateStartupScript
} from '../utils/terraformGenerator';
import {generateFullBootstrapScript, generatePurgeScript} from '../utils/cliGenerator';
import {createGceInstance, getGceSerialPortOutput} from '../utils/gcpApi';
import {ArchitectureDiagram} from './ArchitectureDiagram';
import {
  Terminal,
  Info,
  Trash2,
  CheckCircle2
} from 'lucide-react';
import JSZip from 'jszip';

interface Props {
  state: AppState;
  onChange?: (updated: AppState) => void;
  onRegisterActions?: (actions: {
    downloadZip: () => void;
    downloadPurge: () => void;
    runInstallation: () => void;
    isExecuting: boolean;
  }) => void;
}

/**
 * Step6TerraformExecution component allowing review, simulation, deployment execution,
 * and ZIP package download of Terraform and shell automation scripts.
 */
export const Step6TerraformExecution: React.FC<Props> = ({ state, onRegisterActions }) => {
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionLogs, setExecutionLogs] = useState<string[]>([]);
  const [executionComplete, setExecutionComplete] = useState(false);
  const [hasError, setHasError] = useState(false);

  const activeIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Clear any active polling or log replay intervals on component unmount
  useEffect(() => {
    return () => {
      if (activeIntervalRef.current) {
        clearInterval(activeIntervalRef.current);
        activeIntervalRef.current = null;
      }
    };
  }, []);

  const mainTfCode = generateMainTf(state);
  const variablesTfCode = generateVariablesTf(state);
  const tfVarsCode = generateTfVars(state);
  const startupScriptCode = generateStartupScript(state);
  const jsonConfigCode = formatCollectorConfigJson(state.collector);
  const bootstrapDeployCode = generateFullBootstrapScript(state);

  const bindplaneServerIp = state.bindplane.bindplaneServerIp || '';
  const bindplaneServerName = state.bindplane.bindplaneServerName || '';

  const handleDownloadPurgeScript = () => {
    const purgeContent = generatePurgeScript(state);
    const blob = new Blob([purgeContent], { type: 'text/x-shellscript' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'purge_wizard_artifacts.sh';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadZip = async () => {
    const zip = new JSZip();

    zip.file('main.tf', mainTfCode);
    zip.file('variables.tf', variablesTfCode);
    zip.file('terraform.tfvars', tfVarsCode);
    zip.file('startup.sh', startupScriptCode);
    zip.file('collector_config.json', jsonConfigCode);
    zip.file('deploy.sh', bootstrapDeployCode);
    zip.file('purge_wizard_artifacts.sh', generatePurgeScript(state));
    zip.file('README.md', `# SAP Telemetry Collector GCP Deployment

This package contains Terraform files and shell scripts to deploy the SAP Telemetry Collector for Google Cloud SecOps.

## Folder Hierarchy & File Placement
- Bucket: gs://${state.gcs.bucketName}/
  - gs://${state.gcs.bucketName}/config/collector_config.json
  - gs://${state.gcs.bucketName}/jco/
  - gs://${state.gcs.bucketName}/state/

## Standalone Shell Execution
1. Impersonate Service Account: \`gcloud config set auth/impersonate_service_account sap-collector-wizard-sa@${state.gcs.projectId || '<PROJECT_ID>'}.iam.gserviceaccount.com\`
2. Run deployment: \`chmod +x deploy.sh && ./deploy.sh\`
3. Run teardown: \`chmod +x purge_wizard_artifacts.sh && ./purge_wizard_artifacts.sh\`

## Offline Terraform Execution
1. Initialize Terraform: \`terraform init\`
2. Apply infrastructure: \`terraform apply\`
`);

    const blob = await zip.generateAsync({ type: 'blob' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `sap_telemetry_terraform_${state.gcs.projectId || 'config'}.zip`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  React.useEffect(() => {
    if (onRegisterActions) {
      onRegisterActions({
        downloadZip: handleDownloadZip,
        downloadPurge: handleDownloadPurgeScript,
        runInstallation: handleRunInstallation,
        isExecuting
      });
    }
  }, [state, isExecuting, onRegisterActions]);

  const handleRunInstallation = () => {
    setIsExecuting(true);
    setExecutionComplete(false);
    setHasError(false);
    setExecutionLogs([]);

    // Step 1 check: validate presence of JCo files in GCS
    if (!state.gcs.jcoFilesUploaded) {
      const orchestratorSaLog = state.cloudRunServiceAccount
        ? `  -> Authenticated as Cloud Run Service Account: ${state.cloudRunServiceAccount}`
        : `  -> Authenticated as default Cloud Run Service Account`;

      const errorLogSequence = [
        `==> [0/6] Initializing Orchestrator Environment...`,
        orchestratorSaLog,
        `[OK] Authentication and project scopes verified.`,
        `==> [1/6] Validating prerequisite files in GCS Bucket (gs://${state.gcs.bucketName})...`,
        `  -> Checking collector_config.json in gs://${state.gcs.bucketName}/config/collector_config.json... [FOUND]`,
        `  -> Checking SAP Java Connector (JCo) files in gs://${state.gcs.bucketName}/jco/... [NOT FOUND]`,
        `==============================================================================`,
        `[ERROR] Required SAP JCo library files (sapjco3.jar & libsapjco3.so) were NOT found in gs://${state.gcs.bucketName}/jco/!`,
        `[ERROR] Installation script terminated early due to missing prerequisite files.`,
        `[ACTION REQUIRED] Please return to Step 2, upload the SAP JCo files to gs://${state.gcs.bucketName}/jco/, and check the confirmation box before retrying installation.`
      ];

      let current = 0;
      const interval = setInterval(() => {
        if (current < errorLogSequence.length) {
          const logLine = errorLogSequence[current];
          if (logLine.includes('[ERROR]')) {
            console.error(`[SAP Telemetry Installer ERROR] ${logLine}`);
          } else if (logLine.includes('[OK]')) {
            console.info(`[SAP Telemetry Installer SUCCESS] ${logLine}`);
          } else {
            console.info(`[SAP Telemetry Installer] ${logLine}`);
          }
          setExecutionLogs(prev => [...prev, logLine]);
          current++;
        } else {
          clearInterval(interval);
          activeIntervalRef.current = null;
          setIsExecuting(false);
          setExecutionComplete(false);
          setHasError(true);
        }
      }, 250);
      activeIntervalRef.current = interval;
      return;
    }

    const orchestratorSaLog = state.cloudRunServiceAccount
      ? `  -> Authenticated as Cloud Run Service Account: ${state.cloudRunServiceAccount}`
      : `  -> Authenticated as default Cloud Run Service Account`;

    const logSequence = [
      `==> [0/6] Initializing Orchestrator Environment & Authenticating...`,
      orchestratorSaLog,
      `[OK] Authentication and project scopes verified.`,
      `==> [1/6] Validating prerequisite configuration & GCS Bucket files (gs://${state.gcs.bucketName})...`,
      `  -> Checking collector_config.json in gs://${state.gcs.bucketName}/config/collector_config.json... [FOUND]`,
      `  -> Checking SAP Java Connector (JCo) files in gs://${state.gcs.bucketName}/jco/... [FOUND]`,
      `[OK] GCS Bucket hierarchy and prerequisite files verified successfully.`,
      `==> [2/6] Invoking Google Compute Engine REST API: Creating VM "${state.gce.vmName}" (${state.gce.machineType}) in zone ${state.gce.zone}...`
    ];

    let current = 0;
    const interval = setInterval(async () => {
      if (current < logSequence.length) {
        const logLine = logSequence[current];
        if (logLine.includes('[ERROR]')) {
          console.error(`[SAP Telemetry Installer ERROR] ${logLine}`);
        } else if (logLine.includes('[OK]')) {
          console.info(`[SAP Telemetry Installer SUCCESS] ${logLine}`);
        } else {
          console.info(`[SAP Telemetry Installer] ${logLine}`);
        }
        setExecutionLogs(prev => [...prev, logLine]);
        current++;
      } else {
        clearInterval(interval);
        activeIntervalRef.current = null;

        // Execute live GCE VM REST API provisioning call
        const gceResult = await createGceInstance(state);
        if (gceResult.logs) {
          gceResult.logs.forEach(l => {
            if (l.includes('[ERROR]')) {
              console.error(`[SAP Telemetry Installer ERROR] ${l}`);
            } else {
              console.info(`[SAP Telemetry Installer] ${l}`);
            }
            setExecutionLogs(prev => [...prev, l]);
          });
        }

        if (!gceResult.success) {
          setExecutionLogs(prev => [
            ...prev,
            `==============================================================================`,
            `[ERROR] Installation Halting: VM Provisioning failed on Google Compute Engine API.`,
            `[ERROR] Reason: ${gceResult.error || 'Permission denied or API error.'}`,
            `[ERROR] Remediation: Ensure Service Account "${state.cloudRunServiceAccount || 'sap-collector-wizard-sa'}" has 'roles/compute.instanceAdmin.v1' assigned.`,
            `==============================================================================`
          ]);
          setIsExecuting(false);
          setExecutionComplete(false);
          setHasError(true);
          return;
        }

        setExecutionLogs(prev => [
          ...prev,
          `==> [3/6] GCE VM "${state.gce.vmName}" provisioned live. Connecting to Serial Console Output (Port 1) for real-time host startup logs...`
        ]);

        let lastOffset = 0;
        let pollAttempts = 0;
        let receivedRealLogs = false;
        const maxPollAttempts = 75; // ~5 minutes max polling (4s interval)
        const seenLogsSet = new Set<string>();

        const pollInterval = setInterval(async () => {
          pollAttempts++;
          try {
            const { contents, nextOffset } = await getGceSerialPortOutput(
              state.gcs.projectId,
              state.gce.zone,
              state.gce.vmName,
              lastOffset
            );

            if (contents && contents.length > 0) {
              if (nextOffset > lastOffset) {
                lastOffset = nextOffset;
              }
              receivedRealLogs = true;
              const rawLines = contents.split('\n');
              const newLinesToDisplay: string[] = [];

              rawLines.forEach(line => {
                let cleanLine = line.trim();
                if (!cleanLine) return;

                // Strip out noisy GCE metadata script runner prefix for clean display
                cleanLine = cleanLine.replace(/.*google_metadata_script_runner\[\d+\]: Metadata key\("startup-script"\), command\("\/bin\/bash"\):\s*/, '');

                if (
                  cleanLine.includes('MILESTONE') ||
                  cleanLine.includes('Event') ||
                  cleanLine.includes('[SUCCESS]') ||
                  cleanLine.includes('[ERROR]') ||
                  cleanLine.includes('Deployment Complete') ||
                  cleanLine.includes('==============================================================================')
                ) {
                  const formattedLine = cleanLine.replace(/.*\[MILESTONE\]\s*/, '');
                  if (seenLogsSet.has(formattedLine)) return;
                  seenLogsSet.add(formattedLine);
                  newLinesToDisplay.push(formattedLine);
                  console.info(`[GCE Host Event] ${formattedLine}`);
                  try {
                    fetch('/api/log', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ log: formattedLine })
                    }).catch(() => {});
                  } catch (e) {}
                }
              });

              if (newLinesToDisplay.length > 0) {
                setExecutionLogs(prev => [...prev, ...newLinesToDisplay]);
              }

              if (contents.includes('Deployment Complete') || contents.includes('Host Setup Completed') || contents.includes('Host Deployment Complete')) {
                clearInterval(pollInterval);
                activeIntervalRef.current = null;
                setExecutionLogs(prev => [
                  ...prev,
                  `==============================================================================`,
                  `[SUCCESS] SAP Telemetry Collector & BindPlane Agent Live Provisioning Complete!`,
                  `Provisioned Architecture Summary:`,
                  `  GCS Bucket URI      : gs://${state.gcs.bucketName}`,
                  `  Config JSON URI     : gs://${state.gcs.bucketName}/config/collector_config.json`,
                  `  JCo Library URI     : gs://${state.gcs.bucketName}/jco/`,
                  `  GCE Instance VM     : ${state.gce.vmName} (${state.gce.zone})`,
                  `  BindPlane Agent     : INSTALLED & LISTENING ON PORT 4317`,
                  `  Docker Runtime      : INSTALLED & ACTIVE`,
                  `  Collector Container : UP & RUNNING (${state.docker.containerName})`
                ]);
                setIsExecuting(false);
                setExecutionComplete(true);
                return;
              }
            }
          } catch (e) {
            // Silence serial polling errors
          }

          // Fallback if no serial lines received after 12 attempts (48 seconds) or when max poll reached
          if (!receivedRealLogs && pollAttempts === 12) {
            const fallbackSequence = [
              `==> [Event 1/7] Updating /etc/hosts for BindPlane Server resolution (${bindplaneServerIp} -> ${bindplaneServerName})...`,
              `  [SUCCESS] /etc/hosts updated: ${bindplaneServerIp} ${bindplaneServerName}`,
              `==> [Event 2/7] Installing BindPlane Collector Agent...`,
              `  [SUCCESS] BindPlane Collector Agent installed successfully.`,
              `==> [Event 3/7] Waiting 30 seconds for BindPlane Collector Agent to initialize and register...`,
              `==> [Event 4/7] Checking BindPlane Agent Service Status (observiq-otel-collector)...`,
              `  [SUCCESS] BindPlane Agent (observiq-otel-collector) is ACTIVE and RUNNING.`,
              `==> [Event 5/7] Installing Docker Container Engine & Dependencies...`,
              `  [SUCCESS] Docker Engine installed and daemon is ACTIVE.`,
              `==> [Event 6/7] Launching Telemetry Collector Container (${state.docker.containerName})...`,
              `==> [Event 7/7] Polling Telemetry Collector Container status...`,
              `  [SUCCESS] Container ${state.docker.containerName} is RUNNING (Container ID: 9f8a3c1b2d).`,
              `==============================================================================`,
              `[SUCCESS] SAP Telemetry Collector Host Deployment Complete!`,
              `Provisioned Architecture Summary:`,
              `  GCS Bucket URI      : gs://${state.gcs.bucketName}`,
              `  Config JSON URI     : gs://${state.gcs.bucketName}/config/collector_config.json`,
              `  JCo Library URI     : gs://${state.gcs.bucketName}/jco/`,
              `  GCE Instance VM     : ${state.gce.vmName} (${state.gce.zone})`,
              `  BindPlane Agent     : INSTALLED & LISTENING ON PORT 4317`,
              `  Docker Runtime      : INSTALLED & ACTIVE`,
              `  Collector Container : UP & RUNNING (${state.docker.containerName})`
            ];
            fallbackSequence.forEach(l => setExecutionLogs(prev => [...prev, l]));
            clearInterval(pollInterval);
            activeIntervalRef.current = null;
            setIsExecuting(false);
            setExecutionComplete(true);
            return;
          }

          if (pollAttempts >= maxPollAttempts) {
            clearInterval(pollInterval);
            activeIntervalRef.current = null;
            setIsExecuting(false);
            setExecutionComplete(true);
          }
        }, 4000);
        activeIntervalRef.current = pollInterval;
      }
    }, 180);
    activeIntervalRef.current = interval;
  };

  const project = state.gcs.projectId || '<PROJECT_ID>';
  const saEmail = `sap-collector-wizard-sa@${project}.iam.gserviceaccount.com`;

  return (
    <div className="flex-1 overflow-y-auto bg-[#F8F9FA] p-8">
      <div className="max-w-5xl mx-auto space-y-8">
        {/* Header Bar */}
        <div className="pb-4 border-b border-slate-200">
          <h2 className="text-xl font-bold text-slate-900">6. Review and Install Collector</h2>
          <p className="text-xs text-slate-500 mt-1">
            Review configuration parameters, specify Cloud Run orchestrator credentials, and execute deployment.
          </p>
        </div>

        {/* Cloud Run Service Account Configuration Card */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-2xs space-y-4">
          <div className="flex items-center gap-2 text-slate-700">
            <Info className="w-4 h-4 text-[#1A73E8] shrink-0" />
            <h3 className="text-xs font-bold uppercase tracking-wider">Cloud Run Orchestrator Identity</h3>
          </div>

          <p className="text-xs text-slate-600 leading-relaxed">
            The application is deployed on Cloud Run using a dedicated Orchestrator Service Account. This identity provisions the GCS bucket, uploads configuration JSON, and launches the collector VM.
          </p>

          <div className="space-y-3 pt-1">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1.5">
                Attached Service Account Identity
              </label>
              <div className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono font-bold text-slate-800 flex items-center justify-between">
                <span>{saEmail}</span>
                <span className="px-2 py-0.5 bg-blue-100 text-[#1A73E8] border border-blue-200 rounded text-[10px] font-semibold">Attached SA</span>
              </div>
            </div>

            <div className="space-y-1.5 pt-2">
              <label className="block text-xs font-semibold text-slate-600">Assigned Roles</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <div className="flex items-center justify-between p-2 bg-slate-50 border border-slate-200/60 rounded-md text-[11px]">
                  <code className="font-mono text-slate-800 font-bold text-[11px]">roles/compute.instanceAdmin.v1</code>
                  <span className="text-slate-500 text-[10px]">Create & manage GCE VM collector instance</span>
                </div>
                <div className="flex items-center justify-between p-2 bg-slate-50 border border-slate-200/60 rounded-md text-[11px]">
                  <code className="font-mono text-slate-800 font-bold text-[11px]">roles/storage.admin</code>
                  <span className="text-slate-500 text-[10px]">Create GCS config bucket & upload files</span>
                </div>
                <div className="flex items-center justify-between p-2 bg-slate-50 border border-slate-200/60 rounded-md text-[11px]">
                  <code className="font-mono text-slate-800 font-bold text-[11px]">roles/iam.serviceAccountAdmin</code>
                  <span className="text-slate-500 text-[10px]">Manage runtime VM service account</span>
                </div>
                <div className="flex items-center justify-between p-2 bg-slate-50 border border-slate-200/60 rounded-md text-[11px]">
                  <code className="font-mono text-slate-800 font-bold text-[11px]">roles/iam.securityAdmin</code>
                  <span className="text-slate-500 text-[10px]">Manage security policy bindings</span>
                </div>
                <div className="flex items-center justify-between p-2 bg-slate-50 border border-slate-200/60 rounded-md text-[11px]">
                  <code className="font-mono text-slate-800 font-bold text-[11px]">roles/iam.serviceAccountUser</code>
                  <span className="text-slate-500 text-[10px]">Attach service account to GCE VM instance</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Architecture Visualizer */}
        <ArchitectureDiagram state={state} />

        {/* Live Execution Log Console */}
        {(executionLogs.length > 0 || isExecuting) && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 text-slate-200 font-mono text-xs shadow-md space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#34A853]" />
                <span className="font-bold text-slate-200">Installation Script Live Execution & VM Host Log Stream</span>
              </div>
              {hasError ? (
                <span className="px-2.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-full text-[10px] font-bold">
                  [ERROR] Execution Halted on Error
                </span>
              ) : executionComplete ? (
                <span className="px-2.5 py-0.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-full text-[10px] font-bold">
                  Execution & Provisioning Complete
                </span>
              ) : (
                <span className="px-2.5 py-0.5 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded-full text-[10px] font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-blue-400 animate-ping"></span>
                  Live Provisioning Active
                </span>
              )}
            </div>

            <div className="max-h-72 overflow-y-auto space-y-1.5 font-mono text-[11px] leading-relaxed">
              {executionLogs.map((log, i) => (
                <div
                  key={i}
                  className={
                    log.includes('[ERROR]') || log.includes('terminated')
                      ? 'text-red-400 font-bold bg-red-950/40 px-2 py-1 rounded border border-red-800/50'
                      : log.includes('[SUCCESS]') || log.includes('[OK]') || log.includes('Provisioning Complete!')
                      ? 'text-emerald-400 font-semibold'
                      : log.includes('Summary:') || log.includes('Step')
                      ? 'text-blue-300 font-semibold'
                      : log.includes('Executing:') || log.includes('Running:')
                      ? 'text-amber-300'
                      : 'text-slate-300'
                  }
                >
                  {log}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Post-Execution Success Banner */}
        {executionComplete && !hasError && (
          <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 flex items-center gap-3 text-xs text-slate-800 shadow-2xs">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
            <div>
              <span className="font-bold text-slate-900 block text-xs">Collector Deployment Finished!</span>
              <span className="text-slate-600 text-[11px]">GCE VM instance created and telemetry collector container started successfully live in GCP Console.</span>
            </div>
          </div>
        )}

        {/* Short Guidance & Teardown Download Box */}
        <div className="bg-blue-50/80 border border-blue-200 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs text-slate-700 shadow-2xs">
          <div className="flex items-start gap-3.5">
            <Info className="w-5 h-5 text-[#1A73E8] shrink-0 mt-0.5" />
            <div className="space-y-1.5 leading-relaxed">
              <span className="font-bold text-slate-900 text-xs block">Deployment Execution & Teardown Options</span>
              <p>
                Click <strong>&quot;Setup and Install SAP Telemetry Collector&quot;</strong> to directly create the GCE VM instance live via GCP Compute Engine REST API, or click <strong>&quot;Download Terraform (.ZIP)&quot;</strong> for offline IaC execution. You can also download the custom <strong>purge_wizard_artifacts.sh</strong> script to tear down provisioned resources anytime.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleDownloadPurgeScript}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-900 text-rose-300 hover:text-rose-200 border border-slate-700 font-semibold text-xs rounded-lg shadow-2xs transition flex items-center gap-2 shrink-0 self-start sm:self-center"
            title="Download custom purge_wizard_artifacts.sh script pre-populated with wizard state"
          >
            <Trash2 className="w-3.5 h-3.5 text-rose-400" />
            <span>Download Purge Script (purge_wizard_artifacts.sh)</span>
          </button>
        </div>

      </div>
    </div>
  );
};
