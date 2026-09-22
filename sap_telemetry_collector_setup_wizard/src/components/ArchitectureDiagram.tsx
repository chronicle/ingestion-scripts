import React from 'react';
import {
  Database,
  HardDrive,
  Server,
  Radio,
  Box,
  Layers,
  CheckCircle2,
  AlertCircle,
  Shield
} from 'lucide-react';
import {AppState} from '../types';

interface Props {
  state: AppState;
}

/**
 * ArchitectureDiagram component rendering a comprehensive summary and review
 * table of configured parameters from Steps 1 through 5 prior to execution.
 */
export const ArchitectureDiagram: React.FC<Props> = ({ state }) => {
  const { collector, gcs, gce, bindplane, docker } = state;
  const systems = collector.systems || [];

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-6 font-sans">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <Layers className="w-5 h-5 text-[#1A73E8]" />
            Deployment Configuration Summary (Steps 1–5 Review)
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Line item wise summary of configuration parameters entered across Steps 1 through 5.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs font-bold px-3 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            Ready for Installation
          </span>
        </div>
      </div>

      {/* Line Item Wise Table Display */}
      <div className="divide-y divide-slate-200/80 border border-slate-200 rounded-xl overflow-hidden text-xs">

        {/* Step 1 Line Item: SAP NetWeaver Systems */}
        <div className="p-4 bg-slate-50/50 hover:bg-slate-50 transition flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="w-60 shrink-0 flex items-center gap-2.5">
            <div className="p-1.5 bg-blue-100 text-[#1A73E8] rounded-md font-bold text-xs shrink-0">
              <Database className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Step 1</span>
              <h4 className="font-bold text-slate-900 text-xs">SAP NetWeaver Systems</h4>
            </div>
          </div>

          <div className="flex-1 space-y-2">
            {systems.map((sys, idx) => (
              <div key={idx} className="bg-white p-3.5 rounded-lg border border-slate-200/80 space-y-2.5 text-xs">
                <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5">
                  <div>
                    <span className="text-slate-500 font-medium mr-1.5">SID:</span>
                    <code className="text-[#1A73E8] font-mono font-bold bg-blue-50 px-2 py-0.5 rounded text-xs">{sys.systemId}</code>
                  </div>
                  <div>
                    <span className="text-slate-500 font-medium mr-1.5">Client:</span>
                    <span className="font-mono font-semibold text-slate-800">{sys.connection.client}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-medium mr-1.5">Host:</span>
                    <span className="font-mono font-semibold text-slate-800">{sys.connection.host}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-medium mr-1.5">SysNum:</span>
                    <span className="font-mono font-semibold text-slate-800">{sys.connection.systemNumber}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-medium mr-1.5">Lookback Window:</span>
                    <span className="font-mono font-semibold text-slate-800">{sys.initialLookbackWindow}</span>
                  </div>
                </div>

                {/* Authentication Mode Details */}
                <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs">
                  <span className="font-medium text-slate-700 flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-[#1A73E8]" />
                    <span className="text-slate-500 font-medium">Auth Mode:</span>
                    <span className="px-2 py-0.5 bg-blue-50 text-[#1A73E8] border border-blue-200 rounded font-semibold text-xs ml-0.5">
                      {sys.auth?.x509 ? 'X.509 Certificate / SNC' : 'Basic Authentication'}
                    </span>
                  </span>

                  {sys.auth?.basic && (
                    <>
                      <div>
                        <span className="text-slate-500 font-medium mr-1.5">Username Secret:</span>
                        <code className="text-slate-800 font-mono font-semibold">{sys.auth.basic.usernameSecret || 'Not Specified'}</code>
                      </div>
                      <div>
                        <span className="text-slate-500 font-medium mr-1.5">Password Secret:</span>
                        <code className="text-slate-800 font-mono font-semibold">{sys.auth.basic.passwordSecret || 'Not Specified'}</code>
                      </div>
                    </>
                  )}

                  {sys.auth?.x509 && (
                    <>
                      <div>
                        <span className="text-slate-500 font-medium mr-1.5">My SNC Name:</span>
                        <code className="text-slate-800 font-mono font-semibold">{sys.auth.x509.snc_name || 'N/A'}</code>
                      </div>
                      <div>
                        <span className="text-slate-500 font-medium mr-1.5">Partner SNC Name:</span>
                        <code className="text-slate-800 font-mono font-semibold">{sys.auth.x509.snc_partner_name || 'N/A'}</code>
                      </div>
                      {sys.auth.x509.snc_qop && (
                        <div>
                          <span className="text-slate-500 font-medium mr-1.5">QOP:</span>
                          <code className="text-slate-800 font-mono font-semibold">{sys.auth.x509.snc_qop}</code>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Step 2 Line Item: GCS Bucket & JCo Configuration */}
        <div className="p-4 bg-white hover:bg-slate-50 transition flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs">
          <div className="w-60 shrink-0 flex items-center gap-2.5">
            <div className="p-1.5 bg-amber-100 text-amber-700 rounded-md font-bold text-xs shrink-0">
              <HardDrive className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Step 2</span>
              <h4 className="font-bold text-slate-900 text-xs">GCS Bucket & JCo Setup</h4>
            </div>
          </div>

          <div className="flex-1 flex flex-wrap items-center justify-between gap-3 bg-slate-50/60 px-3.5 py-2.5 rounded-lg border border-slate-200/80">
            <div className="space-y-0.5">
              <div>
                <span className="text-slate-500 font-medium mr-1.5">Bucket Name:</span>
                <span className="font-mono font-bold text-slate-800 text-xs">gs://{gcs.bucketName}</span>
              </div>
              <div className="text-slate-500 text-xs">
                Project: <span className="font-mono text-slate-700 font-semibold">{gcs.projectId || '<PROJECT_ID>'}</span> | Region: <span className="font-mono text-slate-700 font-semibold">{gcs.location}</span>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1.5 text-slate-600 font-medium">
                Bucket Status:
                {gcs.bucketCreated ? (
                  <span className="text-emerald-700 font-semibold flex items-center gap-1 ml-1"><CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Provisioned</span>
                ) : (
                  <span className="text-amber-600 font-semibold ml-1">Pending Creation</span>
                )}
              </span>

              <span className="flex items-center gap-1.5 text-slate-600 font-medium">
                JCo Files:
                {gcs.jcoFilesUploaded ? (
                  <span className="text-emerald-700 font-semibold flex items-center gap-1 ml-1"><CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Confirmed</span>
                ) : (
                  <span className="text-amber-600 font-semibold ml-1 flex items-center gap-1"><AlertCircle className="w-3.5 h-3.5 text-amber-600" /> Unconfirmed</span>
                )}
              </span>
            </div>
          </div>
        </div>

        {/* Step 3 Line Item: GCE VM Configuration */}
        <div className="p-4 bg-slate-50/50 hover:bg-slate-50 transition flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs">
          <div className="w-60 shrink-0 flex items-center gap-2.5">
            <div className="p-1.5 bg-blue-100 text-blue-700 rounded-md font-bold text-xs shrink-0">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Step 3</span>
              <h4 className="font-bold text-slate-900 text-xs">Compute Engine (GCE) VM</h4>
            </div>
          </div>

          <div className="flex-1 flex flex-wrap items-center justify-between gap-3 bg-white px-3.5 py-2.5 rounded-lg border border-slate-200/80">
            <div>
              <div>
                <span className="text-slate-500 font-medium mr-1.5">GCE Instance Name:</span>
                <span className="font-mono font-bold text-slate-800 text-xs">{gce.vmName}</span>
              </div>
              <div className="text-slate-500 text-xs">
                Zone: <span className="font-mono text-slate-700 font-semibold">{gce.zone}</span> | Machine: <span className="font-mono text-slate-700 font-semibold">{gce.machineType}</span> | OS Image: <span className="font-mono text-slate-700 font-semibold">{gce.imageFamily || 'debian-12'}</span>
              </div>
            </div>

            <div className="space-y-0.5 text-xs text-right">
              <div>
                <span className="text-slate-500 font-medium mr-1.5">Network / Subnet:</span>
                <span className="font-mono text-slate-800 font-semibold">{gce.network} / {gce.subnetwork}</span>
              </div>
              <div>
                <span className="text-slate-500 font-medium mr-1.5">Attached SA:</span>
                <span className="font-mono text-slate-800 font-semibold">{gce.serviceAccount || 'sap-telemetry-collector-sa'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Step 4 Line Item: BindPlane Agent Configuration */}
        <div className="p-4 bg-white hover:bg-slate-50 transition flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs">
          <div className="w-60 shrink-0 flex items-center gap-2.5">
            <div className="p-1.5 bg-purple-100 text-purple-700 rounded-md font-bold text-xs shrink-0">
              <Radio className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Step 4</span>
              <h4 className="font-bold text-slate-900 text-xs">BindPlane Gateway Host</h4>
            </div>
          </div>

          <div className="flex-1 flex flex-wrap items-center justify-between gap-3 bg-slate-50/60 px-3.5 py-2.5 rounded-lg border border-slate-200/80">
            <div>
              <div>
                <span className="text-slate-500 font-medium mr-1.5">Host Name:</span>
                <span className="font-mono font-bold text-slate-800 text-xs">{bindplane.bindplaneServerName || 'N/A'}</span>
                <span className="text-slate-500 font-medium ml-3 mr-1.5">IP:</span>
                <span className="font-mono font-bold text-slate-800 text-xs">{bindplane.bindplaneServerIp || 'N/A'}</span>
              </div>
              <div className="text-slate-500 text-xs">
                Service: <span className="font-mono text-slate-700 font-semibold">observiq-otel-collector</span> | Agent Version: <span className="font-mono text-slate-700 font-semibold">v{bindplane.agentVersion}</span>
              </div>
            </div>

            <div className="text-xs text-right">
              <span className="px-2.5 py-1 bg-purple-50 text-purple-700 border border-purple-200 rounded font-semibold text-xs">
                {bindplane.customCommand ? 'CLI Installation Command Provided' : 'Standard Agent Command'}
              </span>
            </div>
          </div>
        </div>

        {/* Step 5 Line Item: Docker Container Configuration */}
        <div className="p-4 bg-slate-50/50 hover:bg-slate-50 transition flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs">
          <div className="w-60 shrink-0 flex items-center gap-2.5">
            <div className="p-1.5 bg-emerald-100 text-emerald-700 rounded-md font-bold text-xs shrink-0">
              <Box className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Step 5</span>
              <h4 className="font-bold text-slate-900 text-xs">Docker Telemetry Collector</h4>
            </div>
          </div>

          <div className="flex-1 flex flex-wrap items-center justify-between gap-3 bg-white px-3.5 py-2.5 rounded-lg border border-slate-200/80">
            <div className="space-y-1 max-w-xl text-left">
              <div>
                <span className="text-slate-500 font-medium mr-1.5">Container Name:</span>
                <span className="font-mono font-bold text-slate-800 text-xs">{docker.containerName}</span>
              </div>
              <div className="text-xs text-slate-600 break-all leading-normal font-mono font-semibold">
                <span className="text-slate-500 font-sans font-medium mr-1.5">Image:</span>
                {docker.dockerImage}
              </div>
            </div>

            <div className="space-y-0.5 text-xs text-left shrink-0">
              <div>
                <span className="text-slate-500 font-medium mr-1.5">Networking:</span>
                <span className="font-semibold text-emerald-700 text-xs">{docker.networkMode} network</span>
              </div>
              <div>
                <span className="text-slate-500 font-medium mr-1.5">Config URI:</span>
                <span className="font-mono text-slate-700 text-xs">gs://{gcs.bucketName}/config/collector_config.json</span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
