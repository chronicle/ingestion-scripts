import React from 'react';
import {AppState, GceConfig} from '../types';
import {Cpu} from 'lucide-react';

interface Props {
  gce: GceConfig;
  onChange: (updated: GceConfig) => void;
  fullState: AppState;
}

/**
 * Step3GceConfig component for specifying Compute Engine VM configuration
 * including machine specs, VPC network, disk size, and service account.
 */
export const Step3GceConfig: React.FC<Props> = ({ gce, onChange, fullState }) => {
  const effectiveProjectId = gce.projectId || fullState?.gcs?.projectId || '';

  const update = <K extends keyof GceConfig>(key: K, val: GceConfig[K]) => {
    onChange({
      ...gce,
      [key]: val
    });
  };

  return (
    <div className="flex-1 overflow-y-auto bg-[#F8F9FA] p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <div>
          <h2 className="text-xl font-bold text-slate-900">3. Compute Engine (GCE) VM Instance Setup</h2>
          <p className="text-xs text-slate-500 mt-1">
            Configure the Compute Engine (GCE) instance that will host the Docker container and BindPlane agent daemon.
          </p>
        </div>

        {/* Form Inputs */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-5">
          <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-2">
            <Cpu className="w-4 h-4 text-[#1A73E8]" />
            GCE VM Instance Specifications
          </h3>

          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">
                  VM Instance Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={gce.vmName ?? ''}
                  onChange={(e) => update('vmName', e.target.value.toLowerCase())}
                  placeholder="sap-telemetry-collector-vm"
                  className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-bold text-slate-800"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">
                  GCP Project ID <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={effectiveProjectId}
                  onChange={(e) => update('projectId', e.target.value)}
                  placeholder={fullState?.gcs?.projectId || "your-gcp-project-id"}
                  className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">
                  GCP Zone <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={gce.zone}
                  onChange={(e) => update('zone', e.target.value)}
                  placeholder="Zone (e.g. us-central1-a)"
                  className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">
                  Machine Type <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={gce.machineType}
                  onChange={(e) => update('machineType', e.target.value)}
                  placeholder="e2-standard-4"
                  className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-semibold"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">
                  VPC Network <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={gce.network}
                  onChange={(e) => update('network', e.target.value)}
                  placeholder="default"
                  className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">
                  Subnetwork <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={gce.subnetwork}
                  onChange={(e) => update('subnetwork', e.target.value)}
                  placeholder="default"
                  className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">
                  OS Image Family <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={gce.imageFamily ?? ''}
                  onChange={(e) => update('imageFamily', e.target.value)}
                  placeholder="debian-12"
                  className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-semibold"
                />
                <span className="text-[10px] text-slate-500 mt-0.5 block">Project: {gce.imageProject || 'debian-cloud'}</span>
              </div>

              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                <div className="text-[10px] font-bold text-slate-400 uppercase">Scopes</div>
                <div className="text-xs font-mono font-bold text-slate-800 mt-1">{gce.scopes}</div>
                <div className="text-[10px] text-slate-500">Full Cloud Access</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
