import React from 'react';
import {AppState, DockerConfig} from '../types';
import {Layers} from 'lucide-react';

interface Props {
  docker: DockerConfig;
  onChange: (updated: DockerConfig) => void;
  fullState: AppState;
}

/**
 * Step5DockerConfig component allowing configuration of Docker container settings
 * and GCS bucket configuration paths for running the collector.
 */
export const Step5DockerConfig: React.FC<Props> = ({ docker, onChange, fullState }) => {
  const step2BucketName = fullState?.gcs?.bucketName ? fullState.gcs.bucketName.replace(/^gs:\/\//, '') : '';
  const defaultGcsPath = step2BucketName ? `gs://${step2BucketName}` : '';
  const rawPath = docker.gcsBucketPath || defaultGcsPath;
  const effectiveGcsPath = rawPath.includes('/config/') && step2BucketName ? `gs://${step2BucketName}` : rawPath;

  const update = (key: keyof DockerConfig, val: string) => {
    onChange({
      ...docker,
      restartPolicy: 'always',
      networkMode: 'host',
      [key]: val
    });
  };

  return (
    <div className="flex-1 overflow-y-auto bg-[#F8F9FA] p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <div>
          <h2 className="text-xl font-bold text-slate-900">5. SAP Telemetry Collector Docker Container Setup</h2>
          <p className="text-xs text-slate-500 mt-1">
            Configure the container execution parameters and environmental GCS configuration URI.
          </p>
        </div>

        {/* Form Inputs */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-5">
          <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#1A73E8]" />
            Docker Container Parameters
          </h3>

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Container Name (--name) <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={docker.containerName ?? ''}
                onChange={(e) => update('containerName', e.target.value)}
                placeholder="sap-telemetry-collector"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-bold text-slate-800"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                COLLECTOR_GCS_BUCKET Environment Variable <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={effectiveGcsPath}
                onChange={(e) => update('gcsBucketPath', e.target.value)}
                placeholder={defaultGcsPath || "gs://<bucket-name-entered-in-step-2>"}
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-semibold text-[#1A73E8]"
              />
              <p className="text-[10px] text-slate-400 mt-1">
                Passed to Docker container via <code className="font-mono text-slate-700">-e COLLECTOR_GCS_BUCKET=...</code>
              </p>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Google Artifact Registry Image <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={docker.dockerImage ?? ''}
                onChange={(e) => update('dockerImage', e.target.value)}
                placeholder="us-docker.pkg.dev/sap-core-eng-products/sap-application-telemetry/google-cloud-sap-application-telemetry:latest"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono text-slate-700"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
