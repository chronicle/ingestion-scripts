import React, {useState} from 'react';
import {AppState, GcsConfig, formatCollectorConfigJson} from '../types';
import {Cloud, CheckCircle2, FolderPlus, FileCheck, HardDrive, Terminal, AlertCircle} from 'lucide-react';
import {createGcsBucketAndFolders} from '../utils/gcpApi';

interface Props {
  gcs: GcsConfig;
  onChange: (updated: GcsConfig) => void;
  fullState: AppState;
}

/**
 * Step2GcsConfig component for configuring GCS bucket location, folder paths,
 * storage class parameters, and live bucket provisioning.
 */
export const Step2GcsConfig: React.FC<Props> = ({ gcs, onChange, fullState }) => {
  const [isCreating, setIsCreating] = useState(false);
  const [creationLog, setCreationLog] = useState<string[] | null>(null);

  const update = <K extends keyof GcsConfig>(key: K, val: GcsConfig[K]) => {
    onChange({
      ...gcs,
      storageClass: 'STANDARD',
      [key]: val
    });
  };

  const handleCreateBucket = async () => {
    if (!gcs.bucketName || !gcs.projectId) {
      alert("Please enter GCP Project ID and Bucket Name first.");
      return;
    }

    setIsCreating(true);
    setCreationLog([]);

    const jsonConfig = fullState?.collector ? formatCollectorConfigJson(fullState.collector) : '{}';

    const result = await createGcsBucketAndFolders(
      gcs.projectId,
      gcs.bucketName,
      gcs.location,
      jsonConfig
    );

    setCreationLog(result.logs);
    setIsCreating(false);

    if (result.success) {
      onChange({
        ...gcs,
        bucketCreated: true
      });
    }
  };

  return (
    <div className="flex-1 overflow-y-auto bg-[#F8F9FA] p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <div>
          <h2 className="text-xl font-bold text-slate-900">2. Google Cloud Storage (GCS) Setup & JCo Configuration</h2>
          <p className="text-xs text-slate-500 mt-1">
            Configure parameters, provision the GCS bucket with folder hierarchy (<code className="font-mono bg-slate-200/60 px-1 py-0.5 rounded text-slate-800">config/</code>, <code className="font-mono bg-slate-200/60 px-1 py-0.5 rounded text-slate-800">jco/</code>, <code className="font-mono bg-slate-200/60 px-1 py-0.5 rounded text-slate-800">state/</code>), upload configuration JSON, and confirm SAP JCo binaries.
          </p>
        </div>

        {/* Bucket Configuration Form */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-5">
          <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-2 border-b border-slate-100 pb-3">
            <Cloud className="w-4 h-4 text-[#1A73E8]" />
            GCS Bucket Parameters
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                GCP Project ID <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={gcs.projectId}
                onChange={(e) => update('projectId', e.target.value)}
                placeholder="your-gcp-project-id"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Location / Region <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={gcs.location}
                onChange={(e) => update('location', e.target.value)}
                placeholder="Region (e.g. us-central1)"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-semibold"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                GCS Bucket Name <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={gcs.bucketName}
                onChange={(e) => update('bucketName', e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
                placeholder="e.g. sap-telemetry-collector-config-your-project"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-bold text-slate-800"
              />
              <p className="text-[10px] text-slate-400 mt-1">
                Globally unique URI: <span className="font-mono text-slate-700 font-semibold">gs://{gcs.bucketName || '<your-unique-bucket-name>'}</span>
              </p>
            </div>
          </div>
        </div>

        {/* Action 1: Bucket & Folder Hierarchy Creation */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
            <div>
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                <FolderPlus className="w-4 h-4 text-[#1A73E8]" />
                Step 2.1: Provision GCS Bucket & Folder Hierarchy
              </h3>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Creates <code className="font-mono">gs://{gcs.bucketName}</code> with folders <code className="font-mono">config/</code>, <code className="font-mono">jco/</code>, <code className="font-mono">state/</code> and places <code className="font-mono">collector_config.json</code> into <code className="font-mono">config/</code>.
              </p>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {gcs.bucketCreated ? (
                <span className="px-2.5 py-1 bg-emerald-100 text-emerald-800 border border-emerald-300 rounded-full text-[11px] font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  Bucket & Folders Provisioned
                </span>
              ) : (
                <span className="px-2.5 py-1 bg-amber-100 text-amber-800 border border-amber-300 rounded-full text-[11px] font-bold flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
                  Bucket Not Provisioned
                </span>
              )}
            </div>
          </div>

          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50 p-4 rounded-lg border border-slate-200">
              <div className="space-y-1 text-xs">
                <p className="font-bold text-slate-800">Target Bucket Structure:</p>
                <ul className="list-disc list-inside text-slate-600 font-mono text-[11px] space-y-0.5">
                  <li>gs://{gcs.bucketName}/config/collector_config.json</li>
                  <li>gs://{gcs.bucketName}/jco/</li>
                  <li>gs://{gcs.bucketName}/state/</li>
                </ul>
              </div>

              <button
                onClick={handleCreateBucket}
                disabled={isCreating}
                className="px-4 py-2.5 bg-[#1A73E8] hover:bg-blue-700 text-white font-bold text-xs rounded-lg shadow-sm transition flex items-center justify-center gap-2 shrink-0 disabled:opacity-50"
              >
                {isCreating ? (
                  <>
                    <span className="w-3.5 h-3.5 rounded-full border-2 border-white border-t-transparent animate-spin"></span>
                    <span>Provisioning GCS Bucket...</span>
                  </>
                ) : (
                  <>
                    <HardDrive className="w-4 h-4" />
                    <span>Create GCS Bucket and Folders</span>
                  </>
                )}
              </button>
            </div>

            {/* Log Output Box if Provisioned */}
            {creationLog && (
              <div className="bg-slate-900 text-slate-200 rounded-lg p-4 font-mono text-[11px] space-y-1 shadow-inner">
                <div className="text-emerald-400 font-bold border-b border-slate-800 pb-1 mb-2 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Bucket Provisioning Execution Log</span>
                </div>
                {creationLog.map((log, idx) => (
                  <div key={idx} className={log.includes('[OK]') || log.includes('complete') ? 'text-emerald-400 font-semibold' : 'text-slate-300'}>
                    {log}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Action 2: SAP JCo Upload & Checkbox Confirmation */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
            <div>
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-[#1A73E8]" />
                Step 2.2: Confirm SAP JCo Library Upload
              </h3>
              <p className="text-[11px] text-slate-500 mt-0.5">
                The SAP Telemetry Collector container requires SAP Java Connector (JCo) native files to establish RFC connection to SAP.
              </p>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {gcs.jcoFilesUploaded ? (
                <span className="px-2.5 py-1 bg-emerald-100 text-emerald-800 border border-emerald-300 rounded-full text-[11px] font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  JCo Upload Confirmed
                </span>
              ) : (
                <span className="px-2.5 py-1 bg-red-100 text-red-800 border border-red-300 rounded-full text-[11px] font-bold flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5 text-red-600" />
                  Pending JCo Upload
                </span>
              )}
            </div>
          </div>

          <div className="space-y-4">
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 space-y-2 text-xs text-amber-900">
              <p className="font-bold flex items-center gap-1.5 text-amber-900">
                <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
                Required Files: <code className="font-mono bg-amber-100 px-1 py-0.5 rounded">sapjco3.jar</code> and <code className="font-mono bg-amber-100 px-1 py-0.5 rounded">libsapjco3.so</code>
              </p>
              <p className="text-[11px] text-amber-800 leading-relaxed">
                Download the SAP Java Connector 3.1 binaries from the SAP Support Portal and upload them into <code className="font-mono font-bold">gs://{gcs.bucketName}/jco/</code>. The installation script in Step 6 validates these files prior to running container setup.
              </p>
            </div>

            {/* Confirmation Checkbox */}
            <div className="pt-1">
              <label className="flex items-start gap-3 p-4 bg-slate-50 rounded-xl border-2 border-slate-200 hover:border-[#1A73E8] transition cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={!!gcs.jcoFilesUploaded}
                  onChange={(e) => update('jcoFilesUploaded', e.target.checked)}
                  className="mt-0.5 w-4 h-4 text-[#1A73E8] border-slate-300 rounded focus:ring-[#1A73E8]"
                />
                <div className="space-y-0.5 text-xs">
                  <span className="font-bold text-slate-900">
                    I confirm that SAP JCo library files (<code className="font-mono text-slate-800">sapjco3.jar</code> and <code className="font-mono text-slate-800">libsapjco3.so</code>) have been uploaded to <code className="font-mono text-[#1A73E8]">gs://{gcs.bucketName}/jco/</code>.
                  </span>
                  <p className="text-[11px] text-slate-500">
                    This confirmation is validated during the installation simulation in Step 6 before proceeding with VM container execution.
                  </p>
                </div>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

