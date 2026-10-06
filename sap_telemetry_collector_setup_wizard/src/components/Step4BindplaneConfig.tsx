import React from 'react';
import {AppState, BindplaneConfig} from '../types';
import {Terminal, ExternalLink} from 'lucide-react';

interface Props {
  bindplane: BindplaneConfig;
  onChange: (updated: BindplaneConfig) => void;
  fullState: AppState;
}

/**
 * Step4BindplaneConfig component for configuring BindPlane OP server details,
 * DNS mapping, and agent installation scripts.
 */
export const Step4BindplaneConfig: React.FC<Props> = ({ bindplane, onChange }) => {
  const currentCommand = bindplane.customCommand || '';

  const updateField = (key: keyof BindplaneConfig, val: string) => {
    onChange({
      ...bindplane,
      [key]: val
    });
  };

  const handleCommandChange = (val: string) => {
    onChange({
      ...bindplane,
      customCommand: val
    });
  };

  return (
    <div className="flex-1 overflow-y-auto bg-[#F8F9FA] p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <div>
          <h2 className="text-xl font-bold text-slate-900">4. BindPlane Agent Installation Setup</h2>
          <p className="text-xs text-slate-500 mt-1">
            Specify BindPlane Gateway host mapping details and the overall CLI command to install the BindPlane Collector Agent.
          </p>
        </div>

        {/* BindPlane Gateway Host Configuration */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-4">
          <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-[#1A73E8]" />
            BindPlane Gateway Host Configuration
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                BindPlane Gateway IP Address <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={bindplane.bindplaneServerIp || ''}
                onChange={(e) => updateField('bindplaneServerIp', e.target.value)}
                placeholder="IP address (e.g. 10.x.x.x)"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-semibold"
              />
              <p className="text-[10px] text-slate-400 mt-1">IP used to update /etc/hosts on GCE instance</p>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                BindPlane Gateway Name <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={bindplane.bindplaneServerName || ''}
                onChange={(e) => updateField('bindplaneServerName', e.target.value)}
                placeholder="Gateway Hostname"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono font-semibold"
              />
              <p className="text-[10px] text-slate-400 mt-1">Hostname mapped in /etc/hosts</p>
            </div>
          </div>
        </div>

        {/* Command Input Box */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-4">
          <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-[#1A73E8]" />
            BindPlane Collector Agent Installation Command
          </h3>

          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">
              CLI Installation Command <span className="text-red-500">*</span>
            </label>
            <p className="text-[11px] text-slate-500 mb-2 leading-relaxed">
              Copy the BindPlane Collector Agent CLI installation command from your BindPlane Gateway and paste it below. For reference on generating the CLI command, refer to the <a href="https://docs.bindplane.com/readme/install-your-first-collector" target="_blank" rel="noopener noreferrer" className="text-[#1A73E8] hover:underline font-semibold inline-flex items-center gap-0.5">BindPlane Collector Installation Guide <ExternalLink className="w-3 h-3" /></a>.
            </p>
            <textarea
              rows={5}
              value={currentCommand}
              onChange={(e) => handleCommandChange(e.target.value)}
              placeholder="Paste BindPlane Collector Agent CLI installation command here..."
              className="w-full px-3 py-2 text-xs bg-slate-900 text-emerald-400 font-mono border border-slate-700 rounded-lg focus:ring-2 focus:ring-[#1A73E8] focus:border-transparent outline-none leading-relaxed"
            />
            <p className="text-[10px] text-slate-400 mt-1.5">
              This command will be executed during instance startup to install, register, and start the BindPlane Collector Agent daemon.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
