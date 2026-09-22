import React, {useState} from 'react';
import {CollectorConfigJSON, LogType, BasicAuth, X509Auth} from '../types';
import {Plus, Trash2, Key, Server, Settings, Tag, ExternalLink} from 'lucide-react';

interface Props {
  collector: CollectorConfigJSON;
  onChange: (updated: CollectorConfigJSON) => void;
  projectId: string;
}

const AVAILABLE_LOG_TYPES: LogType[] = [
  'SAP_SECURITY_AUDIT',
  'SAP_CHANGE_DOCUMENT'
];

/**
 * Step1CollectorConfig component for configuring target SAP systems, connection parameters,
 * Secret Manager credentials, and telemetry log types to collect.
 */
export const Step1CollectorConfig: React.FC<Props> = ({ collector, onChange, projectId }) => {
  const [selectedSystemIdx, setSelectedSystemIdx] = useState<number>(0);
  const [newObjectClassInput, setNewObjectClassInput] = useState<string>('');

  const currentSystem = collector.systems[selectedSystemIdx] || collector.systems[0];

  const updateGlobal = <K extends keyof CollectorConfigJSON>(key: K, val: CollectorConfigJSON[K]) => {
    onChange({
      ...collector,
      [key]: val
    });
  };

  const updateSystem = (idx: number, field: string, val: unknown) => {
    const updatedSystems = [...collector.systems];
    const sys = { ...updatedSystems[idx] };

    if (field.startsWith('connection.')) {
      const connField = field.replace('connection.', '');
      sys.connection = { ...sys.connection, [connField]: val as string };
    } else if (field === 'auth.type') {
      if (val === 'x509') {
        sys.auth = {
          x509: {
            snc_name: "",
            snc_partner_name: "",
            snc_qop: "",
            x509_cert_secret: ""
          }
        };
      } else {
        sys.auth = {
          basic: {
            usernameSecret: "",
            passwordSecret: ""
          }
        };
      }
    } else if (field.startsWith('auth.basic.')) {
      const authField = field.replace('auth.basic.', '');
      sys.auth = {
        basic: { ...sys.auth?.basic, [authField]: val as string } as BasicAuth
      };
    } else if (field.startsWith('auth.x509.')) {
      const authField = field.replace('auth.x509.', '');
      sys.auth = {
        x509: { ...sys.auth?.x509, [authField]: val as string } as X509Auth
      };
    } else if (field === 'systemId') {
      sys.systemId = val as string;
    } else if (field === 'initialLookbackWindow') {
      sys.initialLookbackWindow = val as string;
    } else if (field === 'logSources') {
      sys.logSources = val as CollectorConfigJSON['systems'][number]['logSources'];
    }

    updatedSystems[idx] = sys;
    onChange({ ...collector, systems: updatedSystems });
  };

  const addSystem = () => {
    const nextNum = collector.systems.length + 1;
    const newSysId = `SYS${nextNum}`;
    const newSys = {
      systemId: newSysId,
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
          logType: "SAP_SECURITY_AUDIT" as LogType,
          interval: "600s"
        }
      ],
      initialLookbackWindow: ""
    };

    onChange({
      ...collector,
      systems: [...collector.systems, newSys]
    });
    setSelectedSystemIdx(collector.systems.length);
  };

  const removeSystem = (idx: number) => {
    if (collector.systems.length <= 1) {
      alert("At least one SAP system is required.");
      return;
    }
    const updated = collector.systems.filter((_, i) => i !== idx);
    onChange({ ...collector, systems: updated });
    setSelectedSystemIdx(0);
  };

  const addLogSource = (sysIdx: number) => {
    const sys = collector.systems[sysIdx];
    const existingTypes = sys.logSources.map(l => l.logType);
    const available = AVAILABLE_LOG_TYPES.find(t => !existingTypes.includes(t)) || 'SAP_SECURITY_AUDIT';

    const newSource = {
      logType: available,
      interval: "600s",
      ...(available === 'SAP_CHANGE_DOCUMENT' ? { changeDocumentObjectClasses: ["PFCG", "IDENTITY"] } : {})
    };

    const updatedSources = [...sys.logSources, newSource];
    updateSystem(sysIdx, 'logSources', updatedSources);
  };

  const removeLogSource = (sysIdx: number, logIdx: number) => {
    const sys = collector.systems[sysIdx];
    if (sys.logSources.length <= 1) {
      alert("Each SAP system must configure at least one log source.");
      return;
    }
    const updated = sys.logSources.filter((_, i) => i !== logIdx);
    updateSystem(sysIdx, 'logSources', updated);
  };

  const updateLogSource = (sysIdx: number, logIdx: number, field: string, val: unknown) => {
    const sys = collector.systems[sysIdx];
    const updatedSources = [...sys.logSources];
    const item = { ...updatedSources[logIdx] };

    if (field === 'logType') {
      item.logType = val as LogType;
      if (val === 'SAP_CHANGE_DOCUMENT') {
        if (!item.changeDocumentObjectClasses || item.changeDocumentObjectClasses.length === 0) {
          item.changeDocumentObjectClasses = ['PFCG', 'IDENTITY'];
        }
      } else {
        delete item.changeDocumentObjectClasses;
      }
    } else if (field === 'interval') {
      item.interval = val;
    }

    updatedSources[logIdx] = item;
    updateSystem(sysIdx, 'logSources', updatedSources);
  };

  const addObjectClass = (sysIdx: number, logIdx: number) => {
    if (!newObjectClassInput.trim()) return;
    const sys = collector.systems[sysIdx];
    const updatedSources = [...sys.logSources];
    const item = { ...updatedSources[logIdx] };
    const currentClasses = item.changeDocumentObjectClasses || [];

    if (!currentClasses.includes(newObjectClassInput.trim().toUpperCase())) {
      item.changeDocumentObjectClasses = [...currentClasses, newObjectClassInput.trim().toUpperCase()];
      updatedSources[logIdx] = item;
      updateSystem(sysIdx, 'logSources', updatedSources);
    }
    setNewObjectClassInput('');
  };

  const removeObjectClass = (sysIdx: number, logIdx: number, cls: string) => {
    const sys = collector.systems[sysIdx];
    const updatedSources = [...sys.logSources];
    const item = { ...updatedSources[logIdx] };
    item.changeDocumentObjectClasses = (item.changeDocumentObjectClasses || []).filter(c => c !== cls);
    updatedSources[logIdx] = item;
    updateSystem(sysIdx, 'logSources', updatedSources);
  };

  return (
    <div className="flex-1 overflow-y-auto bg-[#F8F9FA] p-8">
      <div className="max-w-5xl mx-auto space-y-8">
        <div>
          <h2 className="text-xl font-bold text-slate-900">1. SAP Telemetry Collector JSON Configuration</h2>
          <p className="text-xs text-slate-500 mt-1">
            Define collector global host/port and target SAP NetWeaver systems, Secret Manager authentication, and log sources.
          </p>
        </div>

        {/* Global Settings */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-4">
          <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-2">
            <Settings className="w-4 h-4 text-[#1A73E8]" />
            Global Collector Settings
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Bindplane Host <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={collector.bindplaneHost || ''}
                onChange={(e) => updateGlobal('bindplaneHost', e.target.value)}
                placeholder="0.0.0.0"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] focus:border-[#1A73E8] outline-none font-mono font-semibold"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Bindplane Port <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={collector.bindplanePort !== undefined ? String(collector.bindplanePort) : ''}
                onChange={(e) => updateGlobal('bindplanePort', e.target.value)}
                placeholder="4317"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] focus:border-[#1A73E8] outline-none font-mono font-semibold"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Heartbeat Status
              </label>
              <label className="flex items-center gap-2.5 px-3 py-2 bg-slate-50 border border-slate-300 rounded-md cursor-pointer hover:bg-slate-100 transition select-none">
                <input
                  type="checkbox"
                  checked={collector.heartbeat_enabled}
                  onChange={(e) => updateGlobal('heartbeat_enabled', e.target.checked)}
                  className="w-4 h-4 text-[#1A73E8] border-slate-300 rounded focus:ring-[#1A73E8] accent-[#1A73E8] cursor-pointer"
                />
                <span className="text-xs font-bold text-slate-800">
                  Enable Heartbeat ({collector.heartbeat_enabled ? 'True' : 'False'})
                </span>
              </label>
            </div>
          </div>
        </div>

        {/* Systems List & Tabs */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-2">
              <Server className="w-4 h-4 text-[#1A73E8]" />
              SAP Systems ({collector.systems.length})
            </h3>
            <button
              onClick={addSystem}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1A73E8] text-white text-xs font-semibold rounded-md hover:bg-blue-700 shadow-2xs transition"
            >
              <Plus className="w-3.5 h-3.5" />
              Add System
            </button>
          </div>

          <div className="flex items-center gap-2 border-b border-slate-200 overflow-x-auto pb-1">
            {collector.systems.map((sys, idx) => (
              <button
                key={idx}
                onClick={() => setSelectedSystemIdx(idx)}
                className={`flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-t-lg transition border-b-2 ${
                  selectedSystemIdx === idx
                    ? 'border-[#1A73E8] text-[#1A73E8] bg-white border-t border-x border-slate-200'
                    : 'border-transparent text-slate-500 hover:text-slate-800 hover:bg-slate-100'
                }`}
              >
                <span>System: {sys.systemId || `System ${idx + 1}`}</span>
                {collector.systems.length > 1 && (
                  <span
                    onClick={(e) => {
                      e.stopPropagation();
                      removeSystem(idx);
                    }}
                    className="p-0.5 hover:bg-red-100 text-slate-400 hover:text-red-600 rounded transition"
                  >
                    <Trash2 className="w-3 h-3" />
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Current System Form Card */}
          {currentSystem && (
            <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-2xs space-y-6">
              {/* System Connection Details */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">
                    System ID (SID) <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={currentSystem.systemId}
                    onChange={(e) => updateSystem(selectedSystemIdx, 'systemId', e.target.value.toUpperCase())}
                    placeholder="System ID (e.g. SYS)"
                    className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] focus:border-[#1A73E8] outline-none font-mono font-bold"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">
                    SAP Host IP <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={currentSystem.connection.host}
                    onChange={(e) => updateSystem(selectedSystemIdx, 'connection.host', e.target.value)}
                    placeholder="Host IP address"
                    className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] focus:border-[#1A73E8] outline-none font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">
                    Client ID <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={currentSystem.connection.client}
                    onChange={(e) => updateSystem(selectedSystemIdx, 'connection.client', e.target.value)}
                    placeholder="Client ID (e.g. 100)"
                    className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] focus:border-[#1A73E8] outline-none font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">
                    System Number <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={currentSystem.connection.systemNumber}
                    onChange={(e) => updateSystem(selectedSystemIdx, 'connection.systemNumber', e.target.value)}
                    placeholder="System Number (e.g. 00)"
                    className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] focus:border-[#1A73E8] outline-none font-mono"
                  />
                </div>
              </div>

              {/* Choose Authentication Mode connect to the source SAP System */}
              <div className="p-5 bg-slate-50 border border-slate-200 rounded-xl space-y-4">
                <div className="flex items-center gap-2 border-b border-slate-200/80 pb-3">
                  <Key className="w-4 h-4 text-[#FBBC04]" />
                  <span className="text-xs font-bold text-slate-800">Choose Authentication Mode connect to the source SAP System</span>
                </div>

                <div className="space-y-4">
                  {/* Option 1: Basic Authentication */}
                  <div className={`p-4 rounded-lg border transition ${!currentSystem.auth?.x509 ? 'bg-white border-[#1A73E8] shadow-2xs' : 'bg-slate-100/60 border-slate-200 opacity-75'}`}>
                    <label className="flex items-center gap-2.5 cursor-pointer select-none">
                      <input
                        type="radio"
                        name={`auth-type-${selectedSystemIdx}`}
                        checked={!currentSystem.auth?.x509}
                        onChange={() => updateSystem(selectedSystemIdx, 'auth.type', 'basic')}
                        className="w-4 h-4 text-[#1A73E8] focus:ring-[#1A73E8] cursor-pointer"
                      />
                      <span className={`text-xs ${!currentSystem.auth?.x509 ? 'font-bold text-[#1A73E8]' : 'font-semibold text-slate-700'}`}>
                        Basic Authentication
                      </span>
                    </label>

                    {!currentSystem.auth?.x509 && (
                      <div className="mt-3 pt-3 border-t border-slate-100 space-y-4">
                        <p className="text-[11px] text-slate-500 leading-relaxed">
                          Username and password authentication. Provide the full Secret Manager paths for <code className="font-mono font-bold text-slate-700 bg-slate-200/60 px-1 rounded">username_secret</code> and <code className="font-mono font-bold text-slate-700 bg-slate-200/60 px-1 rounded">password_secret</code>.
                          These secrets must contain credentials of the{' '}
                          <a
                            href="https://docs.cloud.google.com/sap/docs/secops/prepare-environment-ingestion#create-an-sap-service-user"
                            target="_blank"
                            rel="noreferrer"
                            className="text-[#1A73E8] hover:underline font-medium inline-flex items-center gap-0.5"
                          >
                            SAP service user <ExternalLink className="w-3 h-3" />
                          </a>{' '}
                          created in the preparation guide. For more info, see{' '}
                          <a
                            href="https://docs.cloud.google.com/sap/docs/secops/prepare-environment-ingestion#auth-option-basic"
                            target="_blank"
                            rel="noreferrer"
                            className="text-[#1A73E8] hover:underline font-medium inline-flex items-center gap-0.5"
                          >
                            Basic authentication documentation <ExternalLink className="w-3 h-3" />
                          </a>.
                        </p>

                        <div className="grid grid-cols-1 gap-3">
                          <div>
                            <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                              Username Secret Path (<code className="font-mono text-slate-700">usernameSecret</code>)
                            </label>
                            <input
                              type="text"
                              value={currentSystem.auth?.basic?.usernameSecret || ''}
                              onChange={(e) => updateSystem(selectedSystemIdx, 'auth.basic.usernameSecret', e.target.value)}
                              placeholder="projects/my-project/secrets/sap-secops-username/versions/latest"
                              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono text-slate-700"
                            />
                          </div>
                          <div>
                            <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                              Password Secret Path (<code className="font-mono text-slate-700">passwordSecret</code>)
                            </label>
                            <input
                              type="text"
                              value={currentSystem.auth?.basic?.passwordSecret || ''}
                              onChange={(e) => updateSystem(selectedSystemIdx, 'auth.basic.passwordSecret', e.target.value)}
                              placeholder="projects/my-project/secrets/sap-secops-password/versions/latest"
                              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono text-slate-700"
                            />
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Option 2: X.509 (SNC) */}
                  <div className={`p-4 rounded-lg border transition ${currentSystem.auth?.x509 ? 'bg-white border-[#1A73E8] shadow-2xs' : 'bg-slate-100/60 border-slate-200 opacity-75'}`}>
                    <label className="flex items-center gap-2.5 cursor-pointer select-none">
                      <input
                        type="radio"
                        name={`auth-type-${selectedSystemIdx}`}
                        checked={!!currentSystem.auth?.x509}
                        onChange={() => updateSystem(selectedSystemIdx, 'auth.type', 'x509')}
                        className="w-4 h-4 text-[#1A73E8] focus:ring-[#1A73E8] cursor-pointer"
                      />
                      <span className={`text-xs ${currentSystem.auth?.x509 ? 'font-bold text-[#1A73E8]' : 'font-semibold text-slate-700'}`}>
                        X.509 (SNC) Authentication
                      </span>
                    </label>

                    {currentSystem.auth?.x509 && (
                      <div className="mt-3 pt-3 border-t border-slate-100 space-y-4">
                        <p className="text-[11px] text-slate-500 leading-relaxed">
                          Secure Network Communication (SNC) authentication. For setup instructions, see the{' '}
                          <a
                            href="https://docs.cloud.google.com/sap/docs/secops/prepare-environment-ingestion#configure-snc-x509"
                            target="_blank"
                            rel="noreferrer"
                            className="text-[#1A73E8] hover:underline font-medium inline-flex items-center gap-0.5"
                          >
                            SNC X.509 configuration guide <ExternalLink className="w-3 h-3" />
                          </a>.
                        </p>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                              SNC Name (<code className="font-mono text-slate-700">snc_name</code>)
                            </label>
                            <input
                              type="text"
                              value={currentSystem.auth?.x509?.snc_name || ''}
                              onChange={(e) => updateSystem(selectedSystemIdx, 'auth.x509.snc_name', e.target.value)}
                              placeholder="p:CN=SAP-Collector,O=MyCompany,C=US"
                              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono text-slate-700 font-semibold"
                            />
                            <p className="text-[10px] text-slate-400 mt-1">The SNC name for the telemetry collector.</p>
                          </div>

                          <div>
                            <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                              SNC Partner Name (<code className="font-mono text-slate-700">snc_partner_name</code>)
                            </label>
                            <input
                              type="text"
                              value={currentSystem.auth?.x509?.snc_partner_name || ''}
                              onChange={(e) => updateSystem(selectedSystemIdx, 'auth.x509.snc_partner_name', e.target.value)}
                              placeholder="p:CN=SAP-Server-DEV,O=MyCompany,C=US"
                              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono text-slate-700 font-semibold"
                            />
                            <p className="text-[10px] text-slate-400 mt-1">SNC identity of the SAP Application Server.</p>
                          </div>

                          <div>
                            <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                              SNC Quality of Protection (<code className="font-mono text-slate-700">snc_qop</code>) <span className="text-slate-400 font-normal">(Optional)</span>
                            </label>
                            <input
                              type="text"
                              value={currentSystem.auth?.x509?.snc_qop || ''}
                              onChange={(e) => updateSystem(selectedSystemIdx, 'auth.x509.snc_qop', e.target.value)}
                              placeholder="e.g. 3"
                              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono text-slate-700"
                            />
                            <p className="text-[10px] text-slate-400 mt-1">Quality of Protection level (e.g. 3 for end-to-end data privacy & payload encryption).</p>
                          </div>

                          <div>
                            <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                              X.509 Certificate Secret Path (<code className="font-mono text-slate-700">x509_cert_secret</code>) <span className="text-slate-400 font-normal">(Optional)</span>
                            </label>
                            <input
                              type="text"
                              value={currentSystem.auth?.x509?.x509_cert_secret || ''}
                              onChange={(e) => updateSystem(selectedSystemIdx, 'auth.x509.x509_cert_secret', e.target.value)}
                              placeholder="projects/my-project-123/secrets/sap-x509-cert/versions/latest"
                              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] font-mono text-slate-700"
                            />
                            <p className="text-[10px] text-slate-400 mt-1">
                              Full Secret Manager path to secret containing <code className="font-mono">collector_cert.crt</code>. See{' '}
                              <a
                                href="https://docs.cloud.google.com/sap/docs/secops/prepare-environment-ingestion#store-snc-artifacts"
                                target="_blank"
                                rel="noreferrer"
                                className="text-[#1A73E8] hover:underline"
                              >
                                SNC artifacts guide
                              </a>.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Initial Lookback Window */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">
                    Initial Lookup Window (in seconds)
                  </label>
                  <input
                    type="text"
                    value={currentSystem.initialLookbackWindow}
                    onChange={(e) => updateSystem(selectedSystemIdx, 'initialLookbackWindow', e.target.value)}
                    placeholder="e.g. 600s or 600"
                    className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:ring-2 focus:ring-[#1A73E8] focus:border-[#1A73E8] outline-none font-mono font-semibold"
                  />
                  <p className="text-[10px] text-slate-400 mt-1">Accepts duration in seconds (e.g. 600s or 600)</p>
                </div>
              </div>

              {/* Log Sources Builder */}
              <div className="border-t border-slate-200 pt-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-slate-800">Log Sources</h4>
                    <p className="text-[11px] text-slate-500">Configure log types and polling intervals in seconds.</p>
                  </div>
                  <button
                    onClick={() => addLogSource(selectedSystemIdx)}
                    className="flex items-center gap-1 px-3 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-md transition"
                  >
                    <Plus className="w-3.5 h-3.5 text-[#1A73E8]" />
                    ADD LOG SOURCE
                  </button>
                </div>

                <div className="space-y-3">
                  {currentSystem.logSources.map((log, logIdx) => (
                    <div key={logIdx} className="p-4 border border-slate-200 bg-slate-50/70 rounded-lg space-y-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Log Type <span className="text-red-500">*</span></label>
                            <select
                              value={log.logType}
                              onChange={(e) => updateLogSource(selectedSystemIdx, logIdx, 'logType', e.target.value)}
                              className="w-full px-3 py-1.5 text-xs bg-white border border-slate-300 rounded-md font-mono font-bold text-slate-800"
                            >
                              {AVAILABLE_LOG_TYPES.map(type => (
                                <option key={type} value={type}>{type}</option>
                              ))}
                            </select>
                          </div>
                          <div>
                            <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Interval (in seconds) <span className="text-red-500">*</span></label>
                            <input
                              type="text"
                              value={log.interval}
                              onChange={(e) => updateLogSource(selectedSystemIdx, logIdx, 'interval', e.target.value)}
                              placeholder="600s"
                              className="w-full px-3 py-1.5 text-xs bg-white border border-slate-300 rounded-md font-mono"
                            />
                          </div>
                        </div>

                        <button
                          onClick={() => removeLogSource(selectedSystemIdx, logIdx)}
                          className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded transition mt-4"
                          title="Remove Log Source"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>

                      {/* Change Document Object Classes Tags */}
                      {log.logType === 'SAP_CHANGE_DOCUMENT' && (
                        <div className="bg-white p-3 rounded border border-slate-200 space-y-2">
                          <label className="block text-[10px] font-bold text-slate-600 uppercase flex items-center gap-1">
                            <Tag className="w-3 h-3 text-[#1A73E8]" />
                            changeDocumentObjectClasses
                          </label>

                          <div className="flex flex-wrap gap-1.5">
                            {(log.changeDocumentObjectClasses || []).map((cls) => (
                              <span
                                key={cls}
                                className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-blue-50 text-[#1A73E8] border border-blue-200 rounded text-xs font-mono font-bold"
                              >
                                {cls}
                                <button
                                  onClick={() => removeObjectClass(selectedSystemIdx, logIdx, cls)}
                                  className="text-blue-400 hover:text-red-600 transition"
                                >
                                  ×
                                </button>
                              </span>
                            ))}
                          </div>

                          <div className="flex items-center gap-2 pt-1">
                            <input
                              type="text"
                              value={newObjectClassInput}
                              onChange={(e) => setNewObjectClassInput(e.target.value.toUpperCase())}
                              onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addObjectClass(selectedSystemIdx, logIdx))}
                              placeholder="Add class e.g. PFCG, IDENTITY, USER"
                              className="flex-1 px-3 py-1 text-xs bg-slate-50 border border-slate-200 rounded font-mono uppercase"
                            />
                            <button
                              type="button"
                              onClick={() => addObjectClass(selectedSystemIdx, logIdx)}
                              className="px-3 py-1 bg-slate-800 text-white text-xs font-bold rounded hover:bg-slate-900 transition"
                            >
                              Add
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
