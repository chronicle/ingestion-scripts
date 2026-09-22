import React from 'react';
import {ExternalLink, FileText} from 'lucide-react';

/**
 * Header component displaying the application title, brand indicator,
 * and reference links to Google Cloud SAP ingestion documentation.
 */
export const Header: React.FC = () => {
  return (
    <header className="h-20 px-8 flex items-center justify-between bg-white border-b border-slate-200 sticky top-0 z-30 shadow-2xs">
      <div className="flex items-center gap-4">
        {/* Logo Card matching attached screenshot */}
        <div className="px-3.5 py-2.5 bg-slate-100 border border-slate-200/80 rounded-xl flex items-center justify-center gap-1.5 shadow-2xs shrink-0">
          <span className="w-2.5 h-2.5 rounded-full bg-[#4285F4]"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-[#EA4335]"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-[#FBBC05]"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-[#34A853]"></span>
        </div>

        <div>
          <h1 className="text-lg font-bold tracking-tight text-slate-900">
            SAP Telemetry Collector Setup Wizard
          </h1>
          <p className="text-xs text-slate-500 font-normal mt-0.5">
            Unified Setup & Configuration Tool for SAP Telemetry
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* GCP Documentation Link */}
        <a
          href="https://docs.cloud.google.com/sap/docs/secops/ingest-self-managed-sap-logs#ingest_application_logs"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-[#1A73E8] transition px-3 py-1.5 rounded-lg hover:bg-slate-50 border border-slate-200"
          title="Open official Google Cloud SAP SecOps documentation"
        >
          <FileText className="w-3.5 h-3.5 text-[#1A73E8]" />
          <span>GCP Documentation to Ingest SAP Application Logs</span>
          <ExternalLink className="w-3 h-3 text-slate-400" />
        </a>
      </div>
    </header>
  );
};

