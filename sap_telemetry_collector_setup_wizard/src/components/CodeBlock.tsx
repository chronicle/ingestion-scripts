import React, {useState} from 'react';
import {Copy, Check, Download} from 'lucide-react';

interface CodeBlockProps {
  code: string;
  language?: string;
  filename?: string;
  title?: string;
  maxHeight?: string;
  showLineNumbers?: boolean;
}

/**
 * CodeBlock component rendering formatted, syntax-styled configuration snippets
 * or bash scripts with line numbering, copy-to-clipboard, and file download support.
 */
export const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  language = 'text',
  filename,
  title,
  maxHeight = 'max-h-96',
  showLineNumbers = true
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename || 'script.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const lines = code.trim().split('\n');

  return (
    <div className="rounded-lg border border-slate-800 bg-[#1E293B] text-slate-200 overflow-hidden shadow-sm font-mono text-xs">
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#0F172A] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#EA4335]" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#FBBC04]" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#34A853]" />
          </div>
          <span className="text-slate-400 font-semibold text-[11px] ml-2">
            {filename || title || language.toUpperCase()}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {filename && (
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition text-[11px] font-sans font-medium"
              title="Download file"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download</span>
            </button>
          )}

          <button
            onClick={handleCopy}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded transition text-[11px] font-sans font-medium ${
              copied
                ? 'bg-[#34A853]/20 text-[#34A853] border border-[#34A853]/30'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
            }`}
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5" />
                <span>Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      <div className={`p-4 overflow-x-auto ${maxHeight} leading-relaxed font-mono`}>
        {showLineNumbers ? (
          <table className="w-full border-collapse">
            <tbody>
              {lines.map((line, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40">
                  <td className="w-8 select-none text-right pr-4 text-slate-600 font-mono text-[11px]">
                    {idx + 1}
                  </td>
                  <td className="whitespace-pre text-slate-200">
                    {line}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <pre className="whitespace-pre text-slate-200">{code}</pre>
        )}
      </div>
    </div>
  );
};
