import React, { useState } from 'react';
import { 
  FileCode, Copy, Check, Download, ShieldCheck, 
  Terminal, Lock, Layers, EyeOff, AlertTriangle 
} from 'lucide-react';

const EvidencePanel = ({ scanResult }) => {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState('headers');

  if (!scanResult) return null;

  const bundle = scanResult.evidenceBundle || {};

  const handleCopyEvidence = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(JSON.stringify(bundle, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleExportEvidence = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(bundle, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `evidence-${scanResult.scanId || 'scan'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      {/* Header Row */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <FileCode size={18} className="text-cyber-primary" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            Forensic Evidence & Artifacts
          </h3>
          <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/40 flex items-center gap-1">
            <EyeOff size={11} /> Sensitive Data Masked
          </span>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleCopyEvidence}
            className="px-3 py-1.5 rounded-lg bg-black/40 border border-cyber-border hover:border-gray-500 text-xs text-gray-200 flex items-center gap-1.5 transition-colors"
          >
            {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
            <span>{copied ? 'Copied' : 'Copy Evidence'}</span>
          </button>

          <button
            type="button"
            onClick={handleExportEvidence}
            className="px-3 py-1.5 rounded-lg bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/40 hover:bg-cyber-primary/30 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-[0_0_10px_rgba(0,240,255,0.2)]"
          >
            <Download size={14} />
            <span>Export Evidence</span>
          </button>
        </div>
      </div>

      {/* Evidence Sub-Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-cyber-border/40 pb-2 text-xs">
        {[
          { id: 'headers', label: 'HTTP Headers' },
          { id: 'tls', label: 'TLS Handshake' },
          { id: 'tech', label: 'Detected Tech' },
          { id: 'scripts', label: 'Suspicious Scripts' },
          { id: 'iocs', label: 'Extracted IoCs' }
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-1.5 rounded-md transition-all ${
              activeTab === tab.id
                ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/50 font-bold'
                : 'text-gray-400 hover:text-white bg-black/30'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content Area */}
      <div className="bg-black/50 p-4 rounded-xl border border-cyber-border text-xs min-h-[160px] overflow-x-auto">
        {activeTab === 'headers' && (
          <div className="space-y-3">
            <div>
              <span className="text-[11px] text-cyber-primary font-bold uppercase block mb-1">
                Client Request Headers (Masked):
              </span>
              <pre className="text-gray-300 font-mono text-[11px] whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(bundle.httpHeaders?.request || {}, null, 2)}
              </pre>
            </div>
            <div className="pt-2 border-t border-cyber-border/40">
              <span className="text-[11px] text-cyber-secondary font-bold uppercase block mb-1">
                Server Response Headers:
              </span>
              <pre className="text-gray-300 font-mono text-[11px] whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(bundle.httpHeaders?.response || {}, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {activeTab === 'tls' && (
          <div className="space-y-2">
            <span className="text-[11px] text-green-400 font-bold uppercase block mb-1">
              TLS / Cryptographic Handshake Details:
            </span>
            <pre className="text-gray-300 font-mono text-[11px] whitespace-pre-wrap leading-relaxed">
              {JSON.stringify(bundle.tlsInformation || {}, null, 2)}
            </pre>
          </div>
        )}

        {activeTab === 'tech' && (
          <div className="space-y-2">
            <span className="text-[11px] text-cyber-primary font-bold uppercase block mb-2">
              Identified Web Server & Application Stack:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {(bundle.detectedTechnologies || []).map((t, i) => (
                <div key={i} className="p-2.5 rounded bg-black/40 border border-cyber-border/60 flex items-center justify-between">
                  <div>
                    <span className="font-bold text-white block">{t.name}</span>
                    <span className="text-[10px] text-gray-400">{t.category}</span>
                  </div>
                  <span className="text-[11px] font-mono text-cyber-primary">{t.version}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'scripts' && (
          <div className="space-y-2">
            <span className="text-[11px] text-red-400 font-bold uppercase block mb-2">
              Suspicious Inline Scripts & Payloads:
            </span>
            {bundle.suspiciousScripts && bundle.suspiciousScripts.length > 0 ? (
              bundle.suspiciousScripts.map((s, idx) => (
                <div key={idx} className="p-2.5 rounded bg-red-500/10 border border-red-500/30 text-red-300 font-mono text-[11px] break-all">
                  {s}
                </div>
              ))
            ) : (
              <p className="text-gray-400">No obfuscated or malicious inline JavaScript detected.</p>
            )}
          </div>
        )}

        {activeTab === 'iocs' && (
          <div className="space-y-2">
            <span className="text-[11px] text-cyber-warning font-bold uppercase block mb-2">
              Extracted Indicators of Compromise (IoCs):
            </span>
            <div className="divide-y divide-cyber-border/40">
              {(bundle.extractedIndicators || []).map((ioc, idx) => (
                <div key={idx} className="py-2 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.2 rounded bg-black/60 border border-cyber-border text-[10px] uppercase font-bold text-gray-400">
                      {ioc.type}
                    </span>
                    <span className="text-white font-mono break-all">{ioc.value}</span>
                  </div>
                  <span className={`px-2 py-0.2 rounded text-[10px] font-bold border ${
                    ioc.reputation === 'Malicious' ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-green-500/20 text-green-400 border-green-500/40'
                  }`}>
                    {ioc.reputation}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EvidencePanel;
