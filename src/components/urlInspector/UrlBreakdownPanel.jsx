import React from 'react';
import { 
  Globe, Lock, Unlock, AlertTriangle, 
  Layers, Hash, Binary, Calendar, Cpu, Compass 
} from 'lucide-react';

const UrlBreakdownPanel = ({ scanResult }) => {
  if (!scanResult) return null;

  const decomp = scanResult.urlDecomposition || {};
  const features = scanResult.features || {};

  const isSuspiciousProtocol = decomp.protocol === 'http';
  const isSuspiciousIp = decomp.containsIp;
  const isSuspiciousSubdomain = decomp.subdomainCount >= 2;
  const isSuspiciousLength = decomp.length > 90;
  const hasEncodedChars = decomp.encodedCharCount > 0;

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      <div className="flex items-center justify-between border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <Globe size={18} className="text-cyber-primary" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            URL Anatomy & Features
          </h3>
        </div>
        <span className="text-[11px] text-gray-400">
          URL Breakdown & Decomposition
        </span>
      </div>

      {/* Component Breakdown Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
        {/* Protocol */}
        <div className={`p-3 rounded-lg bg-black/40 border transition-all ${
          isSuspiciousProtocol ? 'border-yellow-500/50 bg-yellow-500/5' : 'border-cyber-border'
        }`}>
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] uppercase text-gray-400">Protocol:</span>
            {isSuspiciousProtocol ? (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-yellow-500/20 text-yellow-400 font-bold">
                Unencrypted
              </span>
            ) : (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-green-500/20 text-green-400 font-bold">
                Encrypted
              </span>
            )}
          </div>
          <span className="text-sm font-bold text-white flex items-center gap-1.5">
            {decomp.protocol === 'https' ? (
              <Lock size={14} className="text-green-400" />
            ) : (
              <Unlock size={14} className="text-yellow-400" />
            )}
            {decomp.protocol || 'http'}
          </span>
        </div>

        {/* Domain */}
        <div className="p-3 rounded-lg bg-black/40 border border-cyber-border">
          <span className="text-[10px] uppercase text-gray-400 block mb-1">Domain:</span>
          <span className="text-sm font-bold text-cyber-primary truncate block" title={decomp.domain}>
            {decomp.domain || 'N/A'}
          </span>
        </div>

        {/* Subdomain */}
        <div className={`p-3 rounded-lg bg-black/40 border transition-all ${
          isSuspiciousSubdomain ? 'border-yellow-500/50 bg-yellow-500/5' : 'border-cyber-border'
        }`}>
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] uppercase text-gray-400">Subdomain:</span>
            {isSuspiciousSubdomain && (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-yellow-500/20 text-yellow-400">
                Multi-Level
              </span>
            )}
          </div>
          <span className="text-sm font-bold text-white truncate block" title={decomp.subdomain || 'None'}>
            {decomp.subdomain || '<Root Domain>'}
          </span>
        </div>

        {/* Port */}
        <div className="p-3 rounded-lg bg-black/40 border border-cyber-border">
          <span className="text-[10px] uppercase text-gray-400 block mb-1">Port:</span>
          <span className="text-sm font-bold text-white">
            {decomp.port || 'Default'}
          </span>
        </div>

        {/* Path */}
        <div className="p-3 rounded-lg bg-black/40 border border-cyber-border sm:col-span-2">
          <span className="text-[10px] uppercase text-gray-400 block mb-1">Path:</span>
          <span className="text-xs font-semibold text-gray-200 break-all block">
            {decomp.path || '/'}
          </span>
        </div>

        {/* Query Parameters */}
        <div className="p-3 rounded-lg bg-black/40 border border-cyber-border sm:col-span-2">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] uppercase text-gray-400">Query Parameters:</span>
            <span className="text-[10px] text-gray-400">
              {decomp.queryParamCount || 0} params
            </span>
          </div>
          <span className="text-xs font-semibold text-cyber-secondary break-all block">
            {decomp.queryParams || '<None>'}
          </span>
        </div>

        {/* Fragment */}
        <div className="p-3 rounded-lg bg-black/40 border border-cyber-border sm:col-span-2 lg:col-span-4">
          <span className="text-[10px] uppercase text-gray-400 block mb-1">Fragment (#hash):</span>
          <span className="text-xs font-semibold text-gray-400">
            {decomp.fragment || '<None>'}
          </span>
        </div>
      </div>

      {/* Structural Metric Badges */}
      <div className="pt-2 border-t border-cyber-border/60">
        <span className="text-[11px] text-gray-400 uppercase tracking-wider block mb-2">
          Structural Complexity & Heuristics:
        </span>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 text-center text-xs">
          <div className={`p-2 rounded bg-black/30 border ${isSuspiciousLength ? 'border-yellow-500/40 text-yellow-400' : 'border-cyber-border/40 text-gray-300'}`}>
            <span className="text-[10px] text-gray-500 block">Length</span>
            <span className="font-bold">{decomp.length || 0} chars</span>
          </div>

          <div className="p-2 rounded bg-black/30 border border-cyber-border/40 text-gray-300">
            <span className="text-[10px] text-gray-500 block">Parameters</span>
            <span className="font-bold">{decomp.queryParamCount || 0}</span>
          </div>

          <div className={`p-2 rounded bg-black/30 border ${isSuspiciousSubdomain ? 'border-yellow-500/40 text-yellow-400' : 'border-cyber-border/40 text-gray-300'}`}>
            <span className="text-[10px] text-gray-500 block">Subdomains</span>
            <span className="font-bold">{decomp.subdomainCount || 0}</span>
          </div>

          <div className="p-2 rounded bg-black/30 border border-cyber-border/40 text-gray-300">
            <span className="text-[10px] text-gray-500 block">Special Chars</span>
            <span className="font-bold">{decomp.specialCharCount || 0}</span>
          </div>

          <div className={`p-2 rounded bg-black/30 border ${hasEncodedChars ? 'border-red-500/40 text-red-400' : 'border-cyber-border/40 text-gray-300'}`}>
            <span className="text-[10px] text-gray-500 block">Encoded Chars</span>
            <span className="font-bold">{hasEncodedChars ? `${decomp.encodedCharCount} (%)` : 'None'}</span>
          </div>

          <div className={`p-2 rounded bg-black/30 border ${isSuspiciousIp ? 'border-red-500/40 text-red-400' : 'border-cyber-border/40 text-gray-300'}`}>
            <span className="text-[10px] text-gray-500 block">Host Type</span>
            <span className="font-bold">{isSuspiciousIp ? 'Raw IP (High Risk)' : 'FQDN Domain'}</span>
          </div>

          <div className={`p-2 rounded bg-black/30 border ${decomp.hasHttps ? 'border-green-500/40 text-green-400' : 'border-red-500/40 text-red-400'}`}>
            <span className="text-[10px] text-gray-500 block">HTTPS Status</span>
            <span className="font-bold">{decomp.hasHttps ? 'TLS 1.3 Active' : 'Unencrypted'}</span>
          </div>

          <div className="p-2 rounded bg-black/30 border border-cyber-border/40 text-gray-300">
            <span className="text-[10px] text-gray-500 block">Domain Age</span>
            <span className="font-bold">{decomp.domainAge || 'N/A'}</span>
          </div>
        </div>
      </div>

      {/* Suspicious Components Highlights */}
      {decomp.suspiciousFlags && decomp.suspiciousFlags.length > 0 && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-red-400 font-bold flex items-center gap-1">
            <AlertTriangle size={14} /> Suspicious Components:
          </span>
          {decomp.suspiciousFlags.map((flag, idx) => (
            <span key={idx} className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40 text-[11px]">
              {flag}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

export default UrlBreakdownPanel;
