import React, { useState } from 'react';
import { 
  GitBranch, ArrowRight, ArrowDown, Lock, Unlock, 
  Clock, Server, ChevronDown, ChevronUp, AlertTriangle, ShieldCheck 
} from 'lucide-react';

const RedirectChainVisualizer = ({ scanResult }) => {
  const [expandedHop, setExpandedHop] = useState(null);

  if (!scanResult) return null;

  const hops = scanResult.redirectChain || [];

  const toggleHop = (step) => {
    setExpandedHop(expandedHop === step ? null : step);
  };

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      <div className="flex items-center justify-between border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <GitBranch size={18} className="text-cyber-primary" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            Redirect Chain Visualization
          </h3>
        </div>
        <span className="text-[11px] text-gray-400">
          {hops.length} {hops.length === 1 ? 'Hop (Direct)' : 'Hops Traversed'}
        </span>
      </div>

      {/* Redirect Chain Flow Diagram */}
      <div className="flex flex-col gap-3">
        {hops.map((hop, index) => {
          const isExpanded = expandedHop === hop.step;
          const isSuspicious = hop.threatStatus === 'SUSPICIOUS' || hop.threatStatus === 'MALICIOUS';
          const isFinal = index === hops.length - 1;

          return (
            <div key={hop.step} className="flex flex-col gap-2">
              {/* Hop Node Card */}
              <div 
                className={`p-4 rounded-xl border bg-black/40 transition-all ${
                  isSuspicious 
                    ? 'border-yellow-500/50 shadow-[0_0_12px_rgba(255,176,0,0.15)]' 
                    : 'border-cyber-border hover:border-gray-600'
                }`}
              >
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
                  {/* Left Hop Title & URL */}
                  <div className="flex items-start gap-3 flex-1 min-w-0">
                    <div className={`w-7 h-7 rounded-lg border flex items-center justify-center font-bold text-xs shrink-0 ${
                      isSuspicious ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40' : 'bg-cyber-primary/10 text-cyber-primary border-cyber-primary/40'
                    }`}>
                      {hop.step}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="text-xs font-bold text-white uppercase">
                          {hop.type || `Hop ${hop.step}`}
                        </span>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold border ${
                          hop.statusCode >= 300 && hop.statusCode < 400
                            ? 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                            : 'bg-green-500/20 text-green-400 border-green-500/40'
                        }`}>
                          HTTP {hop.statusCode} {hop.statusText}
                        </span>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold border ${
                          isSuspicious ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-green-500/20 text-green-400 border-green-500/40'
                        }`}>
                          {hop.threatStatus}
                        </span>
                      </div>

                      <p className="text-xs font-semibold text-gray-200 break-all">
                        {hop.url}
                      </p>
                    </div>
                  </div>

                  {/* Right Telemetry Badges */}
                  <div className="flex items-center gap-3 text-xs shrink-0 self-end md:self-auto">
                    <span className="flex items-center gap-1 text-gray-400 text-[11px]">
                      <Clock size={12} className="text-cyber-primary" /> {hop.responseTimeMs}ms
                    </span>
                    <span className="flex items-center gap-1 text-gray-400 text-[11px]">
                      {hop.hasHttps ? (
                        <>
                          <Lock size={12} className="text-green-400" /> <span className="text-green-400">HTTPS</span>
                        </>
                      ) : (
                        <>
                          <Unlock size={12} className="text-yellow-400" /> <span className="text-yellow-400">HTTP</span>
                        </>
                      )}
                    </span>
                    <button
                      type="button"
                      onClick={() => toggleHop(hop.step)}
                      className="p-1 rounded text-cyber-primary hover:bg-white/5 transition-colors"
                      title="Inspect headers & telemetry"
                    >
                      {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </button>
                  </div>
                </div>

                {/* Expanded Hop Headers & Details */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-cyber-border/60 text-xs text-gray-300 space-y-2 animate-in fade-in duration-150">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                      <div className="p-2 rounded bg-black/60 border border-cyber-border/70">
                        <span className="text-gray-400 block text-[10px] uppercase">Host IP:</span>
                        <span className="font-bold text-white">{hop.ip || '127.0.0.1'}</span>
                      </div>
                      <div className="p-2 rounded bg-black/60 border border-cyber-border/70">
                        <span className="text-gray-400 block text-[10px] uppercase">Domain:</span>
                        <span className="font-bold text-cyber-primary">{hop.domain}</span>
                      </div>
                    </div>

                    <div className="p-2.5 rounded bg-black/60 border border-cyber-border/70 text-[10px]">
                      <span className="text-gray-400 uppercase font-bold block mb-1">HTTP Response Headers:</span>
                      {hop.headers ? (
                        Object.entries(hop.headers).map(([k, v]) => (
                          <div key={k} className="flex gap-2">
                            <span className="text-cyber-primary font-semibold">{k}:</span>
                            <span className="text-gray-300 break-all">{v}</span>
                          </div>
                        ))
                      ) : (
                        <p className="text-gray-500">No custom headers recorded.</p>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Connecting Down Arrow between hops */}
              {!isFinal && (
                <div className="flex items-center justify-center py-0.5 text-cyber-primary">
                  <ArrowDown size={18} className="animate-bounce" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default RedirectChainVisualizer;
