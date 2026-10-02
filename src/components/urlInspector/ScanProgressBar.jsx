import React from 'react';
import { Loader2, CheckCircle2, AlertOctagon, RotateCw, Terminal } from 'lucide-react';

export const SCAN_STAGES = [
  'URL normalization',
  'Domain analysis',
  'DNS analysis',
  'TLS analysis',
  'Redirect analysis',
  'Reputation analysis',
  'Threat intelligence',
  'ML classification',
  'Risk calculation'
];

const ScanProgressBar = ({ currentStageIndex, isFailed, failureReason, onRetry }) => {
  const percent = Math.min(100, Math.round(((currentStageIndex + 1) / SCAN_STAGES.length) * 100));

  if (isFailed) {
    return (
      <div className="glass-panel p-6 border-l-4 border-l-red-500 flex flex-col gap-4 font-mono animate-in fade-in">
        <div className="flex items-start gap-3">
          <AlertOctagon size={24} className="text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <h3 className="text-base font-bold text-white tracking-wide">Analysis could not be completed</h3>
            <p className="text-xs text-red-300 mt-1">
              Reason: {failureReason || 'Target endpoint timed out or returned an invalid network response.'}
            </p>
          </div>
        </div>

        <div className="p-3 rounded bg-black/50 border border-red-500/30 text-xs text-gray-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal size={14} className="text-gray-400" />
            <span>Error Code: ERR_TIMEOUT_DNS_RESOLUTION (Socket ETIMEDOUT)</span>
          </div>
          <button
            onClick={() => alert(`Technical Diagnostic:\nEndpoint: DNS Resolver failed\nStatus: 504 Gateway Timeout\nTrace: socket.connect() aborted after 5000ms timeout`)}
            className="text-xs text-cyber-primary hover:underline"
          >
            View technical error
          </button>
        </div>

        <div className="flex justify-end gap-3 pt-2">
          <button
            type="button"
            onClick={onRetry}
            className="px-4 py-2 rounded-lg bg-cyber-primary text-black font-bold text-xs flex items-center gap-2 hover:bg-cyber-primary/90 transition-all"
          >
            <RotateCw size={14} /> Retry Analysis
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="glass-panel p-6 border-l-4 border-l-cyber-primary flex flex-col gap-5 font-mono animate-in fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <Loader2 size={20} className="text-cyber-primary animate-spin" />
          <div>
            <span className="text-xs uppercase text-cyber-primary tracking-wider font-bold">
              Analyzing URL...
            </span>
            <h3 className="text-sm font-semibold text-white mt-0.5">
              Stage {currentStageIndex + 1} of {SCAN_STAGES.length}: {SCAN_STAGES[currentStageIndex]}
            </h3>
          </div>
        </div>

        <span className="text-base font-bold text-cyber-primary">
          {percent}%
        </span>
      </div>

      {/* Progress Bar Line */}
      <div className="w-full h-2 bg-black/60 rounded-full overflow-hidden border border-cyber-border">
        <div 
          className="h-full bg-gradient-to-r from-cyber-primary to-cyber-secondary transition-all duration-300 shadow-[0_0_10px_rgba(0,240,255,0.5)]"
          style={{ width: `${percent}%` }}
        />
      </div>

      {/* 9 Stage Chips Grid */}
      <div className="grid grid-cols-3 sm:grid-cols-5 md:grid-cols-9 gap-1.5 pt-1">
        {SCAN_STAGES.map((stage, idx) => {
          const isDone = idx < currentStageIndex;
          const isCurrent = idx === currentStageIndex;

          return (
            <div
              key={stage}
              className={`p-2 rounded border text-[10px] flex flex-col items-center justify-center text-center gap-1 transition-all ${
                isDone
                  ? 'bg-green-500/10 border-green-500/40 text-green-400'
                  : isCurrent
                  ? 'bg-cyber-primary/20 border-cyber-primary text-cyber-primary shadow-[0_0_8px_rgba(0,240,255,0.3)] animate-pulse'
                  : 'bg-black/30 border-cyber-border/40 text-gray-500'
              }`}
            >
              {isDone ? (
                <CheckCircle2 size={12} className="text-green-400" />
              ) : isCurrent ? (
                <Loader2 size={12} className="text-cyber-primary animate-spin" />
              ) : (
                <span className="w-2.5 h-2.5 rounded-full border border-gray-600" />
              )}
              <span className="truncate w-full">{stage}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ScanProgressBar;
