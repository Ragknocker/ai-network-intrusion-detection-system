import React from 'react';
import { ShieldAlert, Trash2, ShieldX } from 'lucide-react';

const ThreatAlertPanel = ({ alerts, onClear, onBlockIP }) => {
  return (
    <div className="glass-panel flex-1 flex flex-col overflow-hidden max-h-[500px]">
      <div className="p-3 border-b border-cyber-border flex justify-between items-center bg-black/40">
        <div className="flex items-center gap-2 text-cyber-danger">
          <ShieldAlert size={18} />
          <h2 className="font-mono text-sm tracking-wider uppercase">Active Threats</h2>
          <span className="bg-cyber-danger/20 text-cyber-danger px-2 py-0.5 rounded text-xs">
            {alerts.length}
          </span>
        </div>
        <button 
          onClick={onClear}
          className="p-1.5 text-gray-400 hover:text-white transition-colors rounded hover:bg-white/10"
          title="Clear Alerts"
        >
          <Trash2 size={16} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {alerts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-500 font-mono text-sm">
            <ShieldAlert size={32} className="mb-2 opacity-50" />
            <p>No active threats detected.</p>
          </div>
        ) : (
          alerts.map(alert => (
            <div 
              key={alert.id}
              className={`p-3 rounded border ${
                alert.severity === 'Critical' 
                  ? 'bg-cyber-danger/10 border-cyber-danger text-cyber-danger'
                  : 'bg-cyber-warning/10 border-cyber-warning text-cyber-warning'
              } flex flex-col gap-2 relative overflow-hidden`}
            >
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="font-bold tracking-wide uppercase text-sm">{alert.type} DETECTED</h4>
                  <p className="text-xs opacity-75 font-mono mt-1">{alert.timestamp}</p>
                </div>
                <span className="px-2 py-1 bg-black/40 rounded text-xs font-mono uppercase font-bold">
                  {alert.severity}
                </span>
              </div>
              
              <div className="text-xs font-mono opacity-90">
                <span className="text-white">SRC:</span> {alert.source} <span className="opacity-50 text-[10px]">({alert.geo})</span><br />
                <span className="text-white">DST:</span> {alert.target}
              </div>

              {alert.payloadInfo && (
                <div className="mt-1 p-1.5 bg-black/60 rounded text-[10px] font-mono break-all text-cyber-primary border border-cyber-primary/20">
                  <span className="text-gray-500 mr-1">SIG:</span>{alert.payloadInfo}
                </div>
              )}

              <div className="flex gap-2 mt-2">
                <button 
                  onClick={() => onBlockIP && onBlockIP(alert.source)}
                  disabled={alert.isBlocked}
                  className={`flex-1 py-1.5 text-xs font-mono rounded border transition-colors flex items-center justify-center gap-1 ${
                    alert.isBlocked 
                      ? 'bg-gray-800 border-gray-600 text-gray-500 cursor-not-allowed' 
                      : 'bg-cyber-danger/20 hover:bg-cyber-danger/40 border-cyber-danger/50 text-white'
                  }`}
                >
                  <ShieldX size={14} /> {alert.isBlocked ? 'BLOCKED' : 'BLOCK IP'}
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};


export default ThreatAlertPanel;
