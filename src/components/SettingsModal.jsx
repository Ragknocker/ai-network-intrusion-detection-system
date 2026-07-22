import React from 'react';
import { X, Settings, ShieldCheck, Database, Sliders, Trash2, CheckCircle2 } from 'lucide-react';

const SettingsModal = ({ 
  isOpen, 
  onClose, 
  settings, 
  onUpdateSettings, 
  blockedIPs, 
  onUnblockIP 
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md animate-fade-in">
      <div className="glass-panel w-full max-w-2xl bg-black/90 border border-cyber-primary/40 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 border-b border-cyber-border flex justify-between items-center bg-black/60">
          <div className="flex items-center gap-3 text-cyber-primary">
            <Settings className="w-5 h-5 animate-spin-slow" />
            <h2 className="font-mono text-base font-bold tracking-wider uppercase">SOC Engine Settings</h2>
          </div>
          <button 
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-white hover:bg-white/10 rounded transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 overflow-y-auto font-mono text-sm">
          {/* AWS Lambda Integration Section */}
          <div className="space-y-3 p-4 rounded-lg bg-cyber-primary/5 border border-cyber-primary/20">
            <div className="flex items-center gap-2 text-cyber-primary font-bold">
              <Database size={16} />
              <h3>AWS Lambda ML Backend</h3>
            </div>

            <div className="space-y-2">
              <label className="text-xs text-gray-400">Lambda Function Endpoint URL</label>
              <input 
                type="text" 
                value={settings.lambdaUrl}
                onChange={(e) => onUpdateSettings({ ...settings, lambdaUrl: e.target.value })}
                className="w-full px-3 py-2 bg-black/60 border border-cyber-border rounded text-xs font-mono text-cyber-primary focus:outline-none focus:border-cyber-primary"
                placeholder="https://your-lambda-url.lambda-url.region.on.aws/"
              />
            </div>

            <div className="flex items-center justify-between pt-1">
              <div>
                <span className="text-xs text-gray-300">Live AI Backend Classification</span>
                <p className="text-[10px] text-gray-500">Route packet telemetry to live AWS Random Forest Lambda function</p>
              </div>
              <input 
                type="checkbox"
                checked={settings.useLiveLambda}
                onChange={(e) => onUpdateSettings({ ...settings, useLiveLambda: e.target.checked })}
                className="w-4 h-4 accent-cyber-primary cursor-pointer"
              />
            </div>
          </div>

          {/* Detection Thresholds */}
          <div className="space-y-3 p-4 rounded-lg bg-white/5 border border-cyber-border">
            <div className="flex items-center gap-2 text-cyber-secondary font-bold">
              <Sliders size={16} />
              <h3>Detection Sensitivity</h3>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-gray-400">Threat Alert Confidence Threshold</span>
                <span className="text-cyber-secondary font-bold">{settings.sensitivityThreshold}%</span>
              </div>
              <input 
                type="range" 
                min="50" 
                max="95" 
                value={settings.sensitivityThreshold}
                onChange={(e) => onUpdateSettings({ ...settings, sensitivityThreshold: Number(e.target.value) })}
                className="w-full accent-cyber-secondary cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-white/5">
              <div>
                <span className="text-xs text-gray-300">Auto-Block Critical Threats</span>
                <p className="text-[10px] text-gray-500">Automatically block IP when threat score exceeds 90%</p>
              </div>
              <input 
                type="checkbox"
                checked={settings.autoBlockCritical}
                onChange={(e) => onUpdateSettings({ ...settings, autoBlockCritical: e.target.checked })}
                className="w-4 h-4 accent-cyber-secondary cursor-pointer"
              />
            </div>
          </div>

          {/* Blocked IPs Manager */}
          <div className="space-y-3 p-4 rounded-lg bg-cyber-danger/5 border border-cyber-danger/20">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-cyber-danger font-bold">
                <ShieldCheck size={16} />
                <h3>Active Firewall IP Blocklist</h3>
              </div>
              <span className="text-xs px-2 py-0.5 rounded bg-cyber-danger/20 text-cyber-danger">
                {blockedIPs.length} Blocked
              </span>
            </div>

            {blockedIPs.length === 0 ? (
              <p className="text-xs text-gray-500 italic py-2">No IP addresses currently blocked by firewall.</p>
            ) : (
              <div className="space-y-2 max-h-36 overflow-y-auto pr-1">
                {blockedIPs.map((ip) => (
                  <div key={ip} className="flex justify-between items-center p-2 rounded bg-black/60 border border-cyber-danger/30 text-xs">
                    <span className="font-mono text-gray-200">{ip}</span>
                    <button 
                      onClick={() => onUnblockIP(ip)}
                      className="px-2 py-1 text-[10px] text-cyber-success hover:bg-cyber-success/20 rounded border border-cyber-success/40 transition-colors flex items-center gap-1"
                    >
                      <Trash2 size={12} /> UNBLOCK
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-cyber-border flex justify-end bg-black/60">
          <button 
            onClick={onClose}
            className="px-4 py-2 bg-cyber-primary text-black font-bold font-mono text-xs rounded hover:bg-cyber-primary/80 transition-colors flex items-center gap-1.5"
          >
            <CheckCircle2 size={14} /> SAVE & CLOSE
          </button>
        </div>
      </div>
    </div>
  );
};

export default SettingsModal;
