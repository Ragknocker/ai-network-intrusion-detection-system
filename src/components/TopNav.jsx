import React, { useState, useEffect } from 'react';
import { 
  Search, Bell, HelpCircle, Shield, User, 
  Moon, Sun, CheckCircle, AlertTriangle, ExternalLink, X 
} from 'lucide-react';

const TopNav = ({ 
  threatLevel = 'Low', 
  onGlobalSearch, 
  onOpenSettings,
  activeModule,
  setActiveModule,
  isLightMode: propIsLightMode,
  onToggleTheme 
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [showNotifications, setShowNotifications] = useState(false);
  const [showHelpModal, setShowHelpModal] = useState(false);
  const [internalLightMode, setInternalLightMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('ai_nids_theme') === 'light';
    }
    return false;
  });

  const isLightMode = propIsLightMode !== undefined ? propIsLightMode : internalLightMode;

  const toggleTheme = () => {
    if (onToggleTheme) {
      onToggleTheme();
    } else {
      const next = !internalLightMode;
      setInternalLightMode(next);
      if (next) {
        document.documentElement.classList.add('light-mode');
        localStorage.setItem('ai_nids_theme', 'light');
      } else {
        document.documentElement.classList.remove('light-mode');
        localStorage.setItem('ai_nids_theme', 'dark');
      }
    }
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    if (searchQuery.trim() && onGlobalSearch) {
      onGlobalSearch(searchQuery.trim());
      setActiveModule('url-inspector');
    }
  };

  return (
    <header className="h-16 bg-cyber-dark/95 border-b border-cyber-border px-4 lg:px-6 flex items-center justify-between gap-4 z-30 select-none">
      {/* Global Search Bar */}
      <form onSubmit={handleSearchSubmit} className="flex-1 max-w-xl relative">
        <div className="relative">
          <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Global search: URL, domain, IPv4, scan ID (e.g. SCAN-2026-8941)..."
            className="w-full pl-10 pr-24 py-2 bg-black/40 border border-cyber-border/80 rounded-lg text-xs font-mono text-white placeholder-gray-500 focus:outline-none focus:border-cyber-primary focus:ring-1 focus:ring-cyber-primary transition-all"
          />
          <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1 text-[10px] font-mono text-gray-500 pointer-events-none">
            <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-cyber-border">ESC</kbd>
            <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-cyber-border">↵</kbd>
          </div>
        </div>
      </form>

      {/* Top Controls */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        {/* System Status Indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-black/40 border border-cyber-border text-xs font-mono">
          <div className={`w-2 h-2 rounded-full ${
            threatLevel === 'Critical' ? 'bg-cyber-danger animate-ping' : 
            threatLevel === 'High' ? 'bg-cyber-warning' : 'bg-green-400 animate-pulse'
          }`} />
          <span className="text-gray-400 uppercase text-[11px] tracking-wider">
            Status: <span className="font-bold text-white">{threatLevel === 'Low' ? 'NORMAL (DEFCON 4)' : threatLevel}</span>
          </span>
        </div>

        {/* Notifications Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-colors relative"
            title="Notifications"
          >
            <Bell size={18} />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-cyber-primary ring-2 ring-cyber-dark" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 rounded-xl bg-cyber-panel border border-cyber-border shadow-2xl p-3 z-50 animate-in fade-in zoom-in-95 duration-150 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-cyber-border/70">
                <span className="font-bold text-white uppercase tracking-wider text-[11px]">SOC Alerts</span>
                <span className="text-[10px] text-cyber-primary">3 New</span>
              </div>
              <div className="divide-y divide-cyber-border/40 max-h-64 overflow-y-auto">
                {notifications.map((n) => (
                  <div key={n.id} className="py-2.5 flex items-start gap-2 hover:bg-white/5 px-1 rounded transition-colors cursor-pointer">
                    <span className={`w-2 h-2 rounded-full mt-1 shrink-0 ${
                      n.severity === 'critical' ? 'bg-red-400' : (n.severity === 'warning' ? 'bg-yellow-400' : 'bg-blue-400')
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-semibold truncate">{n.title}</p>
                      <p className="text-gray-400 text-[10px] truncate">{n.domain}</p>
                    </div>
                    <span className="text-[9px] text-gray-500 whitespace-nowrap">{n.time}</span>
                  </div>
                ))}
              </div>
              <div className="pt-2 border-t border-cyber-border/70 text-center">
                <button 
                  onClick={() => { setShowNotifications(false); setActiveModule('alerts'); }}
                  className="text-[11px] text-cyber-primary hover:underline"
                >
                  View All Alerts in Incident Center
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Highly Visible Theme Mode Toggle Button */}
        <button
          type="button"
          onClick={toggleTheme}
          className={`px-3.5 py-1.5 rounded-xl border-2 transition-all flex items-center gap-2 font-mono text-xs font-black cursor-pointer shadow-lg select-none ${
            isLightMode 
              ? 'bg-slate-900 text-white border-slate-700 hover:bg-black shadow-[0_0_15px_rgba(15,23,42,0.25)]' 
              : 'bg-yellow-400/15 text-yellow-300 border-yellow-400 shadow-[0_0_20px_rgba(250,204,21,0.35)] hover:bg-yellow-400/25 hover:shadow-[0_0_25px_rgba(250,204,21,0.5)]'
          }`}
          title={isLightMode ? 'Switch to Dark Background' : 'Switch to White Background'}
        >
          <span className={`w-5 h-5 rounded-lg flex items-center justify-center font-bold ${
            isLightMode ? 'bg-sky-500 text-white' : 'bg-yellow-400 text-black shadow-[0_0_8px_#facc15]'
          }`}>
            {isLightMode ? <Moon size={12} /> : <Sun size={12} />}
          </span>
          <span className="tracking-wider">
            {isLightMode ? 'DARK THEME' : 'WHITE THEME'}
          </span>
        </button>

        {/* Help Center Button */}
        <button
          onClick={() => setShowHelpModal(true)}
          className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
          title="SOC Operator Help & Documentation"
        >
          <HelpCircle size={18} />
        </button>

        {/* User Profile */}
        <div className="flex items-center gap-2.5 pl-2 border-l border-cyber-border/80">
          <div className="w-8 h-8 rounded-lg bg-cyber-primary/20 border border-cyber-primary/40 flex items-center justify-center font-mono font-bold text-xs text-cyber-primary shrink-0 shadow-[0_0_10px_rgba(0,240,255,0.2)]">
            OP
          </div>
          <div className="hidden xl:flex flex-col">
            <span className="text-xs font-mono font-semibold text-white leading-tight">SecOps Analyst</span>
            <span className="text-[10px] font-mono text-gray-400 leading-tight">Tier-3 • Cyber Incident Lead</span>
          </div>
        </div>
      </div>

      {/* Help Modal */}
      {showHelpModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-cyber-panel border border-cyber-border rounded-xl max-w-lg w-full p-6 shadow-2xl font-mono relative animate-in fade-in zoom-in-95 duration-200">
            <button
              onClick={() => setShowHelpModal(false)}
              className="absolute top-4 right-4 text-gray-400 hover:text-white"
            >
              <X size={18} />
            </button>

            <div className="flex items-center gap-2.5 text-cyber-primary mb-3">
              <Shield size={22} />
              <h3 className="text-base font-bold text-white tracking-wider">AI-NIDS SOC Operator Guide</h3>
            </div>

            <p className="text-xs text-gray-300 leading-relaxed mb-4">
              The URL Inspector module integrates XGBoost Machine Learning, Char-CNN anomaly detection, domain reputation intelligence, and heuristic signature matching to provide real-time web threat triage.
            </p>

            <div className="space-y-2.5 text-xs text-gray-300">
              <div className="p-2.5 rounded bg-black/40 border border-cyber-border">
                <span className="font-bold text-cyber-primary block mb-0.5">Unified Threat Scoring (0-100)</span>
                Scores ≥ 70 are classified as <span className="text-red-400 font-bold">MALICIOUS</span>. Scores 35-69 represent <span className="text-yellow-400 font-bold">SUSPICIOUS</span> links.
              </div>
              <div className="p-2.5 rounded bg-black/40 border border-cyber-border">
                <span className="font-bold text-cyber-primary block mb-0.5">Privacy Notice</span>
                URLs are inspected in sandboxed memory. Do not submit URLs containing sensitive private tokens or passwords.
              </div>
              <div className="p-2.5 rounded bg-black/40 border border-cyber-border">
                <span className="font-bold text-cyber-primary block mb-0.5">Investigation Mode</span>
                Click &quot;Investigate URL&quot; on any result to view full forensic telemetry, IoCs, add analyst notes, and update case triage status.
              </div>
            </div>

            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setShowHelpModal(false)}
                className="px-4 py-2 bg-cyber-primary text-black font-bold text-xs rounded-lg hover:bg-cyber-primary/90"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};

export default TopNav;
