import React from 'react';
import { 
  ShieldAlert, LayoutDashboard, Globe, FileCode2, Network, 
  Database, Settings, ChevronLeft, ChevronRight, Shield, Sun, Moon 
} from 'lucide-react';

const Sidebar = ({ 
  activeModule, 
  setActiveModule, 
  isCollapsed, 
  setIsCollapsed, 
  onOpenSettings,
  isLightMode,
  onToggleTheme 
}) => {
  const menuItems = [
    { id: 'dashboard', label: 'Live Dashboard', icon: LayoutDashboard },
    { id: 'url-inspector', label: 'URL Inspector', icon: Globe, badge: 'ACTIVE' },
    { id: 'file-scanner', label: 'File Threat Scanner', icon: FileCode2 },
    { id: 'network-monitor', label: 'Network Monitor', icon: Network },
    { id: 'models', label: 'Model Performance', icon: Database },
    { id: 'settings', label: 'Settings', icon: Settings, isAction: true }
  ];

  const handleItemClick = (item) => {
    if (item.isAction && item.id === 'settings' && onOpenSettings) {
      onOpenSettings();
    } else {
      setActiveModule(item.id);
    }
  };

  return (
    <aside 
      className={`bg-cyber-dark/95 border-r border-cyber-border flex flex-col transition-all duration-300 z-40 shrink-0 select-none ${
        isCollapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-cyber-border/80">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="w-9 h-9 rounded-lg bg-cyber-primary/10 border border-cyber-primary/40 flex items-center justify-center shrink-0 shadow-[0_0_12px_rgba(0,240,255,0.25)]">
            <ShieldAlert className="w-5 h-5 text-cyber-primary animate-pulse" />
          </div>
          {!isCollapsed && (
            <div className="flex flex-col min-w-0">
              <span className="text-sm font-bold tracking-wider font-mono text-white truncate flex items-center gap-1.5">
                AI-NIDS <span className="text-cyber-primary text-xs px-1 py-0.2 rounded bg-cyber-primary/20 border border-cyber-primary/40">SOC</span>
              </span>
              <span className="text-[10px] font-mono text-gray-400 truncate tracking-tight">
                Neural Defense Engine
              </span>
            </div>
          )}
        </div>

        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="p-1 rounded-md text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      {/* Navigation Modules */}
      <div className="flex-1 overflow-y-auto py-3 px-2 space-y-1">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeModule === item.id;

          return (
            <button
              key={item.id}
              onClick={() => handleItemClick(item)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg font-mono text-xs transition-all text-left relative group ${
                isActive
                  ? 'bg-cyber-primary/15 text-cyber-primary border border-cyber-primary/40 shadow-[0_0_15px_rgba(0,240,255,0.15)] font-semibold'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'
              }`}
              title={isCollapsed ? item.label : undefined}
            >
              <Icon size={18} className={`shrink-0 ${isActive ? 'text-cyber-primary' : 'text-gray-400 group-hover:text-gray-200'}`} />
              
              {!isCollapsed && (
                <div className="flex-1 flex items-center justify-between min-w-0">
                  <span className="truncate">{item.label}</span>
                  {item.badge && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/40 font-mono tracking-wider font-bold">
                      {item.badge}
                    </span>
                  )}
                  {item.alertCount && (
                    <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-red-500/20 text-red-400 border border-red-500/40 font-bold">
                      {item.alertCount}
                    </span>
                  )}
                </div>
              )}

              {/* Active Indicator Bar */}
              {isActive && (
                <span className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-cyber-primary rounded-r" />
              )}
            </button>
          );
        })}
      </div>

      {/* SOC Security Status & Theme Mode Footer */}
      {!isCollapsed ? (
        <div className="p-3 m-2 rounded-lg bg-black/40 border border-cyber-border/70 text-[11px] font-mono flex flex-col gap-2">
          <div className="flex items-center justify-between text-gray-400">
            <span className="flex items-center gap-1.5">
              <Shield size={12} className="text-green-400" /> Defense Grid:
            </span>
            <span className="text-green-400 font-bold">ONLINE</span>
          </div>
          
          {/* Visible Theme Switch Button */}
          <button
            type="button"
            onClick={onToggleTheme}
            className={`w-full p-2 rounded-lg border-2 font-mono text-xs font-bold transition-all flex items-center justify-between cursor-pointer shadow-md select-none ${
              isLightMode
                ? 'bg-slate-900 text-white border-slate-700 hover:bg-black shadow-[0_0_12px_rgba(15,23,42,0.25)]'
                : 'bg-yellow-400/15 text-yellow-300 border-yellow-400 shadow-[0_0_15px_rgba(250,204,21,0.3)] hover:bg-yellow-400/25'
            }`}
            title={isLightMode ? 'Switch to Dark Mode' : 'Switch to White Background'}
          >
            <div className="flex items-center gap-1.5">
              {isLightMode ? <Moon size={14} className="text-sky-400" /> : <Sun size={14} className="text-yellow-400" />}
              <span>{isLightMode ? 'Dark Mode' : 'White Mode'}</span>
            </div>
            <span className={`px-1.5 py-0.2 rounded text-[10px] font-black uppercase ${
              isLightMode ? 'bg-sky-500 text-white' : 'bg-yellow-400 text-black'
            }`}>
              TOGGLE
            </span>
          </button>

          <p className="text-[10px] text-gray-500 truncate">Agent v2.6.4 • Node EU-01</p>
        </div>
      ) : (
        <div className="p-2 flex flex-col items-center gap-2 pb-4">
          <button
            type="button"
            onClick={onToggleTheme}
            className={`p-2 rounded-lg border-2 transition-all flex items-center justify-center cursor-pointer ${
              isLightMode
                ? 'bg-slate-900 text-white border-slate-700'
                : 'bg-yellow-400/15 text-yellow-300 border-yellow-400 shadow-[0_0_10px_rgba(250,204,21,0.3)]'
            }`}
            title={isLightMode ? 'Switch to Dark Mode' : 'Switch to White Background'}
          >
            {isLightMode ? <Moon size={16} className="text-sky-400" /> : <Sun size={16} className="text-yellow-400" />}
          </button>
          <div className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" title="SOC Defense Grid: ONLINE" />
        </div>
      )}
    </aside>
  );
};

export default Sidebar;
