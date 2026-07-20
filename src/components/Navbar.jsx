import React from 'react';
import { ShieldAlert, Activity, Database, Settings } from 'lucide-react';

const Navbar = ({ activeTab, setActiveTab, threatLevel }) => {
  return (
    <nav className="glass-panel mx-6 mt-6 p-4 flex justify-between items-center z-50">
      <div className="flex items-center gap-3">
        <ShieldAlert className={`w-8 h-8 ${threatLevel === 'Critical' ? 'text-cyber-danger animate-pulse' : 'text-cyber-primary'}`} />
        <div>
          <h1 className="text-xl font-bold tracking-wider uppercase bg-clip-text text-transparent bg-gradient-to-r from-cyber-primary to-cyber-secondary">
            AI-NIDS SOC
          </h1>
          <p className="text-xs text-gray-400 font-mono">Neural Threat Detection Engine</p>
        </div>
      </div>

      <div className="flex gap-4">
        <button 
          onClick={() => setActiveTab('dashboard')}
          className={`flex items-center gap-2 px-4 py-2 rounded transition-all duration-300 font-mono text-sm
            ${activeTab === 'dashboard' ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/50' : 'text-gray-400 hover:text-white'}`}
        >
          <Activity size={16} /> Live Dashboard
        </button>
        <button 
          onClick={() => setActiveTab('models')}
          className={`flex items-center gap-2 px-4 py-2 rounded transition-all duration-300 font-mono text-sm
            ${activeTab === 'models' ? 'bg-cyber-secondary/20 text-cyber-secondary border border-cyber-secondary/50' : 'text-gray-400 hover:text-white'}`}
        >
          <Database size={16} /> Model Performance
        </button>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1 bg-black/40 rounded border border-cyber-border">
          <div className={`w-2 h-2 rounded-full ${threatLevel === 'Critical' ? 'bg-cyber-danger animate-ping' : threatLevel === 'High' ? 'bg-cyber-warning' : 'bg-cyber-success'}`}></div>
          <span className="font-mono text-xs uppercase tracking-widest text-gray-300">Status: {threatLevel}</span>
        </div>
        <button className="p-2 text-gray-400 hover:text-cyber-primary transition-colors">
          <Settings size={20} />
        </button>
      </div>
    </nav>
  );
};

export default Navbar;
