import React from 'react';
import { Crosshair, Cpu, Globe, Database, Bug } from 'lucide-react';
import { triggerAttack } from '../services/trafficGenerator';

const AttackButton = ({ label, icon: Icon, type, colorClass }) => (
  <button 
    onClick={() => triggerAttack(type)}
    className={`p-3 rounded glass-panel flex flex-col items-center justify-center gap-2 hover:bg-black/40 transition-all active:scale-95 group border-transparent hover:border-current ${colorClass}`}
  >
    <Icon size={24} className="group-hover:scale-110 transition-transform" />
    <span className="font-mono text-xs text-white group-hover:text-current font-bold uppercase text-center">
      {label}
    </span>
  </button>
);

const AttackSimulator = ({ onTriggerAttack }) => {
  return (
    <div className="glass-panel flex-1 flex flex-col">
      <div className="p-3 border-b border-cyber-border bg-black/40">
        <div className="flex items-center gap-2 text-cyber-warning">
          <Crosshair size={18} />
          <h2 className="font-mono text-sm tracking-wider uppercase">Attack Simulator</h2>
        </div>
        <p className="text-xs text-gray-500 mt-1 font-mono">Inject synthetic attack vectors into live traffic.</p>
      </div>

      <div className="p-4 grid grid-cols-2 gap-3 flex-1 content-start overflow-y-auto">
        <AttackButton 
          label="DDoS Flood" 
          icon={Globe} 
          type="DDoS" 
          colorClass="text-cyber-danger" 
        />
        <AttackButton 
          label="Port Scan" 
          icon={Crosshair} 
          type="Port Scan" 
          colorClass="text-cyber-warning" 
        />
        <AttackButton 
          label="SQL Injection" 
          icon={Database} 
          type="SQL Injection" 
          colorClass="text-purple-400" 
        />
        <AttackButton 
          label="Malware C2" 
          icon={Bug} 
          type="Malware C2" 
          colorClass="text-cyber-primary" 
        />
        <AttackButton 
          label="Zero-Day" 
          icon={Cpu} 
          type="Zero-Day" 
          colorClass="text-cyber-success" 
        />
      </div>
    </div>
  );
};

export default AttackSimulator;
