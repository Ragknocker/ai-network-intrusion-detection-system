import React from 'react';
import { Activity, Radio, Shield, Zap } from 'lucide-react';

const MetricCard = ({ icon: Icon, title, value, unit, colorClass }) => (
  <div className="glass-panel p-4 flex items-center gap-4">
    <div className={`p-3 rounded-lg bg-black/50 ${colorClass}`}>
      <Icon size={24} />
    </div>
    <div>
      <p className="text-xs text-gray-400 font-mono uppercase">{title}</p>
      <div className="flex items-baseline gap-1">
        <h3 className="text-2xl font-bold text-white font-mono">{value}</h3>
        {unit && <span className="text-xs text-gray-500 font-mono">{unit}</span>}
      </div>
    </div>
  </div>
);

const MetricsOverview = ({ metrics }) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <MetricCard 
        icon={Activity} 
        title="Active Flows" 
        value={metrics.packetRate} 
        unit="pps"
        colorClass="text-cyber-primary"
      />
      <MetricCard 
        icon={Radio} 
        title="Bandwidth" 
        value={(metrics.bandwidth / 1024 / 1024).toFixed(2)} 
        unit="MB/s"
        colorClass="text-cyber-secondary"
      />
      <MetricCard 
        icon={Shield} 
        title="Blocked IPs" 
        value={metrics.blockedIPs}
        colorClass="text-cyber-warning"
      />
      <MetricCard 
        icon={Zap} 
        title="Total Analyzed" 
        value={metrics.totalAnalyzed.toLocaleString()}
        colorClass="text-cyber-success"
      />
    </div>
  );
};

export default MetricsOverview;
