import React from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer,
  AreaChart, Area
} from 'recharts';
import { Brain, Database } from 'lucide-react';

const mockModelMetrics = [
  { name: 'Normal', precision: 99.2, recall: 98.5, f1: 98.8 },
  { name: 'DDoS', precision: 96.5, recall: 97.1, f1: 96.8 },
  { name: 'Port Scan', precision: 94.2, recall: 91.8, f1: 93.0 },
  { name: 'SQLi', precision: 91.5, recall: 89.2, f1: 90.3 },
  { name: 'Zero-Day', precision: 85.4, recall: 82.1, f1: 83.7 },
];

const mockRocCurve = [
  { fpr: 0.0, tpr: 0.0 },
  { fpr: 0.05, tpr: 0.75 },
  { fpr: 0.1, tpr: 0.88 },
  { fpr: 0.2, tpr: 0.94 },
  { fpr: 0.3, tpr: 0.96 },
  { fpr: 0.5, tpr: 0.98 },
  { fpr: 1.0, tpr: 1.0 },
];

const ModelPerformance = () => {
  return (
    <div className="flex-1 grid grid-cols-12 gap-6 p-2 overflow-y-auto">
      
      {/* Metrics Summary */}
      <div className="col-span-12 flex gap-4">
        <div className="glass-panel p-6 flex-1 flex items-center justify-between">
          <div>
            <p className="text-gray-400 font-mono text-sm uppercase">Global Accuracy</p>
            <h2 className="text-4xl font-bold text-cyber-primary font-mono mt-1">96.4%</h2>
          </div>
          <Brain size={48} className="text-cyber-primary opacity-20" />
        </div>
        <div className="glass-panel p-6 flex-1 flex items-center justify-between">
          <div>
            <p className="text-gray-400 font-mono text-sm uppercase">Active Model</p>
            <h2 className="text-2xl font-bold text-cyber-secondary font-mono mt-1">Hybrid Forest-AE v2.1</h2>
          </div>
          <Database size={48} className="text-cyber-secondary opacity-20" />
        </div>
      </div>

      {/* Charts */}
      <div className="col-span-12 lg:col-span-8 glass-panel p-6">
        <h3 className="font-mono text-sm tracking-wider uppercase text-cyber-primary mb-6">Class-wise Performance (Precision/Recall)</h3>
        <div className="h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={mockModelMetrics} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3f" />
              <XAxis dataKey="name" stroke="#a0aec0" tick={{fill: '#a0aec0', fontSize: 12, fontFamily: 'monospace'}} />
              <YAxis stroke="#a0aec0" tick={{fill: '#a0aec0', fontSize: 12, fontFamily: 'monospace'}} domain={[0, 100]} />
              <RechartsTooltip 
                contentStyle={{ backgroundColor: '#151520', borderColor: '#2a2a3f', borderRadius: '8px', color: '#fff' }}
                itemStyle={{ fontFamily: 'monospace' }}
              />
              <Legend wrapperStyle={{ fontFamily: 'monospace', fontSize: '12px' }} />
              <Bar dataKey="precision" fill="#00f0ff" name="Precision (%)" radius={[4, 4, 0, 0]} />
              <Bar dataKey="recall" fill="#7000ff" name="Recall (%)" radius={[4, 4, 0, 0]} />
              <Bar dataKey="f1" fill="#00ff66" name="F1-Score (%)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="col-span-12 lg:col-span-4 glass-panel p-6">
        <h3 className="font-mono text-sm tracking-wider uppercase text-cyber-warning mb-6">ROC Curve (Anomaly Detector)</h3>
        <div className="h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={mockRocCurve} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3f" />
              <XAxis dataKey="fpr" type="number" stroke="#a0aec0" domain={[0, 1]} tick={{fill: '#a0aec0', fontSize: 12}} />
              <YAxis dataKey="tpr" type="number" stroke="#a0aec0" domain={[0, 1]} tick={{fill: '#a0aec0', fontSize: 12}} />
              <RechartsTooltip 
                contentStyle={{ backgroundColor: '#151520', borderColor: '#2a2a3f', borderRadius: '8px', color: '#fff' }}
              />
              <Area type="monotone" dataKey="tpr" stroke="#ffb000" fill="#ffb000" fillOpacity={0.2} name="True Positive Rate" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

    </div>
  );
};

export default ModelPerformance;
