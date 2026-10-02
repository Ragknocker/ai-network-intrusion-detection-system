import React from 'react';
import { 
  BarChart3, Globe, ShieldAlert, AlertTriangle, ShieldCheck, 
  Activity, TrendingUp, FileSearch, Shield 
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, LineChart, Line, BarChart, Bar, 
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend 
} from 'recharts';

const DashboardStatisticsView = () => {
  // Key Metrics
  const stats = [
    { label: 'URLs Scanned', value: '1,428', icon: Globe, color: 'text-cyber-primary' },
    { label: 'Malicious URLs', value: '184', icon: ShieldAlert, color: 'text-red-400' },
    { label: 'Suspicious URLs', value: '92', icon: AlertTriangle, color: 'text-yellow-400' },
    { label: 'Safe URLs', value: '1,152', icon: ShieldCheck, color: 'text-green-400' },
    { label: 'Detection Rate', value: '98.4%', icon: Activity, color: 'text-cyber-primary' },
    { label: 'Avg Risk Score', value: '24 / 100', icon: TrendingUp, color: 'text-gray-200' },
    { label: 'New Threats (24h)', value: '18', icon: ShieldAlert, color: 'text-red-400' },
    { label: 'Active Investigations', value: '7', icon: FileSearch, color: 'text-cyber-secondary' }
  ];

  // Verdict Donut Data
  const verdictDistributionData = [
    { name: 'Safe', value: 1152, color: '#00ff66' },
    { name: 'Suspicious', value: 92, color: '#ffb000' },
    { name: 'Malicious', value: 184, color: '#ff003c' },
    { name: 'Unknown', value: 24, color: '#6b7280' }
  ];

  // Threat Trend (Line/Area Data)
  const trendData = [
    { time: '00:00', malicious: 4, suspicious: 2, safe: 48 },
    { time: '04:00', malicious: 6, suspicious: 3, safe: 32 },
    { time: '08:00', malicious: 18, suspicious: 8, safe: 140 },
    { time: '12:00', malicious: 32, suspicious: 14, safe: 210 },
    { time: '16:00', malicious: 26, suspicious: 11, safe: 195 },
    { time: '20:00', malicious: 14, suspicious: 6, safe: 112 }
  ];

  // Threat Categories Bar Data
  const categoryData = [
    { category: 'Phishing', count: 124, fill: '#ff003c' },
    { category: 'Malware', count: 68, fill: '#ff3366' },
    { category: 'Scam', count: 42, fill: '#ffb000' },
    { category: 'Botnet C2', count: 35, fill: '#7000ff' },
    { category: 'Suspicious', count: 92, fill: '#00f0ff' },
    { category: 'Other Web', count: 16, fill: '#9ca3af' }
  ];

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="p-2.5 rounded-lg bg-black/90 border border-cyber-border text-xs font-mono text-white shadow-xl">
          <p className="font-bold text-cyber-primary mb-1">{label || payload[0]?.name}</p>
          {payload.map((p, i) => (
            <p key={i} style={{ color: p.color || p.fill || '#fff' }}>
              {p.name}: <span className="font-bold">{p.value}</span>
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="flex flex-col gap-6 font-mono">
      {/* 8 Metrics Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        {stats.map((s, idx) => {
          const Icon = s.icon;
          return (
            <div key={idx} className="glass-panel p-3.5 flex flex-col justify-between gap-2 border border-cyber-border/80">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-400 uppercase tracking-wider">{s.label}</span>
                <Icon size={14} className={s.color} />
              </div>
              <span className={`text-lg font-black tracking-tight ${s.color}`}>
                {s.value}
              </span>
            </div>
          );
        })}
      </div>

      {/* 3 Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Chart 1: Donut Chart - Verdict Distribution */}
        <div className="lg:col-span-4 glass-panel p-5 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-cyber-border/70">
            <h4 className="text-xs font-bold uppercase tracking-wider text-white">
              URL Verdict Distribution
            </h4>
            <span className="text-[10px] text-gray-400">Total: 1,428 URLs</span>
          </div>

          <div className="h-64 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={verdictDistributionData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {verdictDistributionData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend 
                  verticalAlign="bottom" 
                  height={36} 
                  formatter={(val) => <span className="text-xs text-gray-300 font-mono">{val}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Threat Trend Line Chart */}
        <div className="lg:col-span-4 glass-panel p-5 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-cyber-border/70">
            <h4 className="text-xs font-bold uppercase tracking-wider text-white">
              24-Hour Threat Detection Trend
            </h4>
            <span className="text-[10px] text-cyber-primary">Live Influx</span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData}>
                <XAxis dataKey="time" stroke="#6b7280" fontSize={10} fontStyle="italic" />
                <YAxis stroke="#6b7280" fontSize={10} />
                <Tooltip content={<CustomTooltip />} />
                <Legend 
                  verticalAlign="bottom" 
                  height={36} 
                  formatter={(val) => <span className="text-xs text-gray-300 font-mono capitalize">{val}</span>}
                />
                <Line type="monotone" dataKey="malicious" stroke="#ff003c" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="suspicious" stroke="#ffb000" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="safe" stroke="#00ff66" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 3: Threat Categories Bar Chart */}
        <div className="lg:col-span-4 glass-panel p-5 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-cyber-border/70">
            <h4 className="text-xs font-bold uppercase tracking-wider text-white">
              Threat Classifications
            </h4>
            <span className="text-[10px] text-gray-400">By Vector</span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryData} layout="vertical">
                <XAxis type="number" stroke="#6b7280" fontSize={10} />
                <YAxis dataKey="category" type="category" stroke="#6b7280" fontSize={10} width={80} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {categoryData.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardStatisticsView;
