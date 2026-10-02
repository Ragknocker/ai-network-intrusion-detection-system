import React from 'react';
import { 
  Binary, ShieldAlert, CheckCircle, AlertTriangle, 
  ExternalLink, Info, ShieldCheck, Database 
} from 'lucide-react';

const ThreatIntelligencePanel = ({ scanResult }) => {
  if (!scanResult) return null;

  const feeds = scanResult.threatIntelFeeds || [];

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <Binary size={18} className="text-cyber-primary" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            Threat Intelligence Matches
          </h3>
        </div>

        {/* Real-world Disclaimer Tag */}
        <span className="text-[10px] text-gray-400 bg-black/40 px-2.5 py-1 rounded border border-cyber-border/60 flex items-center gap-1">
          <Info size={11} className="text-cyber-primary" />
          Cross-correlated with 8 Global Threat Repositories
        </span>
      </div>

      {/* Intelligence Feeds Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-cyber-border text-[10px] text-gray-400 uppercase tracking-wider bg-black/30">
              <th className="py-2.5 px-3">Intelligence Source</th>
              <th className="py-2.5 px-3">Indicator Type</th>
              <th className="py-2.5 px-3">Match Status</th>
              <th className="py-2.5 px-3">Category</th>
              <th className="py-2.5 px-3">Confidence</th>
              <th className="py-2.5 px-3">First Seen</th>
              <th className="py-2.5 px-3">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/40">
            {feeds.map((feed, idx) => {
              const isMatch = feed.matchStatus.includes('Match') || feed.matchStatus.includes('Listed');

              return (
                <tr key={idx} className="hover:bg-white/5 transition-colors">
                  <td className="py-2.5 px-3 font-semibold text-white flex items-center gap-2">
                    <Database size={13} className="text-cyber-primary" />
                    {feed.source}
                  </td>
                  <td className="py-2.5 px-3 text-gray-300 font-mono text-[11px]">
                    {feed.indicatorType}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      isMatch 
                        ? 'bg-red-500/20 text-red-400 border-red-500/40' 
                        : 'bg-green-500/15 text-green-400 border-green-500/30'
                    }`}>
                      {feed.matchStatus}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-gray-200">
                    <span className={`px-2 py-0.2 rounded text-[10px] ${
                      feed.category !== 'Clean' ? 'text-yellow-400 font-semibold' : 'text-gray-400'
                    }`}>
                      {feed.category}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-bold text-gray-300">
                    {feed.confidence}
                  </td>
                  <td className="py-2.5 px-3 text-gray-400 text-[11px]">
                    {feed.firstSeen}
                  </td>
                  <td className="py-2.5 px-3 text-gray-400 text-[11px]">
                    {feed.lastSeen}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="p-3 rounded-lg bg-black/40 border border-cyber-border/60 text-[11px] text-gray-400 flex items-center justify-between">
        <span>
          External Intelligence Gateway: All indicators queries are encrypted & authenticated.
        </span>
        <span className="text-[10px] text-green-400 font-semibold">
          Feed Status: Active
        </span>
      </div>
    </div>
  );
};

export default ThreatIntelligencePanel;
