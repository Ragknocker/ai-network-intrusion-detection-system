import React, { useState } from 'react';
import { Table, ArrowUpDown, Filter, Search } from 'lucide-react';

const UrlFeatureTable = ({ scanResult }) => {
  const [sortField, setSortField] = useState('feature');
  const [sortOrder, setSortOrder] = useState('asc');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  if (!scanResult) return null;

  const rawFeatures = scanResult.featureAnalysisTable || [];

  // Filter
  const filteredFeatures = rawFeatures.filter((item) => {
    const matchesRisk = riskFilter === 'ALL' || item.risk.toUpperCase() === riskFilter;
    const matchesSearch = item.feature.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          item.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          (item.rationale && item.rationale.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesRisk && matchesSearch;
  });

  // Sort
  const sortedFeatures = [...filteredFeatures].sort((a, b) => {
    let valA = a[sortField] || '';
    let valB = b[sortField] || '';

    if (sortField === 'risk') {
      const riskWeights = { Critical: 4, High: 3, Medium: 2, Low: 1 };
      valA = riskWeights[a.risk] || 0;
      valB = riskWeights[b.risk] || 0;
      return sortOrder === 'asc' ? valA - valB : valB - valA;
    }

    return sortOrder === 'asc' 
      ? String(valA).localeCompare(String(valB)) 
      : String(valB).localeCompare(String(valA));
  });

  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const getRiskBadge = (risk) => {
    switch (risk) {
      case 'Critical':
        return 'bg-red-500/20 text-red-400 border-red-500/50 font-bold';
      case 'High':
        return 'bg-red-500/20 text-red-400 border-red-500/40 font-semibold';
      case 'Medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      default:
        return 'bg-green-500/20 text-green-400 border-green-500/40';
    }
  };

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <Table size={18} className="text-cyber-primary" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            Technical URL Feature Analysis
          </h3>
        </div>

        {/* Filter and Search Toolbar */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Search Box */}
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter features..."
              className="pl-8 pr-3 py-1 bg-black/40 border border-cyber-border rounded-lg text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyber-primary"
            />
          </div>

          {/* Risk Level Filter */}
          <div className="flex items-center gap-1 p-0.5 rounded-lg bg-black/40 border border-cyber-border">
            <span className="text-[10px] text-gray-400 px-1 flex items-center gap-1">
              <Filter size={10} /> Risk:
            </span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((risk) => (
              <button
                key={risk}
                type="button"
                onClick={() => setRiskFilter(risk)}
                className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold transition-all ${
                  riskFilter === risk
                    ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/50'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                {risk}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Features Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-cyber-border text-[10px] text-gray-400 uppercase tracking-wider bg-black/30">
              <th 
                className="py-2.5 px-3 cursor-pointer hover:text-white select-none"
                onClick={() => handleSort('feature')}
              >
                <div className="flex items-center gap-1">
                  <span>Feature</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th 
                className="py-2.5 px-3 cursor-pointer hover:text-white select-none"
                onClick={() => handleSort('value')}
              >
                <div className="flex items-center gap-1">
                  <span>Extracted Value</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th 
                className="py-2.5 px-3 cursor-pointer hover:text-white select-none"
                onClick={() => handleSort('risk')}
              >
                <div className="flex items-center gap-1">
                  <span>Risk Level</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th className="py-2.5 px-3">SOC Technical Rationale</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/40">
            {sortedFeatures.map((item, idx) => (
              <tr key={idx} className="hover:bg-white/5 transition-colors">
                <td className="py-2.5 px-3 font-semibold text-white">
                  {item.feature}
                </td>
                <td className="py-2.5 px-3 font-mono text-gray-200">
                  {item.value}
                </td>
                <td className="py-2.5 px-3">
                  <span className={`px-2 py-0.5 rounded text-[10px] uppercase border ${getRiskBadge(item.risk)}`}>
                    {item.risk}
                  </span>
                </td>
                <td className="py-2.5 px-3 text-gray-400 text-[11px] leading-relaxed">
                  {item.rationale}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default UrlFeatureTable;
