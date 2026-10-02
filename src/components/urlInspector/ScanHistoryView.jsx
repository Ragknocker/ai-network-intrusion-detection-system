import React, { useState } from 'react';
import { 
  History, Search, Filter, Eye, RotateCw, 
  Download, BookmarkPlus, FileSearch, ChevronLeft, ChevronRight 
} from 'lucide-react';
import { getScanHistory, addToWatchlist } from '../../services/urlInspector';

const ScanHistoryView = ({ onViewScan, onRescan, onStartInvestigation }) => {
  const [historyItems, setHistoryItems] = useState(getScanHistory());
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  // Filter
  const filtered = historyItems.filter((item) => {
    const matchesSearch = item.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          item.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          item.scanId.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          item.threatType.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesVerdict = verdictFilter === 'ALL' || item.verdict === verdictFilter;
    
    let matchesRisk = true;
    if (riskFilter === 'HIGH') matchesRisk = item.riskScore >= 70;
    else if (riskFilter === 'MEDIUM') matchesRisk = item.riskScore >= 35 && item.riskScore < 70;
    else if (riskFilter === 'LOW') matchesRisk = item.riskScore < 35;

    return matchesSearch && matchesVerdict && matchesRisk;
  });

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filtered.length / itemsPerPage));
  const paginated = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const getVerdictBadge = (verdict) => {
    switch (verdict) {
      case 'MALICIOUS':
        return 'bg-red-500/20 text-red-400 border-red-500/50 font-bold';
      case 'SUSPICIOUS':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50 font-semibold';
      case 'SAFE':
        return 'bg-green-500/20 text-green-400 border-green-500/50 font-semibold';
      default:
        return 'bg-gray-500/20 text-gray-300 border-gray-500/50';
    }
  };

  const handleExportItem = (item) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(item, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute("href", dataStr);
    dl.setAttribute("download", `scan-record-${item.scanId}.json`);
    document.body.appendChild(dl);
    dl.click();
    dl.remove();
  };

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <History size={18} className="text-cyber-primary" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            URL Scan History & Audit Log
          </h3>
        </div>

        {/* Search & Filter Bar */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Search Box */}
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
              placeholder="Search scan ID, URL, domain..."
              className="pl-8 pr-3 py-1 bg-black/40 border border-cyber-border rounded-lg text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyber-primary"
            />
          </div>

          {/* Verdict Filter */}
          <div className="flex items-center gap-1 p-0.5 rounded-lg bg-black/40 border border-cyber-border">
            <span className="text-[10px] text-gray-400 px-1">Verdict:</span>
            {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'SAFE'].map((v) => (
              <button
                key={v}
                type="button"
                onClick={() => { setVerdictFilter(v); setCurrentPage(1); }}
                className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold transition-all ${
                  verdictFilter === v
                    ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/50'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                {v}
              </button>
            ))}
          </div>

          {/* Risk Level Filter */}
          <div className="flex items-center gap-1 p-0.5 rounded-lg bg-black/40 border border-cyber-border">
            <span className="text-[10px] text-gray-400 px-1">Risk:</span>
            {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((r) => (
              <button
                key={r}
                type="button"
                onClick={() => { setRiskFilter(r); setCurrentPage(1); }}
                className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold transition-all ${
                  riskFilter === r
                    ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/50'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-cyber-border text-[10px] text-gray-400 uppercase tracking-wider bg-black/30">
              <th className="py-2.5 px-3">Scan ID</th>
              <th className="py-2.5 px-3">Target URL</th>
              <th className="py-2.5 px-3">Domain</th>
              <th className="py-2.5 px-3">Verdict</th>
              <th className="py-2.5 px-3">Risk Score</th>
              <th className="py-2.5 px-3">Threat Type</th>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Analyst</th>
              <th className="py-2.5 px-3">Status</th>
              <th className="py-2.5 px-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/40">
            {paginated.length > 0 ? (
              paginated.map((item) => (
                <tr key={item.scanId} className="hover:bg-white/5 transition-colors">
                  <td className="py-2.5 px-3 font-semibold text-cyber-primary font-mono text-[11px]">
                    {item.scanId}
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-white max-w-[220px] truncate" title={item.url}>
                    {item.url}
                  </td>
                  <td className="py-2.5 px-3 text-gray-300">
                    {item.domain}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase border ${getVerdictBadge(item.verdict)}`}>
                      {item.verdict}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-bold text-white">
                    <span className={item.riskScore >= 70 ? 'text-red-400' : (item.riskScore >= 35 ? 'text-yellow-400' : 'text-green-400')}>
                      {item.riskScore}%
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-gray-300 text-[11px]">
                    {item.threatType}
                  </td>
                  <td className="py-2.5 px-3 text-gray-400 text-[11px]">
                    {item.timestamp}
                  </td>
                  <td className="py-2.5 px-3 text-gray-300 text-[11px]">
                    {item.analyst}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-black/40 text-gray-300 border border-cyber-border">
                      {item.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        type="button"
                        onClick={() => onViewScan && onViewScan(item)}
                        title="View Full Scan Result"
                        className="p-1 text-gray-400 hover:text-cyber-primary transition-colors"
                      >
                        <Eye size={14} />
                      </button>
                      <button
                        type="button"
                        onClick={() => onRescan && onRescan(item.url)}
                        title="Rescan URL"
                        className="p-1 text-gray-400 hover:text-white transition-colors"
                      >
                        <RotateCw size={14} />
                      </button>
                      <button
                        type="button"
                        onClick={() => handleExportItem(item)}
                        title="Export JSON"
                        className="p-1 text-gray-400 hover:text-white transition-colors"
                      >
                        <Download size={14} />
                      </button>
                      <button
                        type="button"
                        onClick={() => addToWatchlist(item.domain)}
                        title="Add Domain to Watchlist"
                        className="p-1 text-gray-400 hover:text-yellow-400 transition-colors"
                      >
                        <BookmarkPlus size={14} />
                      </button>
                      <button
                        type="button"
                        onClick={() => onStartInvestigation && onStartInvestigation(item)}
                        title="Create Investigation"
                        className="p-1 text-gray-400 hover:text-cyber-secondary transition-colors"
                      >
                        <FileSearch size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="10" className="py-6 text-center text-gray-500">
                  No scan history records match current search or filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex items-center justify-between pt-2 border-t border-cyber-border/60 text-xs text-gray-400">
        <span>
          Showing {paginated.length} of {filtered.length} total scans
        </span>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
            className="p-1 rounded bg-black/40 border border-cyber-border disabled:opacity-30"
          >
            <ChevronLeft size={14} />
          </button>
          <span>Page {currentPage} of {totalPages}</span>
          <button
            type="button"
            onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
            disabled={currentPage === totalPages}
            className="p-1 rounded bg-black/40 border border-cyber-border disabled:opacity-30"
          >
            <ChevronRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanHistoryView;
