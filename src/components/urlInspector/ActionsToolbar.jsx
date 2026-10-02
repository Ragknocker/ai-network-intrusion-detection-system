import React, { useState } from 'react';
import { 
  RotateCw, Download, BookmarkPlus, 
  ShieldAlert, AlertOctagon, Check 
} from 'lucide-react';
import { blockDomain, addToWatchlist } from '../../services/urlInspector';

const ActionsToolbar = ({ scanResult, onRescan }) => {
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [blockReason, setBlockReason] = useState('Critical Phishing & Malware Threat Delivery');
  const [actionMessage, setActionMessage] = useState(null);

  if (!scanResult) return null;

  const showNotification = (msg) => {
    setActionMessage(msg);
    setTimeout(() => setActionMessage(null), 3000);
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scanResult, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute("href", dataStr);
    dl.setAttribute("download", `url-scan-${scanResult.scanId || 'report'}.json`);
    document.body.appendChild(dl);
    dl.click();
    dl.remove();
    showNotification('Scan result JSON exported successfully.');
  };

  const handleAddToWatchlist = () => {
    addToWatchlist(scanResult.domain, `Watchlist flagged by Analyst for URL ${scanResult.url}`);
    showNotification(`Domain '${scanResult.domain}' added to SOC Watchlist.`);
  };

  const handleConfirmBlock = () => {
    blockDomain(scanResult.domain, blockReason);
    setShowBlockModal(false);
    showNotification(`Domain '${scanResult.domain}' successfully BLOCKED in perimeter firewall rules.`);
  };

  return (
    <>
      <div className="glass-panel p-4 flex flex-wrap items-center justify-between gap-3 font-mono">
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase text-gray-400 font-bold tracking-wider">
            Analyst Actions:
          </span>
          {actionMessage && (
            <span className="text-xs text-cyber-primary bg-cyber-primary/15 px-2 py-0.5 rounded border border-cyber-primary/40 animate-in fade-in flex items-center gap-1">
              <Check size={12} /> {actionMessage}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Rescan */}
          <button
            type="button"
            onClick={onRescan}
            className="px-3 py-1.5 rounded-lg bg-black/40 border border-cyber-border hover:border-cyber-primary text-gray-200 hover:text-white flex items-center gap-1.5 transition-colors"
          >
            <RotateCw size={13} />
            <span>Rescan</span>
          </button>

          {/* Export JSON */}
          <button
            type="button"
            onClick={handleExportJson}
            className="px-3 py-1.5 rounded-lg bg-black/40 border border-cyber-border hover:border-gray-400 text-gray-200 hover:text-white flex items-center gap-1.5 transition-colors"
          >
            <Download size={13} />
            <span>Export JSON</span>
          </button>

          {/* Add to Watchlist */}
          <button
            type="button"
            onClick={handleAddToWatchlist}
            className="px-3 py-1.5 rounded-lg bg-black/40 border border-cyber-border hover:border-cyber-warning text-yellow-400/90 hover:text-yellow-400 flex items-center gap-1.5 transition-colors"
          >
            <BookmarkPlus size={13} />
            <span>Add to Watchlist</span>
          </button>

          {/* Block Domain (Requires Confirmation) */}
          <button
            type="button"
            onClick={() => setShowBlockModal(true)}
            className="px-3 py-1.5 rounded-lg bg-red-500/15 border border-red-500/50 hover:bg-red-500/25 text-red-400 hover:text-red-300 font-bold flex items-center gap-1.5 transition-colors shadow-[0_0_10px_rgba(255,0,60,0.2)]"
          >
            <ShieldAlert size={13} />
            <span>Block Domain</span>
          </button>
        </div>
      </div>

      {/* Confirmation Modal for Domain Blocking */}
      {showBlockModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-cyber-panel border border-red-500/60 rounded-xl max-w-md w-full p-6 shadow-2xl font-mono relative animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center gap-2.5 text-red-400 mb-3">
              <AlertOctagon size={24} />
              <h3 className="text-base font-bold text-white tracking-wide">
                Confirm Domain Block
              </h3>
            </div>

            <p className="text-xs text-gray-300 leading-relaxed mb-3">
              Are you sure you want to enforce a network-wide perimeter block on domain:
            </p>

            <div className="p-2.5 rounded bg-black/60 border border-red-500/40 text-sm font-bold text-red-400 break-all mb-4">
              {scanResult.domain}
            </div>

            <div className="space-y-1.5 text-xs mb-4">
              <label className="text-[11px] text-gray-400 uppercase">Enforcement Reason:</label>
              <input
                type="text"
                value={blockReason}
                onChange={(e) => setBlockReason(e.target.value)}
                className="w-full px-3 py-2 bg-black/50 border border-cyber-border rounded-lg text-xs text-white focus:outline-none focus:border-red-500"
              />
            </div>

            <div className="p-2.5 rounded bg-yellow-500/10 border border-yellow-500/30 text-[11px] text-yellow-300 leading-normal mb-5">
              Warning: This action will immediately update active DNS firewalls and drop all inbound/outbound packets to this domain for all connected subnets.
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setShowBlockModal(false)}
                className="px-4 py-2 rounded-lg bg-black/40 border border-cyber-border text-xs text-gray-300 hover:text-white"
              >
                Cancel
              </button>

              <button
                type="button"
                onClick={handleConfirmBlock}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs shadow-[0_0_12px_rgba(255,0,60,0.4)]"
              >
                Confirm & Enforce Block
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default ActionsToolbar;
