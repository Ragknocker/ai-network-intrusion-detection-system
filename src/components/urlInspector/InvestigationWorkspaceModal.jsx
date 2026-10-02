import React, { useState } from 'react';
import { 
  X, FileSearch, Tag, Clock, Send, ShieldAlert, 
  User, Network, Globe 
} from 'lucide-react';
import { updateInvestigation } from '../../services/urlInspector';

const InvestigationWorkspaceModal = ({ investigation, onClose, onStatusChange }) => {
  const [currentStatus, setCurrentStatus] = useState(investigation?.status || 'Open');
  const [notesText, setNotesText] = useState('');
  const [allNotes, setAllNotes] = useState(
    investigation?.notes ? [investigation.notes] : []
  );
  const [tagInput, setTagInput] = useState('');
  const [tags, setTags] = useState(investigation?.tags || ['Phishing', 'Brand Spoofing']);
  const [evidenceList] = useState(investigation?.evidenceItems || []);

  if (!investigation) return null;

  const handleStatusChange = (newStatus) => {
    setCurrentStatus(newStatus);
    updateInvestigation(investigation.id, { status: newStatus });
    if (onStatusChange) onStatusChange(investigation.id, newStatus);
  };

  const handleAddNote = (e) => {
    e.preventDefault();
    if (!notesText.trim()) return;
    const newNote = `[${new Date().toLocaleTimeString()}] ${notesText.trim()}`;
    const updated = [newNote, ...allNotes];
    setAllNotes(updated);
    setNotesText('');
    updateInvestigation(investigation.id, { notes: updated.join('\n') });
  };

  const handleAddTag = (e) => {
    e.preventDefault();
    if (!tagInput.trim()) return;
    if (!tags.includes(tagInput.trim())) {
      const updatedTags = [...tags, tagInput.trim()];
      setTags(updatedTags);
      updateInvestigation(investigation.id, { tags: updatedTags });
    }
    setTagInput('');
  };

  const getStatusBadge = (st) => {
    switch (st) {
      case 'Confirmed Threat':
        return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'Investigating':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'False Positive':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      case 'Resolved':
        return 'bg-green-500/20 text-green-400 border-green-500/50';
      default:
        return 'bg-gray-500/20 text-gray-300 border-gray-500/50';
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-3 sm:p-6 font-mono overflow-y-auto">
      <div className="bg-cyber-panel border border-cyber-border rounded-2xl max-w-5xl w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-cyber-border flex items-center justify-between bg-black/40">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/40 shadow-[0_0_10px_rgba(0,240,255,0.2)]">
              <FileSearch size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-wider">
                  Investigation Workspace: {investigation.id}
                </h3>
                <span className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold border ${getStatusBadge(currentStatus)}`}>
                  {currentStatus}
                </span>
              </div>
              <p className="text-xs text-gray-400 truncate max-w-xl">
                Case Target: <span className="text-white font-semibold">{investigation.url}</span>
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-6">
          {/* Status Switcher & Tag Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-black/40 border border-cyber-border">
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase text-gray-400 font-bold">Triage Status:</span>
              <div className="flex flex-wrap gap-1">
                {['Open', 'Investigating', 'Confirmed Threat', 'False Positive', 'Resolved'].map((st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => handleStatusChange(st)}
                    className={`px-2.5 py-1 rounded text-xs font-bold transition-all border ${
                      currentStatus === st
                        ? `${getStatusBadge(st)} shadow-[0_0_8px_rgba(0,240,255,0.2)]`
                        : 'bg-black/30 border-cyber-border text-gray-400 hover:text-white'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            {/* Tags */}
            <form onSubmit={handleAddTag} className="flex items-center gap-1.5">
              <Tag size={13} className="text-cyber-primary" />
              <input
                type="text"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                placeholder="+ Add tag..."
                className="px-2 py-1 bg-black/50 border border-cyber-border rounded text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyber-primary"
              />
            </form>
          </div>

          {/* Tags List */}
          <div className="flex flex-wrap items-center gap-1.5 -mt-3">
            {tags.map((t, idx) => (
              <span key={idx} className="px-2 py-0.5 rounded bg-cyber-secondary/20 text-cyber-secondary border border-cyber-secondary/40 text-[11px] font-bold">
                #{t}
              </span>
            ))}
          </div>

          {/* 4 Multi-Column Information Section */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            {/* Column 1: Core URL & Domain Info */}
            <div className="p-4 rounded-xl bg-black/30 border border-cyber-border flex flex-col gap-2">
              <h4 className="text-xs font-bold text-cyber-primary uppercase tracking-wider flex items-center gap-1.5 pb-1 border-b border-cyber-border/50">
                <Globe size={13} /> URL & Host Summary
              </h4>
              <div className="space-y-1.5 text-gray-300">
                <div>
                  <span className="text-gray-500 block text-[10px]">Target URL:</span>
                  <span className="text-white font-semibold break-all">{investigation.url}</span>
                </div>
                <div>
                  <span className="text-gray-500 block text-[10px]">Primary Host / Domain:</span>
                  <span className="text-cyber-primary font-bold">{investigation.domain}</span>
                </div>
                <div>
                  <span className="text-gray-500 block text-[10px]">Lead Analyst:</span>
                  <span className="text-gray-200">{investigation.analyst || 'SecOps Tier-3 Analyst'}</span>
                </div>
              </div>
            </div>

            {/* Column 2: Correlated Threat Indicators & Related Entities */}
            <div className="p-4 rounded-xl bg-black/30 border border-cyber-border flex flex-col gap-2">
              <h4 className="text-xs font-bold text-yellow-400 uppercase tracking-wider flex items-center gap-1.5 pb-1 border-b border-cyber-border/50">
                <Network size={13} /> Correlated Infrastructure
              </h4>
              <div className="space-y-1.5 text-gray-300">
                <div>
                  <span className="text-gray-500 block text-[10px]">Related Domains (Co-hosted):</span>
                  <span className="text-gray-300">login-update-auth.xyz, portal-secure-01.xyz</span>
                </div>
                <div>
                  <span className="text-gray-500 block text-[10px]">Related IP Subnet:</span>
                  <span className="text-gray-300 font-mono">45.142.122.0/24 (High-Risk AS49210)</span>
                </div>
                <div>
                  <span className="text-gray-500 block text-[10px]">Related SIEM Alerts:</span>
                  <span className="text-red-400 font-bold">3 Associated Web Outbound Events</span>
                </div>
              </div>
            </div>

            {/* Column 3: Forensic Evidence Items */}
            <div className="p-4 rounded-xl bg-black/30 border border-cyber-border flex flex-col gap-2">
              <h4 className="text-xs font-bold text-red-400 uppercase tracking-wider flex items-center gap-1.5 pb-1 border-b border-cyber-border/50">
                <ShieldAlert size={13} /> Case Evidence Items
              </h4>
              <ul className="space-y-1.5 text-[11px] text-gray-300">
                {evidenceList.map((e, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1.5 shrink-0" />
                    <span>{e}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Timeline & Analyst Notes Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Timeline */}
            <div className="p-4 rounded-xl bg-black/30 border border-cyber-border flex flex-col gap-3">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 pb-1 border-b border-cyber-border/50">
                <Clock size={13} className="text-cyber-primary" /> Incident Timeline
              </h4>
              <div className="space-y-2 text-xs">
                {(investigation.timeline || []).map((t, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-gray-300">
                    <span className="text-[10px] text-cyber-primary font-mono whitespace-nowrap">{t.time}</span>
                    <span className="text-[11px] text-gray-300">• {t.action}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Analyst Notes Editor */}
            <div className="p-4 rounded-xl bg-black/30 border border-cyber-border flex flex-col gap-3">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 pb-1 border-b border-cyber-border/50">
                <User size={13} className="text-cyber-secondary" /> Analyst Triage Notes
              </h4>

              <form onSubmit={handleAddNote} className="flex gap-2">
                <input
                  type="text"
                  value={notesText}
                  onChange={(e) => setNotesText(e.target.value)}
                  placeholder="Type an investigation observation or action note..."
                  className="flex-1 px-3 py-1.5 bg-black/50 border border-cyber-border rounded-lg text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyber-primary"
                />
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-cyber-primary text-black font-bold text-xs rounded-lg flex items-center gap-1 hover:bg-cyber-primary/90"
                >
                  <Send size={12} /> Post
                </button>
              </form>

              <div className="space-y-1.5 max-h-36 overflow-y-auto text-xs text-gray-300">
                {allNotes.map((note, idx) => (
                  <div key={idx} className="p-2 rounded bg-black/50 border border-cyber-border/60 text-[11px] leading-relaxed">
                    {note}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-cyber-border bg-black/40 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 rounded-lg bg-cyber-primary text-black font-bold text-xs hover:bg-cyber-primary/90"
          >
            Done & Return to Inspector
          </button>
        </div>
      </div>
    </div>
  );
};

export default InvestigationWorkspaceModal;
