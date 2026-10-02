import React, { useState } from 'react';
import { 
  Bot, ShieldAlert, ShieldCheck, ChevronDown, ChevronUp, 
  ExternalLink, Info, CheckCircle2, AlertOctagon, HelpCircle 
} from 'lucide-react';

const AiThreatAnalysisCards = ({ scanResult }) => {
  const [expandedId, setExpandedId] = useState(null);

  if (!scanResult) return null;

  const categories = scanResult.aiThreatCategories || [];

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getStatusBadge = (categoryName, status) => {
    if (categoryName === 'Domain Reputation') {
      switch (status) {
        case 'Trusted':
          return 'bg-green-500/20 text-green-400 border-green-500/40';
        case 'Suspicious':
          return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
        case 'Malicious':
          return 'bg-red-500/20 text-red-400 border-red-500/40';
        default:
          return 'bg-gray-500/20 text-gray-400 border-gray-500/40';
      }
    }

    if (status === 'Detected') {
      return 'bg-red-500/20 text-red-400 border-red-500/40 font-bold';
    }
    return 'bg-green-500/20 text-green-400 border-green-500/40 font-semibold';
  };

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      <div className="flex items-center justify-between border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <Bot size={18} className="text-cyber-primary" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            AI Threat Analysis Engine
          </h3>
        </div>
        <span className="text-[11px] text-gray-400">
          8 Neural Threat Classifiers
        </span>
      </div>

      {/* 8 Categories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {categories.map((cat) => {
          const isExpanded = expandedId === cat.id;
          const isTriggered = cat.status === 'Detected' || cat.status === 'Malicious' || cat.status === 'Suspicious';

          return (
            <div
              key={cat.id}
              className={`p-4 rounded-xl border bg-black/40 flex flex-col justify-between transition-all duration-200 ${
                isTriggered 
                  ? 'border-red-500/40 shadow-[0_0_12px_rgba(255,0,60,0.1)]' 
                  : 'border-cyber-border/80 hover:border-gray-600'
              }`}
            >
              <div>
                {/* Header Row */}
                <div className="flex items-start justify-between gap-2 mb-2">
                  <h4 className="text-xs font-bold text-white tracking-wide">
                    {cat.category}
                  </h4>
                  <span className={`px-2 py-0.5 rounded text-[10px] uppercase border shrink-0 ${getStatusBadge(cat.category, cat.status)}`}>
                    {cat.status}
                  </span>
                </div>

                {/* Confidence Bar */}
                <div className="flex items-center justify-between text-[10px] text-gray-400 mb-2">
                  <span>Confidence:</span>
                  <span className="font-bold text-gray-200">{cat.confidence}</span>
                </div>

                {/* Explanation */}
                <p className="text-[11px] text-gray-300 leading-relaxed min-h-[38px]">
                  {cat.explanation}
                </p>
              </div>

              {/* Technical Details Expand Section */}
              <div className="mt-3 pt-2.5 border-t border-cyber-border/40">
                <button
                  type="button"
                  onClick={() => toggleExpand(cat.id)}
                  className="w-full flex items-center justify-between text-[10px] text-cyber-primary hover:underline font-semibold"
                >
                  <span>Technical details</span>
                  {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                </button>

                {isExpanded && (
                  <div className="mt-2 p-2 rounded bg-black/60 border border-cyber-border/70 text-[10px] text-gray-400 space-y-1 animate-in fade-in duration-150">
                    <p className="text-gray-300 font-semibold">{cat.technicalDetails}</p>
                    <p className="text-gray-500 text-[9px]">Classifier: Ensemble XGBoost + Static Rule Matrix</p>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default AiThreatAnalysisCards;
