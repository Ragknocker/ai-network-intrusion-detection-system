import React from 'react';
import { 
  HelpCircle, Sparkles, AlertCircle, Eye, 
  ExternalLink, Cpu, ShieldQuestion, CheckCircle2, ShieldAlert, ShieldCheck 
} from 'lucide-react';

const AiExplanationCard = ({ scanResult }) => {
  if (!scanResult) return null;

  const explanation = scanResult.aiExplanation || {};
  const factors = explanation.contributingFactors || [];
  const reasons = scanResult.reasons || [];
  const classification = explanation.evidenceClassification || {
    observedEvidence: [],
    externalIntelligence: [],
    modelInference: [],
    unknownInformation: []
  };

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-5 font-mono">
      {/* Title Header */}
      <div className="flex items-center justify-between border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <Sparkles size={18} className="text-cyber-warning" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            Why was this URL classified this way?
          </h3>
        </div>
        <span className="text-[11px] text-gray-400">
          Explainable AI (XAI) Engine
        </span>
      </div>

      {/* AI Explainable Summary */}
      <div className="p-4 rounded-xl bg-black/40 border border-cyber-border/80 flex items-start gap-3">
        <AlertCircle size={18} className="text-cyber-primary shrink-0 mt-0.5" />
        <div className="flex-1 text-xs leading-relaxed text-gray-200">
          <p className="font-semibold text-white mb-1">Analyst Assessment Summary:</p>
          <p className="text-gray-300">
            {explanation.summary || scanResult.aiSummary || 'Target evaluation completed.'}
          </p>
        </div>
      </div>

      {/* Card: Identified Risk Factors */}
      <div className="p-4 rounded-xl bg-black/40 border border-cyber-border flex flex-col gap-3">
        <div className="flex items-center justify-between pb-2 border-b border-cyber-border/60">
          <div className="flex items-center gap-2">
            <ShieldAlert size={16} className={scanResult.threatScore >= 35 ? 'text-red-400' : 'text-green-400'} />
            <h4 className="text-xs font-bold uppercase tracking-wider text-white">
              Identified Risk Factors
            </h4>
          </div>
          <span className="text-[11px] text-gray-400 font-mono">
            {reasons.length} Factors
          </span>
        </div>

        <div className="flex flex-col gap-2">
          {reasons && reasons.length > 0 && scanResult.threatScore > 0 ? (
            reasons.map((reason, idx) => (
              <div 
                key={idx} 
                className="flex items-start gap-2.5 p-2.5 rounded bg-black/50 border border-cyber-border/50 text-xs text-gray-200"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1.5 shrink-0" />
                <span>{reason}</span>
              </div>
            ))
          ) : (
            <div className="flex items-center gap-2 p-3 rounded bg-green-500/10 border border-green-500/30 text-xs text-green-400">
              <ShieldCheck size={16} />
              <span>Clean URL structure matching normal benign web traffic profile.</span>
            </div>
          )}
        </div>
      </div>

      {/* Contributing Factors with Weight Bars */}
      <div>
        <h4 className="text-xs uppercase text-gray-400 tracking-wider font-bold mb-3 flex items-center gap-1.5">
          <span>Contributing Risk Factors & Weights:</span>
        </h4>

        <div className="space-y-3">
          {factors.map((item, idx) => (
            <div key={idx} className="p-3 rounded-lg bg-black/30 border border-cyber-border/60">
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="font-semibold text-white truncate mr-2">
                  {item.factor}
                </span>
                <div className="flex items-center gap-2 shrink-0">
                  <span className={`px-1.5 py-0.2 rounded text-[10px] uppercase font-bold ${
                    item.impact === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                    item.impact === 'High' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                    item.impact === 'Safe' ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                    'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                  }`}>
                    {item.impact}
                  </span>
                  <span className="text-gray-300 font-bold">{item.contribution}%</span>
                </div>
              </div>

              {/* Visual weight bar */}
              <div className="w-full h-1.5 bg-black/70 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-500 ${
                    item.impact === 'Critical' ? 'bg-red-500 shadow-[0_0_8px_rgba(255,0,60,0.5)]' :
                    item.impact === 'High' ? 'bg-yellow-500' :
                    item.impact === 'Safe' ? 'bg-green-500' : 'bg-cyber-primary'
                  }`}
                  style={{ width: `${Math.min(100, item.contribution * 2.2)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Distinction of Evidence Types (Observed, External, Inference, Unknown) */}
      <div className="pt-3 border-t border-cyber-border/70">
        <h4 className="text-xs uppercase text-gray-400 tracking-wider font-bold mb-3">
          Evidence Classification (Distinguished Telemetry):
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          {/* Observed Evidence */}
          <div className="p-3 rounded-lg bg-black/40 border border-cyber-border/80 flex flex-col gap-2">
            <div className="flex items-center gap-1.5 text-cyber-primary font-bold text-[11px] pb-1 border-b border-cyber-border/50">
              <Eye size={13} /> Observed Evidence
            </div>
            <ul className="space-y-1 text-[11px] text-gray-300 list-disc list-inside">
              {(classification.observedEvidence || []).map((e, i) => (
                <li key={i} className="truncate" title={e}>{e}</li>
              ))}
            </ul>
          </div>

          {/* External Intelligence */}
          <div className="p-3 rounded-lg bg-black/40 border border-cyber-border/80 flex flex-col gap-2">
            <div className="flex items-center gap-1.5 text-cyber-secondary font-bold text-[11px] pb-1 border-b border-cyber-border/50">
              <ExternalLink size={13} /> External Intelligence
            </div>
            <ul className="space-y-1 text-[11px] text-gray-300 list-disc list-inside">
              {(classification.externalIntelligence || []).map((e, i) => (
                <li key={i} className="truncate" title={e}>{e}</li>
              ))}
            </ul>
          </div>

          {/* Model Inference */}
          <div className="p-3 rounded-lg bg-black/40 border border-cyber-border/80 flex flex-col gap-2">
            <div className="flex items-center gap-1.5 text-yellow-400 font-bold text-[11px] pb-1 border-b border-cyber-border/50">
              <Cpu size={13} /> Model Inference
            </div>
            <ul className="space-y-1 text-[11px] text-gray-300 list-disc list-inside">
              {(classification.modelInference || []).map((e, i) => (
                <li key={i} className="truncate" title={e}>{e}</li>
              ))}
            </ul>
          </div>

          {/* Unknown Information */}
          <div className="p-3 rounded-lg bg-black/40 border border-cyber-border/80 flex flex-col gap-2">
            <div className="flex items-center gap-1.5 text-gray-400 font-bold text-[11px] pb-1 border-b border-cyber-border/50">
              <ShieldQuestion size={13} /> Unknown Information
            </div>
            <ul className="space-y-1 text-[11px] text-gray-400 list-disc list-inside">
              {(classification.unknownInformation || []).map((e, i) => (
                <li key={i} className="truncate" title={e}>{e}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AiExplanationCard;
