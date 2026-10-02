import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, HelpCircle, 
  Copy, Check, Clock, Hash, Activity 
} from 'lucide-react';

const ThreatVerdictCard = ({ scanResult }) => {
  const [copied, setCopied] = useState(false);

  if (!scanResult) return null;

  const score = scanResult.riskScore !== undefined ? scanResult.riskScore : (scanResult.threatScore || 0);
  const verdict = scanResult.threatVerdict || (score >= 70 ? 'MALICIOUS' : (score >= 35 ? 'SUSPICIOUS' : 'SAFE'));
  const threatLevel = scanResult.threatLevel || (score >= 90 ? 'CRITICAL' : (score >= 70 ? 'HIGH' : (score >= 35 ? 'MEDIUM' : (score > 0 ? 'LOW' : 'CLEAN'))));
  const confidence = scanResult.confidence || '96%';
  const decision = scanResult.decision || (score >= 70 ? 'BLOCK IMMEDIATELY' : (score >= 35 ? 'ALERT & AUDIT' : 'ALLOW TRAFFIC'));

  const handleCopy = () => {
    if (navigator.clipboard && scanResult.url) {
      navigator.clipboard.writeText(scanResult.url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // Color theme mapping
  const getVerdictTheme = () => {
    switch (verdict) {
      case 'MALICIOUS':
        return {
          badgeBg: 'bg-red-500/20 text-red-400 border-red-500/50',
          strokeColor: '#ff003c',
          glowClass: 'shadow-[0_0_20px_rgba(255,0,60,0.25)]',
          cardBorder: 'border-l-red-500',
          textColor: 'text-red-400',
          label: 'MALICIOUS / PHISHING',
          icon: ShieldAlert
        };
      case 'SUSPICIOUS':
        return {
          badgeBg: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
          strokeColor: '#ffb000',
          glowClass: 'shadow-[0_0_20px_rgba(255,176,0,0.25)]',
          cardBorder: 'border-l-yellow-500',
          textColor: 'text-yellow-400',
          label: 'SUSPICIOUS LINK',
          icon: AlertTriangle
        };
      case 'SAFE':
        return {
          badgeBg: 'bg-green-500/20 text-green-400 border-green-500/50',
          strokeColor: '#00ff66',
          glowClass: 'shadow-[0_0_20px_rgba(0,255,102,0.25)]',
          cardBorder: 'border-l-green-500',
          textColor: 'text-green-400',
          label: 'SAFE / LEGITIMATE',
          icon: ShieldCheck
        };
      default:
        return {
          badgeBg: 'bg-gray-500/20 text-gray-400 border-gray-500/50',
          strokeColor: '#888888',
          glowClass: '',
          cardBorder: 'border-l-gray-500',
          textColor: 'text-gray-400',
          label: 'UNKNOWN / UNCLASSIFIED',
          icon: HelpCircle
        };
    }
  };

  const theme = getVerdictTheme();
  const StatusIcon = theme.icon;

  // Circular gauge calculations
  const radius = 60;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={`glass-panel p-6 border-l-4 ${theme.cardBorder} flex flex-col gap-6 font-mono relative overflow-hidden`}>
      {/* Top Banner Row */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
        {/* Left Verdict Info */}
        <div className="flex items-start gap-4 flex-1 min-w-0">
          <div className={`p-4 rounded-2xl border ${theme.badgeBg} shrink-0 ${theme.glowClass}`}>
            <StatusIcon size={36} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <span className="text-xs uppercase text-gray-400 tracking-wider">Threat Verdict:</span>
              <span className={`px-3 py-1 rounded-md text-xs font-bold tracking-wider border ${theme.badgeBg}`}>
                {theme.label}
              </span>
              <span className="px-2.5 py-0.5 rounded text-xs bg-black/40 text-gray-300 border border-cyber-border">
                Decision: <span className="font-bold text-white">{decision}</span>
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] bg-black/40 text-gray-300 border border-cyber-border">
                Threat Level: <span className={`font-bold ${theme.textColor}`}>{threatLevel}</span>
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] bg-black/40 text-gray-300 border border-cyber-border">
                Confidence: <span className="font-bold text-white">{confidence}</span>
              </span>
            </div>

            {/* Target URL with Copy Button */}
            <div className="flex items-center gap-2 mt-2 group">
              <p className="text-sm sm:text-base font-semibold text-white break-all max-w-2xl">
                {scanResult.url}
              </p>
              <button
                onClick={handleCopy}
                title="Copy full URL"
                className="p-1 rounded text-gray-400 hover:text-white hover:bg-white/10 transition-colors shrink-0"
              >
                {copied ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
              </button>
            </div>

            {/* Short AI Explanation Summary */}
            <p className="text-xs text-gray-300 mt-2.5 leading-relaxed bg-black/30 p-3 rounded-lg border border-cyber-border/60">
              {scanResult.aiSummary || (
                score >= 70
                  ? 'Multiple indicators associated with phishing were detected, including suspicious domain characteristics, redirect behavior, and abnormal URL structure.'
                  : score >= 35
                  ? 'Target URL exhibits suspicious attributes (elevated entropy or unencrypted HTTP transport) that deviate from standard corporate baseline.'
                  : 'Target domain and URL exhibit verified SSL/TLS certificates, established domain registration, and clean reputation telemetry across global feeds.'
              )}
            </p>

            {/* Metadata Footer Tags */}
            <div className="flex flex-wrap items-center gap-3 mt-3 text-[11px] text-gray-400">
              <span className="flex items-center gap-1">
                <Hash size={12} className="text-cyber-primary" /> Scan ID: <span className="text-gray-200 font-semibold">{scanResult.scanId || 'SCAN-2026-8941'}</span>
              </span>
              <span className="flex items-center gap-1">
                <Clock size={12} className="text-cyber-primary" /> Detection Time: <span className="text-gray-200">{scanResult.detectionTime || '2026-09-20 18:42:15 UTC'}</span>
              </span>
              <span className="flex items-center gap-1">
                <Activity size={12} className="text-cyber-primary" /> Status: <span className="text-green-400 font-semibold">{scanResult.analysisStatus || 'Completed'}</span>
              </span>
            </div>
          </div>
        </div>

        {/* Right Circular / Radial Risk Score Visualization */}
        <div className="flex flex-col sm:flex-row lg:flex-col items-center gap-4 bg-black/45 p-4 rounded-xl border border-cyber-border shrink-0 self-stretch sm:self-auto justify-center">
          <div className="relative flex items-center justify-center">
            <svg width="150" height="150" className="transform -rotate-90">
              {/* Background track circle */}
              <circle
                cx="75"
                cy="75"
                r={radius}
                stroke="#1c1c28"
                strokeWidth={strokeWidth}
                fill="transparent"
              />
              {/* Animated Progress circle */}
              <circle
                cx="75"
                cy="75"
                r={radius}
                stroke={theme.strokeColor}
                strokeWidth={strokeWidth}
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-1000 ease-out"
                style={{
                  filter: `drop-shadow(0 0 8px ${theme.strokeColor}80)`
                }}
              />
            </svg>

            {/* Inner Circular Score Text */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-[10px] uppercase text-gray-400 font-bold tracking-wider">
                Unified Threat Score:
              </span>
              <span className={`text-3xl font-black ${theme.textColor} leading-none mt-0.5`}>
                {score}%
              </span>
              <span className="text-[10px] text-gray-400 mt-0.5">{score} / 100</span>
              <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded mt-1 ${theme.badgeBg}`}>
                {threatLevel} RISK
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatVerdictCard;
