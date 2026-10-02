import React, { useState, useEffect, useRef } from 'react';
import { 
  Globe, Shield, Activity, BarChart3, 
  Sparkles, Layers, Search, ShieldAlert, ShieldCheck, AlertTriangle,
  Clipboard, Trash2, AlertCircle 
} from 'lucide-react';
import { 
  analyzeUrlAndFunction, 
  URL_PRESETS 
} from '../services/urlInspector';

// Subcomponents
import ScanProgressBar, { SCAN_STAGES } from './urlInspector/ScanProgressBar';
import ThreatVerdictCard from './urlInspector/ThreatVerdictCard';
import UrlBreakdownPanel from './urlInspector/UrlBreakdownPanel';
import AiThreatAnalysisCards from './urlInspector/AiThreatAnalysisCards';
import SecurityIndicatorsPanel from './urlInspector/SecurityIndicatorsPanel';
import RedirectChainVisualizer from './urlInspector/RedirectChainVisualizer';
import UrlFeatureTable from './urlInspector/UrlFeatureTable';
import AiExplanationCard from './urlInspector/AiExplanationCard';
import EvidencePanel from './urlInspector/EvidencePanel';
import ActionsToolbar from './urlInspector/ActionsToolbar';
import DashboardStatisticsView from './urlInspector/DashboardStatisticsView';

const UrlInspector = ({ inspectTarget, onClearTarget, globalQuery }) => {
  const [activeTab, setActiveTab] = useState('inspector'); // 'inspector' | 'statistics'
  const [urlInput, setUrlInput] = useState('');
  const [activePreset, setActivePreset] = useState(null);
  const scanMode = 'Deep Analysis';
  const [pasteFeedback, setPasteFeedback] = useState(false);
  const inputRef = useRef(null);
  
  // Scanning state
  const [isScanning, setIsScanning] = useState(false);
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [isScanFailed, setIsScanFailed] = useState(false);
  const [failureReason, setFailureReason] = useState(null);
  const [scanResult, setScanResult] = useState(null);

  // Sync external inspect target (e.g. from Live Traffic Monitor or Alert panel)
  useEffect(() => {
    if (inspectTarget) {
      const targetVal = (inspectTarget.value || inspectTarget.url || '').trim();
      if (targetVal) {
        setUrlInput(targetVal);
        setActivePreset(null);
        handleExecuteScan(targetVal);
      }
    }
  }, [inspectTarget]);

  // Sync global query if submitted
  useEffect(() => {
    if (globalQuery) {
      setUrlInput(globalQuery);
      setActivePreset(null);
      handleExecuteScan(globalQuery);
    }
  }, [globalQuery]);

  const handleExecuteScan = (overrideUrl) => {
    const rawVal = inputRef.current ? inputRef.current.value : '';
    const target = (typeof overrideUrl === 'string' && overrideUrl.trim() ? overrideUrl : (urlInput || rawVal)).trim();
    if (!target) return;

    setIsScanning(false);
    setIsScanFailed(false);
    const result = analyzeUrlAndFunction(
      target, 
      'GET', 
      '', 
      '', 
      '', 
      'HTTP/1.1', 
      scanMode
    );
    setScanResult(result);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      handleExecuteScan();
    }
  };

  const handleInputChange = (e) => {
    const val = e.target.value;
    setUrlInput(val);
    setActivePreset(null);
  };

  const handleClear = () => {
    setUrlInput('');
    setScanResult(null);
    setActivePreset(null);
    setIsScanning(false);
    setIsScanFailed(false);
    if (inputRef.current) inputRef.current.value = '';
    if (onClearTarget) onClearTarget();
  };

  const handleSelectPreset = (preset) => {
    setUrlInput(preset.url);
    setActivePreset(preset.name);
    if (inputRef.current) inputRef.current.value = preset.url;
    handleExecuteScan(preset.url);
  };

  const handlePaste = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          setUrlInput(text.trim());
          if (inputRef.current) inputRef.current.value = text.trim();
          setActivePreset(null);
          setPasteFeedback(true);
          setTimeout(() => setPasteFeedback(false), 1500);
        }
      }
    } catch {
      // Fallback
    }
  };

  return (
    <div className="flex-1 flex flex-col gap-6 overflow-y-auto pr-1 pb-10 font-mono">
      {/* 1. Main Page Title & Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-5 sm:p-6 border-b border-cyber-border">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <Globe className="text-cyber-primary" size={26} />
            <h1 className="text-xl sm:text-2xl font-black tracking-wider text-white">
              URL Inspector
            </h1>
            <span className="text-xs px-2.5 py-0.5 rounded font-mono font-bold bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/40 shadow-[0_0_8px_rgba(0,240,255,0.2)]">
              URL Threat Inspector
            </span>
            <span className="text-[11px] px-2 py-0.5 rounded font-bold bg-black/40 text-gray-300 border border-cyber-border">
              ACCURATE REAL-TIME ENGINE
            </span>
          </div>

          <p className="text-xs text-gray-300 mt-1.5 leading-relaxed max-w-3xl">
            Analyze URLs for phishing, malware, suspicious redirects, domain reputation, and other web-based threats.
          </p>
        </div>

        {/* View Switcher Tabs & Engine Active Indicator */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 p-1 rounded-xl bg-black/50 border border-cyber-border/80">
            <button
              type="button"
              onClick={() => setActiveTab('inspector')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 ${
                activeTab === 'inspector'
                  ? 'bg-cyber-primary text-black shadow-[0_0_12px_rgba(0,240,255,0.3)]'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Globe size={13} /> Inspector
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('statistics')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 ${
                activeTab === 'statistics'
                  ? 'bg-cyber-primary text-black shadow-[0_0_12px_rgba(0,240,255,0.3)]'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <BarChart3 size={13} /> SOC Statistics
            </button>
          </div>

          {/* Engine Active Ping Badge */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-black/40 border border-cyber-border text-xs">
            <span className="w-2 h-2 rounded-full bg-cyber-primary animate-pulse" />
            <span className="text-gray-300">Engine Active</span>
          </div>
        </div>
      </div>

      {/* Main Tab: Inspector View */}
      {activeTab === 'inspector' && (
        <>
          {/* 2. Prominent URL Input Card */}
          <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <label htmlFor="url-input" className="text-xs text-gray-400 uppercase tracking-wider flex items-center justify-between w-full sm:w-auto gap-3">
                <span className="flex items-center gap-1.5">
                  <Search size={14} className="text-cyber-primary" /> Target URL to Inspect:
                </span>
                {activePreset && (
                  <span className="text-[11px] text-cyber-secondary">
                    Sample Preset: {activePreset}
                  </span>
                )}
              </label>
            </div>

            {/* Main Input Field Row */}
            <div className="flex flex-col md:flex-row gap-2.5">
              <div className="relative flex-1">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-gray-500">
                  <Globe size={18} />
                </div>
                <input
                  id="url-input"
                  ref={inputRef}
                  type="text"
                  value={urlInput}
                  onChange={handleInputChange}
                  onKeyDown={handleKeyDown}
                  placeholder="Enter URL to inspect (e.g., https://example.com/path or http://secure-paypal-login.xyz)"
                  className="w-full pl-10 pr-24 py-3.5 bg-black/50 border border-cyber-border rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyber-primary focus:ring-1 focus:ring-cyber-primary transition-colors"
                />

                {/* Inline Action Buttons inside input */}
                <div className="absolute inset-y-0 right-0 pr-2 flex items-center gap-1">
                  <button
                    type="button"
                    onClick={handlePaste}
                    title="Paste from clipboard"
                    className="p-1.5 rounded-md text-gray-400 hover:text-white hover:bg-white/10 transition-colors text-xs flex items-center gap-1"
                  >
                    <Clipboard size={14} />
                    <span className="hidden sm:inline text-[11px]">
                      {pasteFeedback ? 'Pasted!' : 'Paste'}
                    </span>
                  </button>

                  {urlInput && (
                    <button
                      type="button"
                      onClick={handleClear}
                      title="Clear input"
                      className="p-1.5 rounded-md text-gray-400 hover:text-red-400 hover:bg-white/10 transition-colors"
                    >
                      <Trash2 size={15} />
                    </button>
                  )}
                </div>
              </div>

              <button
                type="button"
                onClick={() => handleExecuteScan()}
                className="px-6 py-3.5 bg-cyber-primary hover:bg-cyber-primary/90 text-black font-semibold text-sm rounded-lg transition-all flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,240,255,0.3)] shrink-0"
              >
                <Search size={16} />
                Inspect URL
              </button>
            </div>

            {/* Privacy Notice */}
            <div className="flex items-center gap-2 text-[11px] text-gray-400 bg-black/30 px-3 py-1.5 rounded-lg border border-cyber-border/40">
              <AlertCircle size={13} className="text-cyber-primary shrink-0" />
              <span>
                URLs are analyzed securely. Do not submit URLs containing sensitive credentials or private tokens.
              </span>
            </div>

            {/* Attack Sample Presets */}
            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-cyber-border/40">
              <span className="text-xs text-gray-400 mr-1 flex items-center gap-1">
                <Sparkles size={12} className="text-cyber-warning" /> Test with Examples:
              </span>
              {URL_PRESETS.map((preset) => {
                const isSelected = activePreset === preset.name;
                return (
                  <button
                    key={preset.name}
                    type="button"
                    onClick={() => handleSelectPreset(preset)}
                    className={`px-3 py-1 rounded text-xs transition-all border flex items-center gap-1.5 ${
                      isSelected
                        ? 'bg-cyber-primary/20 border-cyber-primary text-cyber-primary'
                        : 'bg-black/30 border-cyber-border text-gray-300 hover:border-gray-500'
                    }`}
                  >
                    <span>{preset.name}</span>
                    <span className={`text-[10px] px-1 rounded font-bold ${
                      preset.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                      preset.severity === 'High' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {preset.severity}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* 3. Scanning Progress Bar */}
          {isScanning && (
            <ScanProgressBar
              currentStageIndex={currentStageIndex}
              isFailed={isScanFailed}
              failureReason={failureReason}
              onRetry={() => handleExecuteScan()}
            />
          )}

          {/* 4. Complete Inspection Results Dashboard */}
          {!isScanning && scanResult ? (
            <div className="flex flex-col gap-6 animate-in fade-in duration-200">
              {/* Actions Toolbar */}
              <ActionsToolbar
                scanResult={scanResult}
                onRescan={() => handleExecuteScan()}
              />

              {/* Large Threat Verdict Card */}
              <ThreatVerdictCard
                scanResult={scanResult}
              />

              {/* URL Breakdown Decomposition Panel */}
              <UrlBreakdownPanel scanResult={scanResult} />

              {/* AI Threat Analysis 8 Cards Grid */}
              <AiThreatAnalysisCards scanResult={scanResult} />

              {/* Explainable AI: Why was this classified this way? */}
              <AiExplanationCard scanResult={scanResult} />

              {/* Security Indicators (WHOIS, DNS, SSL/TLS, IP & ASN) */}
              <SecurityIndicatorsPanel scanResult={scanResult} />

              {/* Redirect Chain Visualization */}
              <RedirectChainVisualizer scanResult={scanResult} />

              {/* Technical URL Feature Analysis Table */}
              <UrlFeatureTable scanResult={scanResult} />

              {/* Forensic Evidence Bundle */}
              <EvidencePanel scanResult={scanResult} />
            </div>
          ) : (
            !isScanning && (
              <div className="glass-panel p-12 text-center flex flex-col items-center justify-center gap-3">
                <Globe size={48} className="text-cyber-primary/40 animate-pulse" />
                <h3 className="text-base font-bold text-white tracking-wide">
                  Enter a URL to Inspect
                </h3>
                <p className="text-xs text-gray-400 max-w-lg leading-relaxed">
                  Type or paste any target URL, domain, or IP address into the input card above and click <span className="text-cyber-primary font-bold">Inspect URL</span> to execute multi-engine heuristic, machine learning, and threat intelligence analysis.
                </p>
              </div>
            )
          )}
        </>
      )}

      {/* Tab 2: SOC Statistics View */}
      {activeTab === 'statistics' && (
        <DashboardStatisticsView />
      )}
    </div>
  );
};

export default UrlInspector;
