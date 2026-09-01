import React, { useState, useEffect } from 'react';
import { 
  Globe, ShieldAlert, ShieldCheck, AlertTriangle, 
  Download, Cpu, Activity, Terminal, Server, 
  Search, Lock, X, FileCode, Share2, RefreshCw, Send
} from 'lucide-react';
import { 
  analyzeUrlAndFunction, 
  recordAnalystFeedback, 
  getFeedbackHistory, 
  triggerModelRetraining, 
  calculateModelDrift 
} from '../services/urlInspector';

const UrlInspector = ({ inspectTarget, onClearTarget }) => {
  const [urlInput, setUrlInput] = useState('');
  const [method, setMethod] = useState('GET');
  const [sourceProtocol, setSourceProtocol] = useState('HTTP/1.1');
  const [payload, setPayload] = useState('');
  const [funcName, setFuncName] = useState('');
  const [processName, setProcessName] = useState('');
  const [activeTab, setActiveTab] = useState('overview');
  const [scannedCount, setScannedCount] = useState(0);
  const [selectedApiEndpoint, setSelectedApiEndpoint] = useState('/scan/url');

  // Analyst Feedback & Auto-Block State
  const [feedbackVerdict, setFeedbackVerdict] = useState('Confirmed Malicious');
  const [feedbackComments, setFeedbackComments] = useState('');
  const [feedbackList, setFeedbackList] = useState(() => getFeedbackHistory());
  const [retrainResult, setRetrainResult] = useState(null);
  const [driftData, setDriftData] = useState(() => calculateModelDrift());
  const [autoBlockEnabled, setAutoBlockEnabled] = useState(true);
  const [humanApprovalState, setHumanApprovalState] = useState('APPROVED');

  const [scanResult, setScanResult] = useState(() => 
    analyzeUrlAndFunction('', 'GET', '', '', '', 'HTTP/1.1')
  );

  useEffect(() => {
    if (inspectTarget) {
      const targetVal = inspectTarget.value || '';
      const targetPayload = inspectTarget.payload || '';
      if (targetVal) setUrlInput(targetVal);
      if (targetPayload) setPayload(targetPayload);
      const res = analyzeUrlAndFunction(
        targetVal,
        method,
        targetPayload,
        funcName,
        processName,
        sourceProtocol
      );
      setScanResult(res);
      setScannedCount(prev => prev + 1);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inspectTarget]);

  const handleRunAnalysis = (overrideUrl, overrideMethod, overridePayload, overrideFunc, overrideProc, overrideProto) => {
    const targetUrl = overrideUrl !== undefined ? overrideUrl : urlInput;
    const targetMethod = overrideMethod !== undefined ? overrideMethod : method;
    const targetPayload = overridePayload !== undefined ? overridePayload : payload;
    const targetFunc = overrideFunc !== undefined ? overrideFunc : funcName;
    const targetProc = overrideProc !== undefined ? overrideProc : processName;
    const targetProto = overrideProto !== undefined ? overrideProto : sourceProtocol;

    const res = analyzeUrlAndFunction(targetUrl, targetMethod, targetPayload, targetFunc, targetProc, targetProto);
    setScanResult(res);
    setScannedCount(prev => prev + 1);
  };

  const handleClearForm = () => {
    setUrlInput('');
    setPayload('');
    setFuncName('');
    setProcessName('');
    setMethod('GET');
    setSourceProtocol('HTTP/1.1');
    setScanResult(analyzeUrlAndFunction('', 'GET', '', '', '', 'HTTP/1.1'));
    if (onClearTarget) onClearTarget();
  };

  const handleSubmitFeedback = (e) => {
    e.preventDefault();
    if (!scanResult.url) return;
    recordAnalystFeedback(scanResult.url, scanResult.threatScore, feedbackVerdict, feedbackComments);
    setFeedbackList([...getFeedbackHistory()]);
    setDriftData(calculateModelDrift());
    setFeedbackComments('');
  };

  const handleTriggerRetrain = () => {
    const res = triggerModelRetraining();
    setRetrainResult(res);
  };

  const handleDownloadReport = () => {
    const reportData = JSON.stringify({
      timestamp: new Date().toISOString(),
      urlMetadata: {
        url: scanResult.url || 'No URL Specified',
        domain: scanResult.domain || 'N/A',
        entropy: scanResult.entropy,
        features: scanResult.features
      },
      domainIntelligence: scanResult.domainIntel,
      multiEngineAnalysis: {
        threatScore: scanResult.threatScore,
        decision: scanResult.decision,
        status: scanResult.status,
        disposition: scanResult.disposition,
        recommendation: scanResult.recommendation,
        reasons: scanResult.reasons,
        engineBreakdown: scanResult.engineBreakdown
      },
      stage1PreFilter: scanResult.stage1PreFilter,
      siemEventPayload: scanResult.siemEventPayload,
      blacklistMatches: scanResult.blacklistMatches,
      httpAttacks: scanResult.httpAttacks,
      functionEvents: scanResult.functionEvents,
      threatIntel: scanResult.threatIntel
    }, null, 2);

    const blob = new Blob([reportData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `url_security_audit_${scanResult.domain || 'scan'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const pipelineSteps = [
    { num: 1, label: 'Collection' },
    { num: 2, label: 'URL Extract' },
    { num: 3, label: 'Normalizer' },
    { num: 4, label: 'Stage1 Filter' },
    { num: 5, label: 'Lexical Feats' },
    { num: 6, label: 'Host Intel' },
    { num: 7, label: 'Stage2 XGB' },
    { num: 8, label: 'Char-CNN' },
    { num: 9, label: 'HTTP Attack' },
    { num: 10, label: 'Syscall Mon' },
    { num: 11, label: 'Reason Gen' },
    { num: 12, label: 'SIEM Alert' },
    { num: 13, label: 'Auto Block' },
    { num: 14, label: 'Feedback Store' }
  ];

  return (
    <div className="flex-1 flex flex-col gap-6 font-sans">
      {/* Header */}
      <div className="glass-panel p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-wide uppercase bg-clip-text text-transparent bg-gradient-to-r from-cyber-primary via-cyber-secondary to-cyber-success flex items-center gap-2">
            <Globe size={24} className="text-cyber-primary" /> URL & Function Inspector Dashboard
          </h2>
          <p className="text-xs text-gray-400 font-mono mt-1">
            End-to-End Extraction, Normalization, 2-Stage Pre-filter & AI ML Engine, Analyst Triage Reasons, and SIEM Auto-Block Integration.
          </p>
        </div>

        <div className="flex gap-2">
          {(urlInput || payload || funcName || inspectTarget) && (
            <button
              onClick={handleClearForm}
              className="px-3.5 py-2 bg-black/60 border border-cyber-border hover:border-cyber-primary text-gray-300 hover:text-white font-mono text-xs rounded transition-all flex items-center gap-1.5"
            >
              <X size={14} /> Clear Form
            </button>
          )}
          <button
            onClick={handleDownloadReport}
            className="px-3.5 py-2 bg-black/60 border border-cyber-border hover:border-cyber-primary text-gray-300 hover:text-white font-mono text-xs rounded transition-all flex items-center gap-2"
          >
            <Download size={14} /> Export Audit Report
          </button>
        </div>
      </div>

      {/* Top Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 flex items-center gap-3">
          <div className="p-2.5 rounded bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary">
            <Globe size={20} />
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400">Total Scanned URLs</span>
            <h4 className="text-lg font-bold font-mono text-white">{scannedCount}</h4>
          </div>
        </div>
        <div className="glass-panel p-4 flex items-center gap-3">
          <div className="p-2.5 rounded bg-cyber-success/10 border border-cyber-success/30 text-cyber-success">
            <ShieldCheck size={20} />
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400">Decision Tier</span>
            <h4 className={`text-sm font-bold font-mono ${
              scanResult.decision === 'ALLOW' ? 'text-cyber-success' :
              scanResult.decision === 'MONITOR' ? 'text-cyber-warning' : 'text-cyber-danger'
            }`}>{scanResult.decision}</h4>
          </div>
        </div>
        <div className="glass-panel p-4 flex items-center gap-3">
          <div className="p-2.5 rounded bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger">
            <ShieldAlert size={20} />
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400">Threat Score</span>
            <h4 className="text-lg font-bold font-mono text-white">{scanResult.threatScore}%</h4>
          </div>
        </div>
        <div className="glass-panel p-4 flex items-center gap-3">
          <div className="p-2.5 rounded bg-cyber-warning/10 border border-cyber-warning/30 text-cyber-warning">
            <Lock size={20} />
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400">HTTP & API Attacks</span>
            <h4 className="text-lg font-bold font-mono text-white">{scanResult.httpAttacks.length} Flagged</h4>
          </div>
        </div>
      </div>

      {/* 14-Step Detection Pipeline Visualizer */}
      <div className="glass-panel p-4 overflow-x-auto">
        <span className="text-xs font-mono font-bold text-gray-400 uppercase tracking-wider block mb-3">
          14-Stage Detection Pipeline Status:
        </span>
        <div className="flex items-center gap-1.5 min-w-[700px]">
          {pipelineSteps.map((s) => (
            <div key={s.num} className="flex-1 flex flex-col items-center">
              <div className={`w-full py-1 text-center rounded text-[10px] font-mono font-bold border transition-colors ${
                scanResult.url
                  ? 'border-cyber-primary bg-cyber-primary/20 text-white'
                  : 'border-cyber-border bg-black/40 text-gray-500'
              }`}>
                P{s.num}
              </div>
              <span className="text-[9px] font-mono text-gray-400 mt-1 text-center truncate max-w-[60px]">{s.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Input Controls Bar */}
      <div className="glass-panel p-5 flex flex-col gap-4">
        <div className="flex flex-col md:flex-row gap-3 items-center">
          <div className="flex-1 flex gap-2 w-full">
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="bg-black/70 border border-cyber-border rounded px-3 py-2 text-xs font-mono text-cyber-primary focus:outline-none focus:border-cyber-primary"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>

            <select
              value={sourceProtocol}
              onChange={(e) => setSourceProtocol(e.target.value)}
              className="bg-black/70 border border-cyber-border rounded px-3 py-2 text-xs font-mono text-cyber-secondary focus:outline-none focus:border-cyber-secondary"
            >
              <option value="HTTP/1.1">HTTP/1.1</option>
              <option value="HTTP/2">HTTP/2</option>
              <option value="TLS SNI">TLS SNI (HTTPS)</option>
              <option value="DNS Query">DNS Query</option>
              <option value="Payload Regex">Payload Regex Scan</option>
            </select>

            <div className="flex-1 relative flex items-center">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Enter URL, domain, percent-encoded string, or IP (e.g. http://%73%65%63%75%72%65-paypal%2ecom/login#fragment)..."
                className="w-full bg-black/70 border border-cyber-border rounded px-4 py-2 pr-8 text-xs font-mono text-white focus:outline-none focus:border-cyber-primary"
              />
              {urlInput && (
                <button
                  onClick={() => setUrlInput('')}
                  className="absolute right-2 text-gray-400 hover:text-white"
                  title="Clear input"
                >
                  <X size={14} />
                </button>
              )}
            </div>
          </div>

          <button
            onClick={() => handleRunAnalysis()}
            className="w-full md:w-auto px-5 py-2 bg-cyber-primary/20 border border-cyber-primary hover:bg-cyber-primary hover:text-black text-white font-mono text-xs rounded transition-all font-bold flex items-center justify-center gap-2"
          >
            <Search size={14} /> Analyze URL & Function
          </button>
        </div>

        {/* Optional Payload / Function inputs */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            type="text"
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder="HTTP Request Payload / Query string..."
            className="bg-black/60 border border-cyber-border/60 rounded px-3 py-1.5 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyber-primary"
          />
          <input
            type="text"
            value={funcName}
            onChange={(e) => setFuncName(e.target.value)}
            placeholder="API Function (VirtualAlloc, CreateProcess)..."
            className="bg-black/60 border border-cyber-border/60 rounded px-3 py-1.5 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyber-primary"
          />
          <input
            type="text"
            value={processName}
            onChange={(e) => setProcessName(e.target.value)}
            placeholder="Process Name (cmd.exe, powershell.exe)..."
            className="bg-black/60 border border-cyber-border/60 rounded px-3 py-1.5 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyber-primary"
          />
        </div>
      </div>

      {/* Main Multi-Engine Tabbed View */}
      <div className="flex flex-col gap-4 flex-1">
        {/* Navigation Tabs */}
        <div className="flex border-b border-cyber-border/60 gap-2 overflow-x-auto pb-1 font-mono text-xs">
          {[
            { id: 'overview', label: 'Engine Overview', icon: Activity },
            { id: 'extraction', label: 'Extraction & Normalizer', icon: FileCode },
            { id: 'url', label: 'Feature Matrix & Intel', icon: Globe },
            { id: 'ai', label: '2-Stage AI Classifier', icon: Cpu },
            { id: 'siem', label: 'SIEM & Auto-Block', icon: Share2 },
            { id: 'feedback', label: 'Feedback & Drift Store', icon: RefreshCw },
            { id: 'http', label: 'HTTP Attack Inspector', icon: ShieldAlert },
            { id: 'function', label: 'Function & API Monitor', icon: Terminal },
            { id: 'api', label: 'API Explorer', icon: Server }
          ].map(tab => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-2 rounded-t flex items-center gap-1.5 transition-colors whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'bg-cyber-primary/20 text-cyber-primary border-b-2 border-cyber-primary font-bold'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-black/40'
                }`}
              >
                <Icon size={14} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* TAB 1: ENGINE OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="flex flex-col gap-4 flex-1">
            {/* Verdict Banner */}
            <div className={`glass-panel p-5 border-2 flex flex-col gap-2 relative overflow-hidden ${
              scanResult.threatScore > 60
                ? 'border-cyber-danger bg-cyber-danger/10 text-white shadow-lg shadow-cyber-danger/20' 
                : scanResult.threatScore > 30
                ? 'border-cyber-warning bg-cyber-warning/10 text-white shadow-lg shadow-cyber-warning/20'
                : 'border-cyber-success bg-cyber-success/10 text-white shadow-lg shadow-cyber-success/20'
            }`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono uppercase tracking-widest text-gray-400">URL & Session Safety Verdict</span>
                <span className="text-xs font-mono text-gray-400">Unified Risk Score: <strong className="text-white font-bold">{scanResult.threatScore}%</strong></span>
              </div>

              <div className="flex items-center gap-3 mt-1">
                {scanResult.threatScore > 60 ? (
                  <ShieldAlert size={32} className="text-cyber-danger animate-pulse shrink-0" />
                ) : scanResult.threatScore > 30 ? (
                  <AlertTriangle size={32} className="text-cyber-warning shrink-0" />
                ) : (
                  <ShieldCheck size={32} className="text-cyber-success shrink-0" />
                )}

                <div className="flex flex-col">
                  <h3 className={`text-base font-extrabold font-mono tracking-wide ${
                    scanResult.threatScore > 60 ? 'text-cyber-danger animate-pulse' :
                    scanResult.threatScore > 30 ? 'text-cyber-warning' : 'text-cyber-success'
                  }`}>
                    {scanResult.disposition}
                  </h3>
                  <span className="text-xs font-mono text-gray-300">
                    Decision Action: <strong className="uppercase underline">{scanResult.decision}</strong>
                  </span>
                </div>
              </div>

              <div className="mt-2 bg-black/60 p-2.5 rounded border border-white/10 text-xs font-mono text-gray-300 leading-relaxed">
                {scanResult.recommendation}
              </div>
            </div>

            {/* Analyst Triage Reason Field */}
            <div className="glass-panel p-5 flex flex-col gap-3 font-mono text-xs">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                <AlertTriangle size={14} className="text-cyber-warning" /> Analyst Triage Reasons & Contributing Factors
              </h4>
              <div className="space-y-1.5">
                {scanResult.reasons && scanResult.reasons.length > 0 ? (
                  scanResult.reasons.map((reason, idx) => (
                    <div key={idx} className="bg-black/70 p-2.5 rounded border border-cyber-border flex items-start gap-2 text-gray-300">
                      <span className="text-cyber-warning font-bold shrink-0">►</span>
                      <span>{reason}</span>
                    </div>
                  ))
                ) : (
                  <div className="bg-black/50 p-3 rounded border border-cyber-border text-gray-400">
                    No threat anomalies detected.
                  </div>
                )}
              </div>
            </div>

            {/* Score Breakdown Bars */}
            <div className="glass-panel p-5 flex flex-col gap-3">
              <h4 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider flex items-center justify-between">
                <span>Multi-Engine Score Breakdown</span>
                <span className="text-cyber-primary">Weighted Score: {scanResult.threatScore}%</span>
              </h4>

              <div className="space-y-2 font-mono text-xs">
                {[
                  { label: 'Blacklist & Signature Check (40%)', score: scanResult.engineBreakdown.blacklistScore, color: 'bg-red-500' },
                  { label: 'AI URL Classifier (30%)', score: scanResult.engineBreakdown.aiUrlScore, color: 'bg-blue-500' },
                  { label: 'Function & Behavioral Monitor (35%)', score: scanResult.engineBreakdown.functionBehaviorScore, color: 'bg-purple-500' },
                  { label: 'Threat Intel Feeds (25%)', score: scanResult.engineBreakdown.threatIntelScore, color: 'bg-amber-500' },
                  { label: 'HTTP Attack Payload Inspector (20%)', score: scanResult.engineBreakdown.httpAttackScore, color: 'bg-emerald-500' }
                ].map((engine, idx) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-gray-400">{engine.label}</span>
                      <span className="text-white font-bold">{engine.score}%</span>
                    </div>
                    <div className="w-full bg-black/60 h-2 rounded overflow-hidden border border-cyber-border">
                      <div className={`h-full ${engine.color}`} style={{ width: `${engine.score}%` }}></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: EXTRACTION & NORMALIZER WORKBENCH */}
        {activeTab === 'extraction' && (
          <div className="glass-panel p-5 flex-1 flex flex-col gap-4 font-mono text-xs">
            <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <FileCode size={14} className="text-cyber-primary" /> Extraction Layer & URL Normalization Workbench
            </h4>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">SOURCE PROTOCOL</span>
                <span className="text-cyber-secondary font-bold text-xs">{sourceProtocol}</span>
              </div>
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">PERCENT DECODED</span>
                <span className={scanResult.features.normMeta?.percentDecoded ? 'text-cyber-warning font-bold text-xs' : 'text-cyber-success font-bold text-xs'}>
                  {scanResult.features.normMeta?.percentDecoded ? 'YES (DECODED)' : 'CLEAN'}
                </span>
              </div>
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">PUNYCODE HOMOGLYPH</span>
                <span className={scanResult.features.normMeta?.isPunycode ? 'text-cyber-danger font-bold text-xs' : 'text-cyber-success font-bold text-xs'}>
                  {scanResult.features.normMeta?.isPunycode ? 'PUNYCODE (IDN)' : 'STANDARD ASCII'}
                </span>
              </div>
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">DEDUPLICATION WINDOW</span>
                <span className={scanResult.features.normMeta?.isDuplicate ? 'text-cyber-warning font-bold text-xs' : 'text-cyber-success font-bold text-xs'}>
                  {scanResult.features.normMeta?.isDuplicate ? 'DUPLICATE (CACHED)' : 'UNIQUE EVENT'}
                </span>
              </div>
            </div>

            <div className="bg-black/80 p-4 rounded border border-cyber-border space-y-3">
              <div>
                <span className="text-gray-400 block text-[10px]">RAW INPUT URL:</span>
                <code className="text-amber-300 block text-xs bg-black p-2 rounded border border-gray-800 break-all">
                  {urlInput || 'http://example.com'}
                </code>
              </div>

              <div>
                <span className="text-cyber-success block text-[10px]">NORMALIZED URL (CANONICAL):</span>
                <code className="text-emerald-300 block text-xs bg-black p-2 rounded border border-emerald-900 break-all">
                  {scanResult.features.normMeta?.normalizedUrl || scanResult.url || 'http://example.com'}
                </code>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: FEATURE MATRIX & INTEL */}
        {activeTab === 'url' && (
          <div className="glass-panel p-5 flex-1 flex flex-col gap-4 font-mono text-xs">
            <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <Globe size={14} className="text-cyber-primary" /> Multi-Category Feature Matrix & Domain Intelligence
            </h4>

            {/* Lexical Features */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">URL ENTROPY</span>
                <span className={scanResult.entropy > 4.5 ? 'text-cyber-danger font-bold text-sm' : 'text-cyber-success font-bold text-sm'}>
                  {scanResult.entropy} / 8.0
                </span>
              </div>
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">HTTPS USAGE</span>
                <span className={scanResult.features.hasHttps ? 'text-cyber-success font-bold text-sm' : 'text-cyber-danger font-bold text-sm'}>
                  {scanResult.features.hasHttps ? 'ENCRYPTED' : 'PLAIN HTTP'}
                </span>
              </div>
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">IP AS HOST</span>
                <span className={scanResult.features.containsIp ? 'text-cyber-danger font-bold text-sm' : 'text-cyber-success font-bold text-sm'}>
                  {scanResult.features.containsIp ? 'DETECTED' : 'DOMAIN NAME'}
                </span>
              </div>
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">SUSPICIOUS KEYWORDS</span>
                <span className="text-white font-bold text-sm">{scanResult.features.suspiciousKeywords.length} Found</span>
              </div>
            </div>

            {/* Host Intelligence */}
            <div className="bg-black/60 p-4 rounded border border-cyber-border space-y-2">
              <span className="text-cyber-secondary font-bold block text-xs">Host & Domain Intelligence:</span>
              <div className="grid grid-cols-2 gap-2 text-[11px] text-gray-300">
                <div>Domain: <strong className="text-white">{scanResult.domainIntel.domain || 'N/A'}</strong></div>
                <div>Domain Age: <strong className={scanResult.domainIntel.domainAgeDays < 10 ? 'text-cyber-danger' : 'text-white'}>{scanResult.domainIntel.domainAgeDays} days</strong></div>
                <div>Registrar: <strong className="text-white">{scanResult.domainIntel.registrar}</strong></div>
                <div>Country: <strong className="text-white">{scanResult.domainIntel.country}</strong></div>
                <div>ASN: <strong className="text-white">{scanResult.domainIntel.asn}</strong></div>
                <div>DNS TTL: <strong className="text-white">{scanResult.domainIntel.dnsTtl}s</strong></div>
                <div>A Record Count: <strong className="text-white">{scanResult.domainIntel.aRecordCount}</strong></div>
                <div>SSL Certificate: <strong className={scanResult.domainIntel.sslValid ? 'text-cyber-success' : 'text-cyber-danger'}>{scanResult.domainIntel.sslValid ? 'VALID' : 'INVALID / MISSING'}</strong></div>
              </div>
            </div>

            {/* Contextual Network Features */}
            <div className="bg-black/60 p-4 rounded border border-cyber-border space-y-2">
              <span className="text-cyber-primary font-bold block text-xs">Contextual Network & Beaconing Features:</span>
              <div className="grid grid-cols-3 gap-3 text-[11px]">
                <div className="bg-black p-2 rounded border border-gray-800">
                  <span className="text-gray-500 block text-[9px]">INTERNAL HOST FREQUENCY</span>
                  <span className="text-white font-bold">{scanResult.features.networkContext?.domainFreqInternalHosts || 1} hosts</span>
                </div>
                <div className="bg-black p-2 rounded border border-gray-800">
                  <span className="text-gray-500 block text-[9px]">FIRST SEEN DOMAIN</span>
                  <span className={scanResult.features.networkContext?.isFirstSeenDomain ? 'text-cyber-warning font-bold' : 'text-cyber-success font-bold'}>
                    {scanResult.features.networkContext?.isFirstSeenDomain ? 'YES (NEW DOMAIN)' : 'HISTORICAL DOMAIN'}
                  </span>
                </div>
                <div className="bg-black p-2 rounded border border-gray-800">
                  <span className="text-gray-500 block text-[9px]">BEACONING PERIODICITY</span>
                  <span className={scanResult.features.networkContext?.beaconingPeriodicityScore > 0.5 ? 'text-cyber-danger font-bold' : 'text-cyber-success font-bold'}>
                    {scanResult.features.networkContext?.beaconingPeriodicityScore || 0.05} / 1.00
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: 2-STAGE AI CLASSIFIER */}
        {activeTab === 'ai' && (
          <div className="glass-panel p-5 flex-1 flex flex-col gap-4 font-mono text-xs">
            <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <Cpu size={14} className="text-cyber-primary" /> Two-Stage Classification Engine (Pre-Filter & XGBoost ML)
            </h4>

            {/* Stage 1 Pre-Filter Banner */}
            <div className="bg-black/70 p-4 rounded border border-cyber-border flex justify-between items-center">
              <div>
                <span className="text-gray-400 block text-[10px]">STAGE 1 FAST RULE PRE-FILTER STATUS:</span>
                <span className={`font-bold text-sm ${
                  scanResult.stage1PreFilter?.stage1Verdict === 'ALLOW' ? 'text-cyber-success' :
                  scanResult.stage1PreFilter?.stage1Verdict === 'BLOCK' ? 'text-cyber-danger' : 'text-cyber-warning'
                }`}>
                  {scanResult.stage1PreFilter?.stage1Verdict || 'PASS_TO_ML'}
                </span>
              </div>
              <span className="px-3 py-1 rounded text-[10px] font-bold uppercase bg-black border border-cyber-border text-gray-300">
                {scanResult.stage1PreFilter?.isAllowlisted ? 'Allowlist Hit' : scanResult.stage1PreFilter?.isBlocklisted ? 'Blocklist Hit' : 'Evaluating ML Stage'}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">STAGE 2 AI MODEL:</span>
                <span className="text-cyber-secondary font-bold text-xs">{scanResult.aiDetails?.model || 'XGBoost URL Classifier v2.4'}</span>
              </div>
              <div className="bg-black/60 p-3 rounded border border-cyber-border">
                <span className="text-gray-500 block text-[10px]">CHAR-CNN ANOMALY SCORE:</span>
                <span className="text-cyber-danger font-bold text-xs">{scanResult.aiDetails?.charCnnAnomalyScore || 0.05} / 1.00</span>
              </div>
            </div>

            <div className="bg-black/60 p-4 rounded border border-cyber-border space-y-2">
              <span className="text-gray-400 font-bold block text-[11px]">Feature Weights & Importances:</span>
              <div className="space-y-1.5 text-[11px]">
                <div className="flex justify-between"><span>Domain Entropy ({scanResult.entropy})</span><span className="text-cyber-primary">Weight 0.32</span></div>
                <div className="flex justify-between"><span>Plain HTTP Flag</span><span className="text-cyber-primary">Weight 0.25</span></div>
                <div className="flex justify-between"><span>Suspicious Keywords ({scanResult.features.suspiciousKeywords.join(', ') || 'None'})</span><span className="text-cyber-primary">Weight 0.20</span></div>
                <div className="flex justify-between"><span>IP Address Host</span><span className="text-cyber-primary">Weight 0.15</span></div>
                <div className="flex justify-between"><span>Suspicious TLD</span><span className="text-cyber-primary">Weight 0.08</span></div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: SIEM & AUTO-BLOCK HOOK */}
        {activeTab === 'siem' && (
          <div className="glass-panel p-5 flex-1 flex flex-col gap-4 font-mono text-xs">
            <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <Share2 size={14} className="text-cyber-secondary" /> SIEM / Alerting Integration & Firewall Auto-Block Hook
            </h4>

            <div className="grid grid-cols-2 gap-3">
              <div className="bg-black/70 p-3 rounded border border-cyber-border flex justify-between items-center">
                <span>Auto-Block Engine Hook:</span>
                <button
                  onClick={() => setAutoBlockEnabled(!autoBlockEnabled)}
                  className={`px-3 py-1 rounded text-[10px] font-bold ${
                    autoBlockEnabled ? 'bg-cyber-success/20 border border-cyber-success text-cyber-success' : 'bg-black border border-gray-700 text-gray-400'
                  }`}
                >
                  {autoBlockEnabled ? 'ENABLED' : 'DISABLED'}
                </button>
              </div>

              <div className="bg-black/70 p-3 rounded border border-cyber-border flex justify-between items-center">
                <span>Human-in-the-Loop Approval:</span>
                <button
                  onClick={() => setHumanApprovalState(humanApprovalState === 'APPROVED' ? 'PENDING_APPROVAL' : 'APPROVED')}
                  className={`px-3 py-1 rounded text-[10px] font-bold ${
                    humanApprovalState === 'APPROVED' ? 'bg-cyber-primary/20 border border-cyber-primary text-cyber-primary' : 'bg-cyber-warning/20 border border-cyber-warning text-cyber-warning'
                  }`}
                >
                  {humanApprovalState}
                </button>
              </div>
            </div>

            <div className="bg-black/90 p-4 rounded border border-cyber-border space-y-2">
              <span className="text-cyber-secondary font-bold block text-xs">Splunk / Elastic / Kafka Event JSON Payload:</span>
              <pre className="text-emerald-400 text-[10px] overflow-x-auto p-3 bg-black rounded border border-gray-800">
{JSON.stringify(scanResult.siemEventPayload || {
  timestamp: new Date().toISOString(),
  srcIp: "192.168.1.105",
  dstIp: "104.21.32.8",
  url: scanResult.url,
  threatScore: scanResult.threatScore,
  verdict: scanResult.decision
}, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {/* TAB 6: ANALYST FEEDBACK & DRIFT STORE */}
        {activeTab === 'feedback' && (
          <div className="glass-panel p-5 flex-1 flex flex-col gap-4 font-mono text-xs">
            <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center justify-between">
              <span className="flex items-center gap-2"><RefreshCw size={14} className="text-cyber-primary" /> Analyst Feedback & Model Score Drift Store</span>
              <button
                onClick={handleTriggerRetrain}
                className="px-3 py-1 bg-cyber-primary/20 border border-cyber-primary hover:bg-cyber-primary hover:text-black text-white rounded font-bold text-[10px] transition-all flex items-center gap-1"
              >
                <RefreshCw size={12} /> Trigger Retraining Pipeline
              </button>
            </h4>

            {retrainResult && (
              <div className="bg-cyber-success/10 border border-cyber-success p-3 rounded text-cyber-success text-xs">
                {retrainResult.message} (Accuracy: {retrainResult.validationAccuracy})
              </div>
            )}

            {/* Model Drift Overview */}
            <div className="bg-black/70 p-4 rounded border border-cyber-border space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-gray-300 font-bold">Model Score Distribution Drift Monitor:</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  driftData.driftStatus === 'STABLE' ? 'bg-cyber-success/20 text-cyber-success' : 'bg-cyber-danger/20 text-cyber-danger'
                }`}>{driftData.driftStatus}</span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-[11px] text-gray-300">
                <div>Evaluated Samples: <strong className="text-white">{driftData.totalEvaluated}</strong></div>
                <div>Mean Risk Score: <strong className="text-white">{driftData.meanRiskScore}%</strong></div>
                <div>High Threat Ratio: <strong className="text-white">{(driftData.highThreatRatio * 100).toFixed(1)}%</strong></div>
              </div>
            </div>

            {/* Feedback Form */}
            <form onSubmit={handleSubmitFeedback} className="bg-black/60 p-4 rounded border border-cyber-border space-y-3">
              <span className="text-cyber-secondary font-bold block text-xs">Record Analyst Verdict & Feedback:</span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <select
                  value={feedbackVerdict}
                  onChange={(e) => setFeedbackVerdict(e.target.value)}
                  className="bg-black border border-cyber-border rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyber-primary"
                >
                  <option value="Confirmed Malicious">Confirmed Malicious</option>
                  <option value="False Positive">False Positive (Benign)</option>
                  <option value="Suspicious Vector">Suspicious Vector</option>
                </select>
                <input
                  type="text"
                  value={feedbackComments}
                  onChange={(e) => setFeedbackComments(e.target.value)}
                  placeholder="Analyst notes / context..."
                  className="bg-black border border-cyber-border rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyber-primary"
                />
              </div>
              <button
                type="submit"
                className="px-4 py-1.5 bg-cyber-secondary/20 border border-cyber-secondary text-white rounded hover:bg-cyber-secondary hover:text-black font-bold text-xs transition-all flex items-center gap-1.5"
              >
                <Send size={12} /> Submit Analyst Feedback
              </button>
            </form>

            {/* Feedback History List */}
            <div className="space-y-2">
              <span className="text-gray-400 font-bold block text-xs">Feedback History ({feedbackList.length}):</span>
              {feedbackList.length > 0 ? (
                feedbackList.map((item) => (
                  <div key={item.id} className="bg-black/80 p-2.5 rounded border border-cyber-border flex justify-between items-center text-[11px]">
                    <div>
                      <span className="text-white font-bold block">{item.url}</span>
                      <span className="text-gray-400 text-[10px]">{item.comments || 'No comments'} — {item.timestamp}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded font-bold ${
                      item.analystVerdict === 'Confirmed Malicious' ? 'bg-cyber-danger/20 text-cyber-danger' : 'bg-cyber-success/20 text-cyber-success'
                    }`}>{item.analystVerdict}</span>
                  </div>
                ))
              ) : (
                <div className="text-gray-500 bg-black/40 p-3 rounded text-center">No feedback submitted yet.</div>
              )}
            </div>
          </div>
        )}

        {/* TAB 7: HTTP ATTACK INSPECTOR */}
        {activeTab === 'http' && (
          <div className="glass-panel p-5 flex-1 flex flex-col gap-3 font-mono text-xs">
            <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert size={14} className="text-cyber-danger" /> HTTP Request Payload & Web Attack Detector
            </h4>

            {scanResult.httpAttacks.length > 0 ? (
              <div className="space-y-2">
                {scanResult.httpAttacks.map((att, idx) => (
                  <div key={idx} className="bg-black/80 p-3 rounded border border-cyber-danger/40 flex flex-col gap-1">
                    <div className="flex justify-between items-center">
                      <span className="text-cyber-danger font-bold">{att.category}</span>
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-cyber-danger/20 text-cyber-danger uppercase border border-cyber-danger/40">
                        {att.severity}
                      </span>
                    </div>
                    <code className="bg-black p-1.5 rounded text-red-300 text-[10px] mt-1">Matched Pattern: {att.pattern}</code>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs font-mono text-gray-400 bg-black/40 p-4 rounded text-center border border-cyber-border">
                Zero HTTP attack payloads (SQLi, XSS, SSRF, Traversal) detected.
              </div>
            )}
          </div>
        )}

        {/* TAB 8: FUNCTION & API MONITOR */}
        {activeTab === 'function' && (
          <div className="glass-panel p-5 flex-1 flex flex-col gap-3 font-mono text-xs">
            <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <Terminal size={14} className="text-cyber-primary" /> Win32 API & System Call Event Monitor
            </h4>

            <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
              {scanResult.functionEvents && scanResult.functionEvents.map((evt, idx) => (
                <div key={idx} className="bg-black/80 p-3 rounded border border-cyber-border flex flex-col gap-1">
                  <div className="flex justify-between items-center text-[10px]">
                    <span className="text-cyber-primary font-bold">{evt.api} ({evt.process})</span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                      evt.severity === 'Critical' ? 'bg-cyber-danger/20 text-cyber-danger' :
                      evt.severity === 'High' ? 'bg-cyber-warning/20 text-cyber-warning' : 'bg-cyber-success/20 text-cyber-success'
                    }`}>
                      {evt.severity}
                    </span>
                  </div>
                  <span className="text-gray-300 text-[11px]">{evt.action}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 9: API EXPLORER */}
        {activeTab === 'api' && (
          <div className="glass-panel p-5 flex-1 flex flex-col gap-3 font-mono text-xs">
            <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <Server size={14} className="text-cyber-secondary" /> FastAPI Endpoint Tester
            </h4>

            <div className="flex gap-2 mb-2 overflow-x-auto">
              {['/scan/url', '/url/extract', '/url/feedback', '/url/retrain', '/url/drift', '/threats/url'].map((ep) => (
                <button
                  key={ep}
                  onClick={() => setSelectedApiEndpoint(ep)}
                  className={`px-2.5 py-1.5 rounded text-[10px] border ${
                    selectedApiEndpoint === ep ? 'border-cyber-primary bg-cyber-primary/20 text-white font-bold' : 'border-cyber-border bg-black/40 text-gray-400'
                  }`}
                >
                  {ep}
                </button>
              ))}
            </div>

            <div className="bg-black/90 p-3 rounded border border-cyber-border text-gray-300 text-[11px] overflow-x-auto space-y-2">
              <div className="text-cyber-success font-bold">200 OK — {selectedApiEndpoint}</div>
              <pre className="text-gray-400 text-[10px]">
{JSON.stringify({
  endpoint: selectedApiEndpoint,
  status: "active",
  timestamp: new Date().toISOString(),
  sampleResponse: { url: scanResult.url || 'No URL Specified', threatScore: scanResult.threatScore, decision: scanResult.decision, reasons: scanResult.reasons }
}, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UrlInspector;
