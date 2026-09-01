import React, { useState, useEffect, useRef } from 'react';
import { 
  UploadCloud, FileText, ShieldAlert, ShieldCheck, AlertTriangle, 
  Download, Copy, Cpu, Activity, 
  Terminal, Server, RefreshCw, Trash2, Lock
} from 'lucide-react';
import { 
  scanFileContent, computeFileHash,
  getQuarantinedFiles, quarantineFile, restoreQuarantinedFile, deleteQuarantinedFile 
} from '../services/fileScanner';

const FileThreatScanner = () => {
  const [fileContent, setFileContent] = useState('');
  const [fileHash, setFileHash] = useState('');
  const [scanResult, setScanResult] = useState(() => scanFileContent('No File Selected', '', 0));
  const [isDragging, setIsDragging] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [quarantineList, setQuarantineList] = useState([]);
  const [scannedHistoryCount, setScannedHistoryCount] = useState(0);
  const [selectedApiEndpoint, setSelectedApiEndpoint] = useState('/scan/file');
  const fileInputRef = useRef(null);

  useEffect(() => {
    if (fileContent) {
      let isMounted = true;
      computeFileHash(fileContent).then(h => {
        if (isMounted) setFileHash(h);
      });
      return () => { isMounted = false; };
    } else {
      setFileHash('');
    }
  }, [fileContent]);

  useEffect(() => {
    setQuarantineList(getQuarantinedFiles());
  }, [scanResult]);

  const processFile = (name, content, size) => {
    setFileContent(content);
    const res = scanFileContent(name, content, size);
    setScanResult(res);
    setScannedHistoryCount(prev => prev + 1);
    computeFileHash(content).then(h => setFileHash(h));
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      processFile(file.name, evt.target.result || '', file.size);
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = (e) => { e.preventDefault(); setIsDragging(false); };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const reader = new FileReader();
      reader.onload = (evt) => {
        processFile(file.name, evt.target.result || '', file.size);
      };
      reader.readAsText(file);
    }
  };

  const handleQuarantineAction = () => {
    quarantineFile(scanResult);
    setQuarantineList(getQuarantinedFiles());
  };

  const handleRestoreQuarantine = (id) => {
    restoreQuarantinedFile(id);
    setQuarantineList(getQuarantinedFiles());
  };

  const handleDeleteQuarantine = (id) => {
    deleteQuarantinedFile(id);
    setQuarantineList(getQuarantinedFiles());
  };

  const handleDownloadReport = () => {
    const reportData = JSON.stringify({
      timestamp: new Date().toISOString(),
      fileMetadata: {
        name: scanResult.fileName,
        sizeBytes: scanResult.fileSize,
        category: scanResult.fileType,
        extension: scanResult.fileExtension,
        sha256: fileHash
      },
      multiEngineThreatAnalysis: {
        unifiedThreatScore: scanResult.threatScore,
        decision: scanResult.decision,
        status: scanResult.status,
        disposition: scanResult.disposition,
        entropy: scanResult.entropy,
        recommendation: scanResult.recommendation,
        engineBreakdown: scanResult.engineBreakdown
      },
      yaraMatches: scanResult.yaraMatches,
      sandboxEvents: scanResult.sandboxEvents,
      threatIntel: scanResult.threatIntel,
      flaggedLines: scanResult.flaggedLines
    }, null, 2);

    const blob = new Blob([reportData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_audit_report_${scanResult.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const pipelineSteps = [
    { num: 1, label: 'Collection' },
    { num: 2, label: 'Hash Gen' },
    { num: 3, label: 'Signature' },
    { num: 4, label: 'YARA Scan' },
    { num: 5, label: 'Static Parse' },
    { num: 6, label: 'Feature Ext' },
    { num: 7, label: 'AI Model' },
    { num: 8, label: 'Reputation' },
    { num: 9, label: 'Sandbox' },
    { num: 10, label: 'Scoring' },
    { num: 11, label: 'Decision' },
    { num: 12, label: 'Quarantine' },
    { num: 13, label: 'Logging' },
    { num: 14, label: 'Dashboard' }
  ];

  return (
    <div className="flex-1 flex flex-col gap-6 font-sans">
      {/* Header & Actions */}
      <div className="glass-panel p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-wide uppercase bg-clip-text text-transparent bg-gradient-to-r from-cyber-primary via-cyber-secondary to-cyber-success flex items-center gap-2">
            <UploadCloud size={24} className="text-cyber-primary" /> File Upload Threat Scanner & Storage Safety Verdict
          </h2>
          <p className="text-xs text-gray-400 font-mono mt-1">
            Multi-engine AI detection suite (ClamAV, YARA, PE Parser, XGBoost AI, Sandbox Simulator & Threat Intel).
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleQuarantineAction}
            className="px-3.5 py-2 bg-cyber-danger/20 border border-cyber-danger/50 hover:bg-cyber-danger/40 text-cyber-danger hover:text-white font-mono text-xs rounded transition-all flex items-center gap-2"
          >
            <Lock size={14} /> Quarantine File
          </button>
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
            <FileText size={20} />
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400">Total Scanned</span>
            <h4 className="text-lg font-bold font-mono text-white">{scannedHistoryCount}</h4>
          </div>
        </div>
        <div className="glass-panel p-4 flex items-center gap-3">
          <div className="p-2.5 rounded bg-cyber-success/10 border border-cyber-success/30 text-cyber-success">
            <ShieldCheck size={20} />
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400">Decision</span>
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
            <span className="text-[10px] font-mono uppercase text-gray-400">Unified Score</span>
            <h4 className="text-lg font-bold font-mono text-white">{scanResult.threatScore}%</h4>
          </div>
        </div>
        <div className="glass-panel p-4 flex items-center gap-3">
          <div className="p-2.5 rounded bg-cyber-warning/10 border border-cyber-warning/30 text-cyber-warning">
            <Lock size={20} />
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400">Quarantined Vault</span>
            <h4 className="text-lg font-bold font-mono text-white">{quarantineList.length} Items</h4>
          </div>
        </div>
      </div>

      {/* 14-Step Pipeline Visualizer */}
      <div className="glass-panel p-4 overflow-x-auto">
        <span className="text-xs font-mono font-bold text-gray-400 uppercase tracking-wider block mb-3">
          14-Stage Detection Pipeline Status:
        </span>
        <div className="flex items-center gap-1.5 min-w-[700px]">
          {pipelineSteps.map((s) => (
            <div key={s.num} className="flex-1 flex flex-col items-center">
              <div className={`w-full py-1 text-center rounded text-[10px] font-mono font-bold border transition-colors ${
                scanResult.fileName !== 'No File Selected'
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

      {/* Main Grid: Upload (Left) vs Tabbed Multi-Engine Inspector (Right) */}
      <div className="grid grid-cols-12 gap-6 flex-1">
        {/* Left Column: Drag & Drop + Metadata */}
        <div className="col-span-12 lg:col-span-5 flex flex-col gap-6">
          {/* Drag & Drop */}
          <div 
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`glass-panel p-8 flex flex-col items-center justify-center text-center cursor-pointer border-2 border-dashed transition-all duration-300 relative group min-h-[220px] ${
              isDragging 
                ? 'border-cyber-primary bg-cyber-primary/10 shadow-lg shadow-cyber-primary/20 scale-[1.01]' 
                : 'border-cyber-border hover:border-cyber-primary/60 bg-black/40 hover:bg-black/60'
            }`}
          >
            <input type="file" ref={fileInputRef} onChange={handleFileUpload} className="hidden" />
            <div className="w-14 h-14 rounded-full bg-cyber-primary/10 border border-cyber-primary/40 flex items-center justify-center text-cyber-primary mb-4 group-hover:scale-110 transition-transform">
              <UploadCloud size={28} />
            </div>
            <h3 className="text-sm font-bold font-mono text-white mb-1">Drag & Drop file to scan for threats</h3>
            <p className="text-xs text-gray-400 font-mono mb-4">or <span className="text-cyber-primary underline font-bold">browse local file</span></p>
            <div className="flex flex-wrap justify-center gap-1.5">
              {['.EXE', '.DLL', '.PDF', '.DOC', '.ZIP', '.PHP', '.JS', '.PY', '.CSV'].map((ext, i) => (
                <span key={i} className="px-2 py-0.5 rounded bg-black/60 border border-cyber-border text-[10px] font-mono text-gray-400">
                  {ext}
                </span>
              ))}
            </div>
          </div>

          {/* File Metadata */}
          <div className="glass-panel p-5 flex flex-col gap-3 flex-1">
            <h4 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <FileText size={14} className="text-cyber-primary" /> Target File Metadata
            </h4>
            <div className="space-y-2 text-xs font-mono text-gray-300">
              <div className="flex justify-between py-1 border-b border-cyber-border/40">
                <span className="text-gray-500">File Name:</span>
                <span className="font-bold text-white truncate max-w-[200px]">{scanResult.fileName}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-cyber-border/40">
                <span className="text-gray-500">Category:</span>
                <span className="text-cyber-secondary font-bold">{scanResult.fileType}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-cyber-border/40">
                <span className="text-gray-500">Size & Lines:</span>
                <span>{scanResult.fileSize} bytes ({scanResult.lineCount} lines)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-cyber-border/40">
                <span className="text-gray-500">Shannon Entropy:</span>
                <span className={scanResult.entropy > 5.3 ? 'text-cyber-danger font-bold' : 'text-cyber-success font-bold'}>
                  {scanResult.entropy} / 8.0
                </span>
              </div>
            </div>
            <div className="mt-2 bg-black/70 p-2.5 rounded border border-cyber-border flex items-center justify-between font-mono text-[11px]">
              <div className="flex flex-col truncate pr-2">
                <span className="text-[10px] text-gray-500 uppercase">SHA-256 Hash:</span>
                <span className="text-gray-300 truncate">{fileHash}</span>
              </div>
              <button 
                onClick={() => navigator.clipboard.writeText(fileHash)}
                className="p-1 hover:text-cyber-primary text-gray-400 transition-colors"
                title="Copy SHA-256"
              >
                <Copy size={14} />
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Tabbed Multi-Engine Inspector */}
        <div className="col-span-12 lg:col-span-7 flex flex-col gap-4">
          {/* Engine Tabs */}
          <div className="flex border-b border-cyber-border/60 gap-2 overflow-x-auto pb-1 font-mono text-xs">
            {[
              { id: 'overview', label: 'Engine Overview', icon: Activity },
              { id: 'yara', label: 'YARA & Signatures', icon: ShieldAlert },
              { id: 'ai', label: 'AI & Static Analysis', icon: Cpu },
              { id: 'sandbox', label: 'Sandbox Trace', icon: Terminal },
              { id: 'quarantine', label: `Quarantine (${quarantineList.length})`, icon: Lock },
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

          {/* TAB 1: OVERVIEW */}
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
                  <span className="text-xs font-mono uppercase tracking-widest text-gray-400">File Storage Safety Verdict</span>
                  <span className="text-xs font-mono text-gray-400">Threat Score: <strong className="text-white font-bold">{scanResult.threatScore}%</strong></span>
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

              {/* Multi-Engine Score Breakdown */}
              <div className="glass-panel p-5 flex flex-col gap-3">
                <h4 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Multi-Engine Weighted Breakdown</span>
                  <span className="text-cyber-primary">Weighted Score: {scanResult.threatScore}%</span>
                </h4>

                <div className="space-y-2 font-mono text-xs">
                  {[
                    { label: 'AI Malware Classifier (40%)', score: scanResult.engineBreakdown.aiScore, color: 'bg-blue-500' },
                    { label: 'ClamAV & Hash Signatures (25%)', score: scanResult.engineBreakdown.signatureScore, color: 'bg-red-500' },
                    { label: 'Sandbox Behavioral Trace (15%)', score: scanResult.engineBreakdown.sandboxScore, color: 'bg-purple-500' },
                    { label: 'Threat Intel Reputation (10%)', score: scanResult.engineBreakdown.reputationScore, color: 'bg-amber-500' },
                    { label: 'YARA Rule Scanner (10%)', score: scanResult.engineBreakdown.yaraScore, color: 'bg-emerald-500' }
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

          {/* TAB 2: YARA & SIGNATURES */}
          {activeTab === 'yara' && (
            <div className="glass-panel p-5 flex-1 flex flex-col gap-4">
              <h4 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert size={14} className="text-cyber-secondary" /> YARA Rules & Signature Scanner Matches
              </h4>

              {scanResult.yaraMatches && scanResult.yaraMatches.length > 0 ? (
                <div className="space-y-2">
                  {scanResult.yaraMatches.map((m, idx) => (
                    <div key={idx} className="bg-black/70 p-3 rounded border border-cyber-danger/40 flex justify-between items-center">
                      <div>
                        <span className="text-cyber-danger font-bold text-xs font-mono block">{m.rule}</span>
                        <span className="text-gray-400 text-[11px] font-mono">{m.description}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyber-danger/20 text-cyber-danger uppercase border border-cyber-danger/40">
                        {m.severity}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs font-mono text-gray-400 bg-black/40 p-4 rounded text-center border border-cyber-border">
                  Zero YARA rule signature matches triggered.
                </div>
              )}

              {/* Flagged Lines */}
              <h5 className="text-xs font-mono font-bold text-gray-400 uppercase mt-2">Flagged Code Signatures ({scanResult.flaggedLines.length}):</h5>
              {scanResult.flaggedLines.length > 0 ? (
                <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                  {scanResult.flaggedLines.map((item, i) => (
                    <div key={i} className="bg-black/80 p-2.5 rounded border border-cyber-danger/30 font-mono text-xs">
                      <div className="flex justify-between text-cyber-danger font-bold text-[11px]">
                        <span>Line {item.line}: {item.category}</span>
                        <span>{item.severity}</span>
                      </div>
                      <code className="block bg-black p-1.5 rounded text-red-300 text-[10px] mt-1 overflow-x-auto">{item.content}</code>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs font-mono text-gray-400 bg-black/40 p-3 rounded text-center border border-cyber-border">
                  No malicious line patterns flagged.
                </div>
              )}
            </div>
          )}

          {/* TAB 3: AI & STATIC ANALYSIS */}
          {activeTab === 'ai' && (
            <div className="glass-panel p-5 flex-1 flex flex-col gap-4 font-mono text-xs">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                <Cpu size={14} className="text-cyber-primary" /> Static Feature Extraction & AI Classifier
              </h4>

              <div className="grid grid-cols-2 gap-3">
                <div className="bg-black/60 p-3 rounded border border-cyber-border">
                  <span className="text-gray-500 block text-[10px]">AI MODEL:</span>
                  <span className="text-cyber-secondary font-bold text-xs">RandomForest-XGBoost Ensemble</span>
                </div>
                <div className="bg-black/60 p-3 rounded border border-cyber-border">
                  <span className="text-gray-500 block text-[10px]">MALWARE PROBABILITY:</span>
                  <span className="text-cyber-danger font-bold text-xs">{scanResult.engineBreakdown.aiScore}%</span>
                </div>
              </div>

              <div className="bg-black/60 p-3 rounded border border-cyber-border space-y-2">
                <span className="text-gray-400 font-bold block text-[11px]">Extracted Feature Vector:</span>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-gray-300">
                  <div>Shannon Entropy: <strong className="text-white">{scanResult.entropy}</strong></div>
                  <div>File Category: <strong className="text-white">{scanResult.fileType}</strong></div>
                  <div>File Extension: <strong className="text-white">.{scanResult.fileExtension}</strong></div>
                  <div>Lines of Code/Data: <strong className="text-white">{scanResult.lineCount}</strong></div>
                  <div>Flagged Patterns: <strong className="text-white">{scanResult.flaggedLines.length}</strong></div>
                  <div>Risk Indicators: <strong className="text-white">{scanResult.riskFactors.length}</strong></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: SANDBOX TRACE */}
          {activeTab === 'sandbox' && (
            <div className="glass-panel p-5 flex-1 flex flex-col gap-3 font-mono text-xs">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                <Terminal size={14} className="text-cyber-primary" /> Dynamic Sandbox Execution Behavioral Trace
              </h4>

              <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                {scanResult.sandboxEvents && scanResult.sandboxEvents.map((evt, idx) => (
                  <div key={idx} className="bg-black/80 p-2.5 rounded border border-cyber-border flex flex-col gap-1">
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-cyber-primary font-bold">{evt.time}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                        evt.type === 'PROCESS' ? 'bg-blue-500/20 text-blue-400' :
                        evt.type === 'REGISTRY' ? 'bg-purple-500/20 text-purple-400' :
                        evt.type === 'NETWORK' ? 'bg-amber-500/20 text-amber-400' : 'bg-green-500/20 text-green-400'
                      }`}>
                        {evt.type}
                      </span>
                    </div>
                    <span className="text-gray-300 text-[11px]">{evt.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 5: QUARANTINE VAULT */}
          {activeTab === 'quarantine' && (
            <div className="glass-panel p-5 flex-1 flex flex-col gap-3 font-mono text-xs">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                <Lock size={14} className="text-cyber-danger" /> Quarantined Files Vault ({quarantineList.length})
              </h4>

              {quarantineList.length > 0 ? (
                <div className="space-y-2">
                  {quarantineList.map((q) => (
                    <div key={q.id} className="bg-black/80 p-3 rounded border border-cyber-border flex justify-between items-center">
                      <div>
                        <span className="text-white font-bold block">{q.fileName}</span>
                        <span className="text-gray-500 text-[10px]">{q.timestamp} | Score: {q.threatScore}%</span>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleRestoreQuarantine(q.id)}
                          className="px-2 py-1 bg-cyber-success/20 text-cyber-success rounded border border-cyber-success/40 text-[10px] flex items-center gap-1 hover:bg-cyber-success/40"
                        >
                          <RefreshCw size={10} /> Restore
                        </button>
                        <button
                          onClick={() => handleDeleteQuarantine(q.id)}
                          className="px-2 py-1 bg-cyber-danger/20 text-cyber-danger rounded border border-cyber-danger/40 text-[10px] flex items-center gap-1 hover:bg-cyber-danger/40"
                        >
                          <Trash2 size={10} /> Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs font-mono text-gray-400 bg-black/40 p-6 rounded text-center border border-cyber-border">
                  Quarantine vault is empty.
                </div>
              )}
            </div>
          )}

          {/* TAB 6: API EXPLORER */}
          {activeTab === 'api' && (
            <div className="glass-panel p-5 flex-1 flex flex-col gap-3 font-mono text-xs">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                <Server size={14} className="text-cyber-secondary" /> FastAPI Endpoint Tester
              </h4>

              <div className="flex gap-2 mb-2">
                {['/scan/file', '/scan/network-file', '/quarantine', '/dashboard/file-threats'].map((ep) => (
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
  sampleResponse: selectedApiEndpoint.includes('quarantine') 
    ? { quarantinedCount: quarantineList.length, storage: "MinIO / Local Vault" }
    : { fileName: scanResult.fileName, threatScore: scanResult.threatScore, decision: scanResult.decision }
}, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default FileThreatScanner;
