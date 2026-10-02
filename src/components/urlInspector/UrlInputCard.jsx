import React, { useState } from 'react';
import { 
  Search, Globe, Clipboard, Trash2, ShieldCheck, 
  Sparkles, Layers, AlertCircle 
} from 'lucide-react';
import { URL_PRESETS } from '../../services/urlInspector';

const UrlInputCard = ({ 
  urlInput, 
  setUrlInput, 
  onInspect, 
  onClear, 
  activePreset, 
  setActivePreset,
  scanMode,
  setScanMode,
  isScanning 
}) => {
  const [pasteFeedback, setPasteFeedback] = useState(false);

  const handlePaste = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          setUrlInput(text.trim());
          setActivePreset(null);
          setPasteFeedback(true);
          setTimeout(() => setPasteFeedback(false), 1500);
        }
      }
    } catch {
      // Fallback
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !isScanning) {
      const inputEl = typeof document !== 'undefined' ? document.getElementById('url-input') : null;
      onInspect(inputEl ? inputEl.value : urlInput);
    }
  };

  const handleInputChange = (e) => {
    setUrlInput(e.target.value);
    setActivePreset(null);
  };

  const handleSelectPreset = (preset) => {
    setUrlInput(preset.url);
    setActivePreset(preset.name);
    onInspect(preset.url);
  };

  const handleButtonClick = () => {
    const inputEl = typeof document !== 'undefined' ? document.getElementById('url-input') : null;
    const val = inputEl && inputEl.value ? inputEl.value : urlInput;
    onInspect(val);
  };

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      {/* Top Controls Header */}
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

      {/* Main Input Row */}
      <div className="flex flex-col md:flex-row gap-2.5">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-gray-500">
            <Globe size={18} />
          </div>
          <input
            id="url-input"
            type="text"
            value={urlInput}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            disabled={isScanning}
            placeholder="Enter URL to inspect (e.g., https://google.com, https://github.com, or http://secure-paypal-login.xyz)"
            className="w-full pl-10 pr-24 py-3.5 bg-black/50 border border-cyber-border rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyber-primary focus:ring-1 focus:ring-cyber-primary transition-colors disabled:opacity-50"
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
                onClick={onClear}
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
          onClick={handleButtonClick}
          disabled={isScanning}
          className="px-6 py-3.5 bg-cyber-primary hover:bg-cyber-primary/90 text-black font-semibold text-sm rounded-lg transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(0,240,255,0.3)] shrink-0"
        >
          <Search size={16} />
          {isScanning ? 'Analyzing...' : 'Inspect URL'}
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
  );
};

export default UrlInputCard;
