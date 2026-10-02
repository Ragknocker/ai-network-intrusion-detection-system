import React, { useState } from 'react';
import { 
  Shield, Server, Lock, Globe, MapPin, 
  Network, Database, Radio, ChevronRight, CheckCircle2, AlertTriangle, ShieldAlert 
} from 'lucide-react';

const SecurityIndicatorsPanel = ({ scanResult }) => {
  const [activeDnsTab, setActiveDnsTab] = useState('a');

  if (!scanResult) return null;

  const indicators = scanResult.securityIndicators || {};
  const whois = indicators.whois || {};
  const ssl = indicators.sslTls || {};
  const dns = indicators.dnsRecords || { a: [], mx: [], ns: [], txt: [] };
  const ip = indicators.ipReputation || {};
  const passiveDns = indicators.passiveDns || {};

  const getBadgeStyle = (badge) => {
    switch (badge) {
      case 'TRUSTED':
        return 'bg-green-500/20 text-green-400 border-green-500/40';
      case 'SUSPICIOUS':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      case 'MALICIOUS':
        return 'bg-red-500/20 text-red-400 border-red-500/40 font-bold';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/40';
    }
  };

  return (
    <div className="glass-panel p-5 sm:p-6 flex flex-col gap-4 font-mono">
      <div className="flex items-center justify-between border-b border-cyber-border/80 pb-3">
        <div className="flex items-center gap-2">
          <Server size={18} className="text-cyber-secondary" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            Domain Intelligence
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-gray-400">Security Indicators:</span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getBadgeStyle(indicators.domainReputationBadge)}`}>
            {indicators.domainReputationBadge || 'UNKNOWN'}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
        {/* Card 1: WHOIS & Domain Age */}
        <div className="p-4 rounded-xl bg-black/40 border border-cyber-border flex flex-col gap-2.5">
          <div className="flex items-center justify-between pb-2 border-b border-cyber-border/50">
            <span className="font-bold text-white uppercase text-[11px] flex items-center gap-1.5">
              <Globe size={13} className="text-cyber-primary" /> WHOIS Registration
            </span>
            <span className={`px-2 py-0.2 rounded text-[10px] font-semibold border ${
              whois.registrar?.includes('Privacy') || whois.registrar?.includes('NameCheap') ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' : 'bg-green-500/20 text-green-400 border-green-500/30'
            }`}>
              {whois.dnssec || 'Active'}
            </span>
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between">
              <span className="text-gray-400">Registrar:</span>
              <span className="text-white font-semibold truncate max-w-[170px]" title={whois.registrar}>
                {whois.registrar || 'N/A'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Registration Age:</span>
              <span className="text-cyber-warning font-bold">
                {indicators.domainRegistrationAge || 'N/A'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Created:</span>
              <span className="text-gray-200">{whois.createdDate || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Expires:</span>
              <span className="text-gray-200">{whois.expiresDate || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Registrant Org:</span>
              <span className="text-gray-300 truncate max-w-[170px]">{whois.registrantOrg || 'Private'}</span>
            </div>
          </div>
        </div>

        {/* Card 2: SSL / TLS Certificate Status */}
        <div className="p-4 rounded-xl bg-black/40 border border-cyber-border flex flex-col gap-2.5">
          <div className="flex items-center justify-between pb-2 border-b border-cyber-border/50">
            <span className="font-bold text-white uppercase text-[11px] flex items-center gap-1.5">
              <Lock size={13} className="text-green-400" /> SSL / TLS Certificate
            </span>
            <span className={`px-2 py-0.2 rounded text-[10px] font-bold border ${getBadgeStyle(ssl.statusBadge)}`}>
              {ssl.statusBadge || 'UNKNOWN'}
            </span>
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between">
              <span className="text-gray-400">Certificate Status:</span>
              <span className={`font-semibold ${ssl.valid ? 'text-green-400' : 'text-red-400'}`}>
                {ssl.valid ? 'Valid & Trusted' : 'Invalid / Missing'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Cipher Suite:</span>
              <span className="text-gray-200 truncate max-w-[170px]">{ssl.cipher || 'None'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Issuer CA:</span>
              <span className="text-white truncate max-w-[170px]">{ssl.issuer || 'None'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Validity Period:</span>
              <span className="text-gray-300">{ssl.validTo || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Serial Number:</span>
              <span className="text-gray-400 font-mono text-[11px]">{ssl.serial || 'N/A'}</span>
            </div>
          </div>
        </div>

        {/* Card 3: Host IP & Network Reputation */}
        <div className="p-4 rounded-xl bg-black/40 border border-cyber-border flex flex-col gap-2.5">
          <div className="flex items-center justify-between pb-2 border-b border-cyber-border/50">
            <span className="font-bold text-white uppercase text-[11px] flex items-center gap-1.5">
              <Network size={13} className="text-cyber-primary" /> IP & ASN Reputation
            </span>
            <span className={`px-2 py-0.2 rounded text-[10px] font-bold border ${getBadgeStyle(ip.badge)}`}>
              {ip.badge || 'UNKNOWN'}
            </span>
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between">
              <span className="text-gray-400">Resolved IP:</span>
              <span className="text-white font-mono font-bold">{ip.ip || '127.0.0.1'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Abuse Confidence:</span>
              <span className={`font-bold ${ip.badge === 'MALICIOUS' ? 'text-red-400' : 'text-green-400'}`}>
                {ip.abuseScore || '0%'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">ASN / Provider:</span>
              <span className="text-gray-200 truncate max-w-[170px]">{ip.asn || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Geolocation:</span>
              <span className="text-gray-300 flex items-center gap-1 truncate max-w-[170px]">
                <MapPin size={11} className="text-red-400 shrink-0" /> {ip.city ? `${ip.city}, ` : ''}{ip.country || 'N/A'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Reverse DNS:</span>
              <span className="text-gray-400 truncate max-w-[170px]">{ip.reverseDns || 'N/A'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Lower Row: DNS Records Tabs & Passive DNS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2 border-t border-cyber-border/60 text-xs">
        {/* DNS Records */}
        <div className="p-4 rounded-xl bg-black/30 border border-cyber-border flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase text-gray-300 font-bold flex items-center gap-1.5">
              <Database size={13} className="text-cyber-primary" /> Live DNS Records
            </span>

            {/* DNS Tabs */}
            <div className="flex items-center gap-1">
              {['a', 'ns', 'mx', 'txt'].map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setActiveDnsTab(tab)}
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase transition-all ${
                    activeDnsTab === tab
                      ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/50'
                      : 'text-gray-400 hover:text-white bg-black/40'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>

          <div className="bg-black/50 p-2.5 rounded-lg border border-cyber-border/60 font-mono text-[11px] min-h-[70px] max-h-28 overflow-y-auto">
            {activeDnsTab === 'a' && (
              <div className="space-y-1">
                {(dns.a || []).map((rec, i) => (
                  <div key={i} className="flex justify-between text-gray-300">
                    <span>A Record:</span>
                    <span className="text-cyber-primary font-bold">{rec}</span>
                  </div>
                ))}
              </div>
            )}
            {activeDnsTab === 'ns' && (
              <div className="space-y-1">
                {(dns.ns || []).map((rec, i) => (
                  <div key={i} className="flex justify-between text-gray-300">
                    <span>Nameserver:</span>
                    <span className="text-white">{rec}</span>
                  </div>
                ))}
              </div>
            )}
            {activeDnsTab === 'mx' && (
              <div className="space-y-1">
                {(dns.mx || []).map((rec, i) => (
                  <div key={i} className="flex justify-between text-gray-300">
                    <span>Mail Exchanger:</span>
                    <span className="text-white">{rec}</span>
                  </div>
                ))}
              </div>
            )}
            {activeDnsTab === 'txt' && (
              <div className="space-y-1">
                {(dns.txt || []).map((rec, i) => (
                  <p key={i} className="text-gray-400 break-all">{rec}</p>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Passive DNS Telemetry */}
        <div className="p-4 rounded-xl bg-black/30 border border-cyber-border flex flex-col justify-between gap-2">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase text-gray-300 font-bold flex items-center gap-1.5">
              <Radio size={13} className="text-cyber-secondary" /> Passive DNS & Flux Telemetry
            </span>
            <span className="text-[10px] text-gray-400">Sensor v3.1</span>
          </div>

          <div className="space-y-1.5 text-gray-300 text-[11px]">
            <div className="flex justify-between">
              <span className="text-gray-400">Historical IP Bindings:</span>
              <span className="font-bold text-white">{passiveDns.historicalIpCount || 1} IPs</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">First Observed:</span>
              <span>{passiveDns.firstSeen || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Fast-Flux Rotation:</span>
              <span className={passiveDns.fastFluxDetected?.includes('Suspicious') ? 'text-red-400 font-bold' : 'text-green-400'}>
                {passiveDns.fastFluxDetected || 'Stable Resolution'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityIndicatorsPanel;
