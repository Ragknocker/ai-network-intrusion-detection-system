import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Search } from 'lucide-react';
import { generatePacket } from '../services/trafficGenerator';

const LiveTrafficMonitor = ({ onNewPacket, onInspectPacket }) => {
  const [packets, setPackets] = useState([]);
  const [isPaused, setIsPaused] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(() => {
      const newPacket = generatePacket();
      onNewPacket(newPacket);
      
      setPackets(prev => {
        const newPackets = [...prev, newPacket];
        if (newPackets.length > 50) newPackets.shift();
        return newPackets;
      });
    }, 800);

    return () => clearInterval(interval);
  }, [isPaused, onNewPacket]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [packets]);

  return (
    <div className="glass-panel h-full flex flex-col overflow-hidden">
      <div className="p-3 border-b border-cyber-border flex justify-between items-center bg-black/40">
        <div className="flex items-center gap-2 text-cyber-primary">
          <Terminal size={18} />
          <h2 className="font-mono text-sm tracking-wider uppercase">Live Network Stream</h2>
        </div>
        <button 
          onClick={() => setIsPaused(!isPaused)}
          className={`px-3 py-1 text-xs font-mono rounded border transition-colors ${isPaused ? 'border-cyber-warning text-cyber-warning' : 'border-cyber-primary text-cyber-primary'}`}
        >
          {isPaused ? 'RESUME' : 'PAUSE'}
        </button>
      </div>

      <div 
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-1"
        style={{ scrollBehavior: 'smooth' }}
      >
        {packets.map((packet) => (
          <div 
            key={packet.id} 
            className={`flex items-center gap-4 py-1 px-2 rounded group
              ${packet.threatScore > 90 ? 'bg-cyber-danger/20 text-cyber-danger' : 
                packet.threatScore > 50 ? 'bg-cyber-warning/20 text-cyber-warning' : 
                'text-gray-400 hover:bg-white/5'} transition-colors`}
          >
            <span className="opacity-50 w-20">{packet.timestamp}</span>
            <span className={`w-12 text-center rounded ${packet.protocol === 'TCP' ? 'bg-blue-500/20 text-blue-400' : packet.protocol === 'UDP' ? 'bg-purple-500/20 text-purple-400' : 'bg-gray-500/20 text-gray-400'}`}>
              {packet.protocol}
            </span>
            <span className="w-32 truncate">{packet.srcIP}:{packet.srcPort}</span>
            <span className="opacity-50">-{'>'}</span>
            <span className="w-32 truncate">{packet.destIP}:{packet.destPort}</span>
            
            {packet.threatScore > 50 ? (
              <span className="ml-auto font-bold animate-pulse">
                [{packet.classification}] (Score: {packet.threatScore.toFixed(1)})
              </span>
            ) : (
              <span className="ml-auto text-gray-500 text-[11px] truncate max-w-[140px]">
                {packet.payloadInfo}
              </span>
            )}

            {onInspectPacket && (
              <button
                onClick={() => onInspectPacket({
                  type: packet.classification === 'SQL Injection' || packet.classification === 'Zero-Day' ? 'code' : 'url',
                  value: packet.classification === 'SQL Injection' 
                    ? `function queryUser() {\n  const q = "SELECT * FROM users WHERE id = '${packet.srcIP}'";\n  eval(q);\n}`
                    : `http://${packet.srcIP}/gateway/login.php?token=${packet.id}`,
                  source: packet.srcIP,
                  payload: packet.payloadInfo
                })}
                title="Inspect in URL Inspector"
                className="opacity-0 group-hover:opacity-100 px-2 py-0.5 bg-cyber-primary/20 hover:bg-cyber-primary hover:text-black border border-cyber-primary/50 rounded text-[10px] text-cyber-primary transition-all flex items-center gap-1 shrink-0 ml-2 font-bold"
              >
                <Search size={10} /> Inspect
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default LiveTrafficMonitor;
