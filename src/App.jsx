import React, { useState } from 'react';
import Navbar from './components/Navbar';
import MetricsOverview from './components/MetricsOverview';
import LiveTrafficMonitor from './components/LiveTrafficMonitor';
import ThreatAlertPanel from './components/ThreatAlertPanel';
import AttackSimulator from './components/AttackSimulator';
import ModelPerformance from './components/ModelPerformance';
import FileThreatScanner from './components/FileThreatScanner';
import UrlInspector from './components/UrlInspector';
import SettingsModal from './components/SettingsModal';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [alerts, setAlerts] = useState([]);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [inspectTarget, setInspectTarget] = useState(null);

  const [settings, setSettings] = useState({
    lambdaUrl: import.meta.env.VITE_LAMBDA_API_URL || 'https://mukpvdcdcsb6kfq5swwujk4vra0jizgi.lambda-url.eu-north-1.on.aws/',
    useLiveLambda: true,
    sensitivityThreshold: 75,
    autoBlockCritical: false
  });

  const [metrics, setMetrics] = useState({
    bandwidth: 0,
    packetRate: 0,
    threatLevel: 'Low',
    totalAnalyzed: 0,
    blockedIPs: 0
  });

  const [_trafficStream, setTrafficStream] = useState([]);

  const handleInspectPacket = (target) => {
    setInspectTarget(target);
    setActiveTab('url-inspector');
  };

  const handleBlockIP = (ipToBlock) => {
    if (!ipToBlock) return;
    setBlockedIPs(prev => {
      if (prev.includes(ipToBlock)) return prev;
      const updated = [...prev, ipToBlock];
      setMetrics(m => ({ ...m, blockedIPs: updated.length }));
      return updated;
    });

    setAlerts(prevAlerts => 
      prevAlerts.map(alert => 
        alert.source === ipToBlock ? { ...alert, isBlocked: true } : alert
      )
    );
  };

  const handleUnblockIP = (ipToUnblock) => {
    setBlockedIPs(prev => {
      const updated = prev.filter(ip => ip !== ipToUnblock);
      setMetrics(m => ({ ...m, blockedIPs: updated.length }));
      return updated;
    });

    setAlerts(prevAlerts => 
      prevAlerts.map(alert => 
        alert.source === ipToUnblock ? { ...alert, isBlocked: false } : alert
      )
    );
  };

  const handleNewPacket = (packet) => {
    const isIPBlocked = blockedIPs.includes(packet.srcIP);
    
    setTrafficStream(prev => [packet, ...prev].slice(0, 50));
    setMetrics(prev => ({
      ...prev,
      totalAnalyzed: prev.totalAnalyzed + 1,
      bandwidth: prev.bandwidth + packet.size,
      packetRate: Math.floor(Math.random() * 50) + 100
    }));

    if (!isIPBlocked && packet.threatScore >= settings.sensitivityThreshold) {
      const isCritical = packet.threatScore > 90;
      
      handleNewAlert({
        id: Date.now() + Math.random(),
        type: packet.classification,
        source: packet.srcIP,
        target: packet.destIP,
        severity: isCritical ? 'Critical' : 'High',
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 3 }),
        geo: packet.geo,
        payloadInfo: packet.payloadInfo,
        isBlocked: false
      });

      if (isCritical && settings.autoBlockCritical) {
        handleBlockIP(packet.srcIP);
      }
    }
  };

  const handleNewAlert = (alert) => {
    setAlerts(prev => [alert, ...prev].slice(0, 20));
    setMetrics(prev => ({
      ...prev,
      threatLevel: alert.severity === 'Critical' ? 'Critical' : 'High'
    }));
  };

  const clearAlerts = () => {
    setAlerts([]);
    setMetrics(prev => ({ ...prev, threatLevel: 'Low' }));
  };

  return (
    <div className="min-h-screen flex flex-col bg-cyber-bg text-white">
      <Navbar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        threatLevel={metrics.threatLevel}
        onOpenSettings={() => setIsSettingsOpen(true)}
      />
      
      <main className="flex-1 p-6 overflow-hidden flex flex-col max-w-[1600px] w-full mx-auto">
        {activeTab === 'dashboard' && (
          <div className="flex-1 grid grid-cols-12 gap-6">
            {/* Left Column - Metrics & Monitor */}
            <div className="col-span-12 lg:col-span-8 flex flex-col gap-6">
              <MetricsOverview metrics={metrics} />
              <div className="flex-1 min-h-[400px]">
                <LiveTrafficMonitor 
                  onNewPacket={handleNewPacket} 
                  onInspectPacket={handleInspectPacket}
                />
              </div>
            </div>
            
            {/* Right Column - Alerts & Simulator */}
            <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
              <ThreatAlertPanel 
                alerts={alerts} 
                onClear={clearAlerts} 
                onBlockIP={handleBlockIP}
              />
              <AttackSimulator onTriggerAttack={(attack) => {
                console.log("Triggered attack simulation:", attack);
              }} />
            </div>
          </div>
        )}

        {activeTab === 'file-scanner' && (
          <FileThreatScanner />
        )}

        {activeTab === 'url-inspector' && (
          <UrlInspector 
            inspectTarget={inspectTarget}
            onClearTarget={() => setInspectTarget(null)}
          />
        )}

        {activeTab === 'models' && (
          <ModelPerformance />
        )}
      </main>

      {/* Settings Modal */}
      <SettingsModal 
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        settings={settings}
        onUpdateSettings={setSettings}
        blockedIPs={blockedIPs}
        onUnblockIP={handleUnblockIP}
      />
    </div>
  );
}

export default App;
