import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import MetricsOverview from './components/MetricsOverview';
import LiveTrafficMonitor from './components/LiveTrafficMonitor';
import ThreatAlertPanel from './components/ThreatAlertPanel';
import AttackSimulator from './components/AttackSimulator';
import ModelPerformance from './components/ModelPerformance';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState({
    bandwidth: 0,
    packetRate: 0,
    threatLevel: 'Low',
    totalAnalyzed: 0,
    blockedIPs: 0
  });

  // Global state for traffic stream
  const [trafficStream, setTrafficStream] = useState([]);
  
  const handleNewPacket = (packet) => {
    setTrafficStream(prev => [packet, ...prev].slice(0, 50));
    setMetrics(prev => ({
      ...prev,
      totalAnalyzed: prev.totalAnalyzed + 1,
      bandwidth: prev.bandwidth + packet.size,
      packetRate: Math.floor(Math.random() * 50) + 100
    }));

    if (packet.threatScore > 75) {
      handleNewAlert({
        id: Date.now(),
        type: packet.classification,
        source: packet.srcIP,
        target: packet.destIP,
        severity: packet.threatScore > 90 ? 'Critical' : 'High',
        timestamp: new Date().toISOString(),
        geo: packet.geo,
        payloadInfo: packet.payloadInfo
      });
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
    <div className="min-h-screen flex flex-col">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} threatLevel={metrics.threatLevel} />
      
      <main className="flex-1 p-6 overflow-hidden flex flex-col max-w-[1600px] w-full mx-auto">
        {activeTab === 'dashboard' && (
          <div className="flex-1 grid grid-cols-12 gap-6">
            {/* Left Column - Metrics & Monitor */}
            <div className="col-span-12 lg:col-span-8 flex flex-col gap-6">
              <MetricsOverview metrics={metrics} />
              <div className="flex-1 min-h-[400px]">
                <LiveTrafficMonitor onNewPacket={handleNewPacket} />
              </div>
            </div>
            
            {/* Right Column - Alerts & Simulator */}
            <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
              <ThreatAlertPanel alerts={alerts} onClear={clearAlerts} />
              <AttackSimulator onTriggerAttack={(attack) => {
                // Mock attack trigger logic to update UI
                console.log("Triggered attack:", attack);
              }} />
            </div>
          </div>
        )}

        {activeTab === 'models' && (
          <ModelPerformance />
        )}
      </main>
    </div>
  );
}

export default App;
