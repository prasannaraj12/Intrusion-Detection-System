import React, { useState, useEffect, useRef, useCallback } from 'react';
import Navigation from './components/Navigation';
import OverviewView from './components/OverviewView';
import ThreatsView from './components/ThreatsView';
import NetworkView from './components/NetworkView';
import HoneypotView from './components/HoneypotView';
import IntelligenceView from './components/IntelligenceView';
import AnalyticsView from './components/AnalyticsView';
import SystemView from './components/SystemView';
import TrafficSimulatorModal from './components/TrafficSimulatorModal';
import './App.css';

const API_BASE = 'http://localhost:5000';

function App() {
  // Primary Navigation (7 items): overview, threats, network, honeypot, intelligence, analytics, system
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedThreat, setSelectedThreat] = useState(null);

  const [apiOnline, setApiOnline] = useState(false);
  const [modelInfo, setModelInfo] = useState(null);
  const [uptimeSeconds, setUptimeSeconds] = useState(480);

  // Simulator modal state
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [autoStream, setAutoStream] = useState(false);
  const [activeScenario, setActiveScenario] = useState('ddos');
  const [packetCount, setPacketCount] = useState(16);

  // Metrics
  const [metrics, setMetrics] = useState({
    totalFlows: 284,
    totalPackets: 4120,
    allowedFlows: 182,
    monitoredFlows: 34,
    quarantinedFlows: 68,
    avgLatencyMs: 1.98,
    lastLatencyMs: 1.82
  });

  // Recent detections & events
  const [events, setEvents] = useState([
    {
      id: 'flow-init-1',
      timestamp: new Date(Date.now() - 1000 * 55).toLocaleTimeString(),
      scenario: 'ddos',
      is_attack: true,
      risk_score: 88.4,
      risk_level: 'HIGH RISK',
      policy: 'QUARANTINE',
      policy_action: 'REROUTE_TO_HONEYPOT_SINKHOLE',
      status_color: 'ROSE',
      attack_category: 'DDOS_SYN_FLOOD',
      mitre_ttp: 'T1498.001 - Network Denial of Service: Direct Flood',
      confidence: 0.884,
      attack_probability: 0.884,
      src_ip: '203.0.113.42',
      dst_ip: '10.0.0.1',
      port: 80,
      packet_count: 16,
      features: {
        'Flow Duration': 14200,
        'Flow IAT Mean': 590,
        'Fwd IAT Mean': 590,
        'Fwd IAT Std': 180,
        'Bwd IAT Std': 0,
        'Fwd IAT Max': 940,
        'Flow IAT Max': 940,
        'Flow IAT Std': 180,
        'Fwd IAT Total': 14200,
        'Bwd IAT Max': 0,
        'Idle Max': 0,
        'Idle Mean': 0
      },
      shap_explanation: {
        base_value: -1.31,
        explanation: 'Flagged primarily due to abnormal Fwd IAT Mean (+1.39) and elevated Fwd IAT Total (+1.07)',
        top_drivers: [
          { feature: 'Fwd IAT Mean', shap_value: 1.3897, feature_value: 590, direction: 'ATTACK', impact: 1.3897 },
          { feature: 'Fwd IAT Total', shap_value: 1.0735, feature_value: 14200, direction: 'ATTACK', impact: 1.0735 },
          { feature: 'Flow Duration', shap_value: 0.8421, feature_value: 14200, direction: 'ATTACK', impact: 0.8421 },
          { feature: 'Idle Max', shap_value: -0.4299, feature_value: 0, direction: 'BENIGN', impact: 0.4299 }
        ]
      }
    },
    {
      id: 'flow-init-2',
      timestamp: new Date(Date.now() - 1000 * 35).toLocaleTimeString(),
      scenario: 'port_scan',
      is_attack: true,
      risk_score: 87.4,
      risk_level: 'HIGH RISK',
      policy: 'QUARANTINE',
      policy_action: 'REROUTE_TO_HONEYPOT_SINKHOLE',
      status_color: 'ROSE',
      attack_category: 'RECON_PORT_SCAN',
      mitre_ttp: 'T1046 - Network Service Scanning',
      confidence: 0.874,
      attack_probability: 0.874,
      src_ip: '45.143.201.12',
      dst_ip: '10.0.0.1',
      port: 8080,
      packet_count: 12,
      features: {
        'Flow Duration': 3200,
        'Flow IAT Mean': 266,
        'Fwd IAT Mean': 266,
        'Fwd IAT Std': 45,
        'Bwd IAT Std': 0,
        'Fwd IAT Max': 350,
        'Flow IAT Max': 350,
        'Flow IAT Std': 45,
        'Fwd IAT Total': 3200,
        'Bwd IAT Max': 0,
        'Idle Max': 0,
        'Idle Mean': 0
      },
      shap_explanation: {
        base_value: -1.31,
        explanation: 'Rapid SYN probing across diverse port ranges flagged due to ultra-low Flow IAT Mean (+1.52)',
        top_drivers: [
          { feature: 'Flow IAT Mean', shap_value: 1.521, feature_value: 266, direction: 'ATTACK', impact: 1.521 },
          { feature: 'Flow Duration', shap_value: 0.984, feature_value: 3200, direction: 'ATTACK', impact: 0.984 },
          { feature: 'Fwd IAT Total', shap_value: 0.722, feature_value: 3200, direction: 'ATTACK', impact: 0.722 }
        ]
      }
    },
    {
      id: 'flow-init-3',
      timestamp: new Date(Date.now() - 1000 * 20).toLocaleTimeString(),
      scenario: 'benign',
      is_attack: false,
      risk_score: 1.5,
      risk_level: 'LOW RISK',
      policy: 'ALLOW',
      policy_action: 'FORWARD_TO_INTERNAL_NETWORK',
      status_color: 'EMERALD',
      attack_category: 'BENIGN',
      mitre_ttp: 'N/A',
      confidence: 0.985,
      attack_probability: 0.015,
      src_ip: '192.168.1.105',
      dst_ip: '10.0.0.1',
      port: 443,
      packet_count: 14,
      features: {
        'Flow Duration': 784000,
        'Flow IAT Mean': 60307,
        'Fwd IAT Mean': 120615,
        'Fwd IAT Std': 22400,
        'Bwd IAT Std': 34100,
        'Fwd IAT Max': 175000,
        'Flow IAT Max': 108000,
        'Flow IAT Std': 24000,
        'Fwd IAT Total': 720000,
        'Bwd IAT Max': 199000,
        'Idle Max': 0,
        'Idle Mean': 0
      },
      shap_explanation: {
        base_value: -1.31,
        explanation: 'Normal temporal cadence confirmed by standard Fwd IAT Total (-1.46) and natural packet intervals',
        top_drivers: [
          { feature: 'Fwd IAT Total', shap_value: -1.4589, feature_value: 720000, direction: 'BENIGN', impact: 1.4589 },
          { feature: 'Flow Duration', shap_value: -0.9241, feature_value: 784000, direction: 'BENIGN', impact: 0.9241 }
        ]
      }
    }
  ]);

  // Telemetry, sessions, and IOCs
  const [honeypotSessions, setHoneypotSessions] = useState([]);
  const [iocsList, setIocsList] = useState([]);
  const [benchmarkReport, setBenchmarkReport] = useState(null);

  // Health and data fetch
  const fetchData = useCallback(async () => {
    try {
      const resHealth = await fetch(`${API_BASE}/health`);
      if (resHealth.ok) {
        const dataHealth = await resHealth.json();
        setApiOnline(true);
        setModelInfo(dataHealth);
      } else {
        setApiOnline(false);
      }

      const resSessions = await fetch(`${API_BASE}/api/honeypot/sessions`);
      if (resSessions.ok) {
        const dataSessions = await resSessions.json();
        setHoneypotSessions(dataSessions.sessions || []);
      }

      const resIocs = await fetch(`${API_BASE}/api/iocs`);
      if (resIocs.ok) {
        const dataIocs = await resIocs.json();
        setIocsList(dataIocs.iocs || []);
      }

      const resBench = await fetch(`${API_BASE}/api/model/benchmarks`);
      if (resBench.ok) {
        const dataBench = await resBench.json();
        setBenchmarkReport(dataBench);
      }
    } catch (err) {
      setApiOnline(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4500);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Uptime counter
  useEffect(() => {
    const timer = setInterval(() => setUptimeSeconds((prev) => prev + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  // Trigger test flow simulation
  const triggerSimulation = async (scenarioType) => {
    const targetScenario = scenarioType || activeScenario;
    setIsSimulating(true);
    const startTime = performance.now();

    try {
      const res = await fetch(`${API_BASE}/api/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: targetScenario,
          count: packetCount
        })
      });

      const latency = Math.round((performance.now() - startTime) * 10) / 10;

      if (res.ok) {
        const data = await res.json();
        const newEvent = {
          id: `flow-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          scenario: data.scenario,
          is_attack: data.is_attack,
          risk_score: data.risk_score,
          risk_level: data.risk_level,
          policy: data.policy,
          policy_action: data.policy_action,
          status_color: data.status_color,
          attack_category: data.attack_category,
          mitre_ttp: data.mitre_ttp,
          confidence: data.confidence,
          attack_probability: data.attack_probability,
          src_ip: data.packets?.[0]?.src_ip || '192.168.1.100',
          dst_ip: data.packets?.[0]?.dst_ip || '10.0.0.1',
          port: data.packets?.[0]?.dst_port || 80,
          packet_count: data.packet_count,
          features: data.features,
          shap_explanation: data.shap_explanation,
          rawPackets: data.packets
        };

        setEvents((prev) => [newEvent, ...prev.slice(0, 49)]);

        setMetrics((prev) => ({
          totalFlows: prev.totalFlows + 1,
          totalPackets: prev.totalPackets + data.packet_count,
          allowedFlows: prev.allowedFlows + (data.policy === 'ALLOW' ? 1 : 0),
          monitoredFlows: prev.monitoredFlows + (data.policy === 'MONITOR' ? 1 : 0),
          quarantinedFlows: prev.quarantinedFlows + (data.policy === 'QUARANTINE' ? 1 : 0),
          lastLatencyMs: latency,
          avgLatencyMs: Math.round(((prev.avgLatencyMs * 4 + latency) / 5) * 10) / 10
        }));

        fetchData();
      }
    } catch (err) {
      console.error('Simulation request failed:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  // Continuous background stream
  const autoStreamRef = useRef(autoStream);
  autoStreamRef.current = autoStream;
  const triggerSimRef = useRef(triggerSimulation);
  triggerSimRef.current = triggerSimulation;

  useEffect(() => {
    if (!autoStream) return;
    const scenarios = ['benign', 'benign', 'ddos', 'port_scan', 'benign', 'brute_force', 'slowloris', 'adversarial_jitter'];
    const timer = setInterval(() => {
      if (autoStreamRef.current && triggerSimRef.current) {
        const randomScenario = scenarios[Math.floor(Math.random() * scenarios.length)];
        triggerSimRef.current(randomScenario);
      }
    }, 2800);
    return () => clearInterval(timer);
  }, [autoStream, packetCount]);

  // Investigation workflow trigger
  const handleSelectThreat = (threat) => {
    setSelectedThreat(threat);
    setActiveTab('threats');
  };

  return (
    <div className="aegis-app-container">
      {/* 1. Primary Navigation */}
      <Navigation
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'threats') {
            setSelectedThreat(null);
          }
        }}
        apiOnline={apiOnline}
        activeThreatCount={events.filter((e) => e.policy === 'QUARANTINE').length}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
      />

      {/* 2. Main Viewport */}
      <main className="aegis-main-viewport">
        {activeTab === 'overview' && (
          <OverviewView
            metrics={metrics}
            events={events}
            iocsCount={iocsList.length}
            apiOnline={apiOnline}
            modelInfo={modelInfo}
            onSelectThreat={handleSelectThreat}
            onNavigateTo={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'threats' && (
          <ThreatsView
            events={events}
            selectedThreat={selectedThreat}
            onSelectThreat={(t) => setSelectedThreat(t)}
            onClearSelectedThreat={() => setSelectedThreat(null)}
            onNavigateTo={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'network' && (
          <NetworkView
            metrics={metrics}
            events={events}
            onSelectThreat={handleSelectThreat}
          />
        )}

        {activeTab === 'honeypot' && (
          <HoneypotView
            honeypotSessions={honeypotSessions}
            iocsList={iocsList}
            onNavigateTo={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'intelligence' && (
          <IntelligenceView iocsList={iocsList} />
        )}

        {activeTab === 'analytics' && (
          <AnalyticsView benchmarkReport={benchmarkReport} />
        )}

        {activeTab === 'system' && (
          <SystemView
            apiOnline={apiOnline}
            modelInfo={modelInfo}
            uptimeSeconds={uptimeSeconds}
          />
        )}
      </main>

      {/* 3. Simulator Modal */}
      <TrafficSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        activeScenario={activeScenario}
        setActiveScenario={setActiveScenario}
        packetCount={packetCount}
        setPacketCount={setPacketCount}
        isSimulating={isSimulating}
        onTriggerSimulation={triggerSimulation}
        autoStream={autoStream}
        setAutoStream={setAutoStream}
      />
    </div>
  );
}

export default App;
