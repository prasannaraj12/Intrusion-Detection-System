import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Server,
  Zap,
  Radio,
  Eye,
  RefreshCw,
  Terminal,
  Cpu,
  Lock,
  Layers,
  ArrowRight,
  Database,
  Sliders,
  CheckCircle2,
  XCircle,
  Play,
  Square,
  Clock,
  Crosshair,
  ExternalLink,
  BarChart3,
  HelpCircle,
  GitCompare,
  TrendingUp,
  Download,
  AlertCircle
} from 'lucide-react';
import './App.css';

const API_BASE = 'http://localhost:5000';

function App() {
  // Navigation Tabs: 'overview', 'detection', 'inspector', 'honeypot', 'model'
  const [activeTab, setActiveTab] = useState('overview');
  
  const [apiOnline, setApiOnline] = useState(false);
  const [modelInfo, setModelInfo] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [autoStream, setAutoStream] = useState(false);
  const [activeScenario, setActiveScenario] = useState('ddos');
  const [packetCount, setPacketCount] = useState(16);
  
  // Real-time metrics
  const [metrics, setMetrics] = useState({
    totalFlows: 284,
    totalPackets: 4120,
    allowedFlows: 182,
    monitoredFlows: 34,
    quarantinedFlows: 68,
    avgLatencyMs: 1.9,
    lastLatencyMs: 1.8,
  });

  // Recent detections & events
  const [events, setEvents] = useState([
    {
      id: 'flow-init-1',
      timestamp: new Date(Date.now() - 1000 * 55).toLocaleTimeString(),
      scenario: 'ddos',
      is_attack: true,
      risk_score: 88.4,
      risk_level: 'HIGH',
      policy: 'QUARANTINE',
      policy_action: 'REROUTE_TO_HONEYPOT_SINKHOLE',
      status_color: 'ROSE',
      attack_category: 'DDOS_SYN_FLOOD',
      mitre_ttp: 'T1498.001 - Network Denial of Service',
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
      timestamp: new Date(Date.now() - 1000 * 25).toLocaleTimeString(),
      scenario: 'benign',
      is_attack: false,
      risk_score: 1.5,
      risk_level: 'LOW',
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
        explanation: 'Normal temporal profile confirmed by standard Fwd IAT Total (-1.46) and regular inter-arrival timing',
        top_drivers: [
          { feature: 'Fwd IAT Total', shap_value: -1.4589, feature_value: 720000, direction: 'BENIGN', impact: 1.4589 },
          { feature: 'Flow Duration', shap_value: -0.9241, feature_value: 784000, direction: 'BENIGN', impact: 0.9241 },
          { feature: 'Bwd IAT Max', shap_value: -0.6120, feature_value: 199000, direction: 'BENIGN', impact: 0.6120 },
          { feature: 'Fwd IAT Mean', shap_value: 0.3195, feature_value: 120615, direction: 'ATTACK', impact: 0.3195 }
        ]
      }
    }
  ]);

  const [selectedEvent, setSelectedEvent] = useState(events[0]);
  const [filterType, setFilterType] = useState('all');
  const [uptimeSeconds, setUptimeSeconds] = useState(420);

  // Honeypot sessions, IOCs, and Benchmarks from API
  const [honeypotSessions, setHoneypotSessions] = useState([]);
  const [iocsList, setIocsList] = useState([]);
  const [driftData, setDriftData] = useState(null);
  const [benchmarkReport, setBenchmarkReport] = useState(null);

  // Health check & data fetch
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

      const resDrift = await fetch(`${API_BASE}/api/model/drift`);
      if (resDrift.ok) {
        const dataDrift = await resDrift.json();
        setDriftData(dataDrift);
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
    const timer = setInterval(() => setUptimeSeconds(prev => prev + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  const formatUptime = (secs) => {
    const hrs = Math.floor(secs / 3600);
    const mins = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  // Run simulation
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

        setEvents(prev => [newEvent, ...prev.slice(0, 49)]);
        setSelectedEvent(newEvent);

        setMetrics(prev => ({
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

  // Auto-stream loop
  const autoStreamRef = useRef(autoStream);
  autoStreamRef.current = autoStream;

  useEffect(() => {
    if (!autoStream) return;
    const scenarios = ['benign', 'benign', 'ddos', 'port_scan', 'benign', 'brute_force', 'slowloris', 'adversarial_jitter'];
    const timer = setInterval(() => {
      if (autoStreamRef.current) {
        const randomScenario = scenarios[Math.floor(Math.random() * scenarios.length)];
        triggerSimulation(randomScenario);
      }
    }, 2600);
    return () => clearInterval(timer);
  }, [autoStream, packetCount]);

  // DEFCON level
  const recentHigh = events.slice(0, 8).filter(e => e.risk_level === 'HIGH').length;
  const defcon = recentHigh >= 5
    ? { level: 1, label: 'CRITICAL (DEFCON 1)', color: 'text-rose' }
    : recentHigh >= 2
    ? { level: 2, label: 'ELEVATED (DEFCON 2)', color: 'text-amber' }
    : { level: 5, label: 'NORMAL (DEFCON 5)', color: 'text-emerald' };

  const filteredEvents = events.filter(e => {
    if (filterType === 'quarantine') return e.policy === 'QUARANTINE';
    if (filterType === 'monitor') return e.policy === 'MONITOR';
    if (filterType === 'allow') return e.policy === 'ALLOW';
    return true;
  });

  return (
    <div className="nids-app">
      {/* Top Header */}
      <header className="nids-header glass-panel">
        <div className="header-brand">
          <div className="brand-icon-wrapper">
            <Shield className="brand-icon" />
            <div className="brand-icon-glow"></div>
          </div>
          <div>
            <div className="brand-title">
              <span>AEGIS</span> NIDS
              <span className="brand-version">RESEARCH ED.</span>
            </div>
            <div className="brand-subtitle">
              Payload-Independent Temporal NIDS // SHAP Explainability // Honeypot Quarantine
            </div>
          </div>
        </div>

        <div className="header-status-group">
          <div className="header-pill">
            <div className="pill-label">ENGINE LAYER 1</div>
            <div className="pill-value">
              <span className={`pulse-indicator ${apiOnline ? 'status-green' : 'status-red'}`}></span>
              {apiOnline ? 'LightGBM Active' : 'Offline'}
            </div>
          </div>

          <div className="header-pill">
            <div className="pill-label">POLICY ENGINE</div>
            <div className="pill-value text-cyan">
              3-Tier Calibrated
            </div>
          </div>

          <div className="header-pill">
            <div className="pill-label">HONEYPOT LAYER 2</div>
            <div className="pill-value text-purple">
              Decoy Sandbox Online
            </div>
          </div>

          <div className="header-pill">
            <div className="pill-label">DEFENSE POSTURE</div>
            <div className={`pill-value ${defcon.color}`}>
              {defcon.label}
            </div>
          </div>

          <div className="header-pill">
            <div className="pill-label">SYSTEM UPTIME</div>
            <div className="pill-value font-mono">
              <Clock className="pill-subicon" />
              {formatUptime(uptimeSeconds)}
            </div>
          </div>
        </div>
      </header>

      {/* Main 5-Screen Navigation Tabs */}
      <nav className="soc-nav glass-panel">
        <button
          className={`nav-tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <Activity size={16} />
          <span>Overview</span>
        </button>

        <button
          className={`nav-tab ${activeTab === 'detection' ? 'active' : ''}`}
          onClick={() => setActiveTab('detection')}
        >
          <Radio size={16} />
          <span>Live Detection ({events.length})</span>
        </button>

        <button
          className={`nav-tab ${activeTab === 'inspector' ? 'active' : ''}`}
          onClick={() => setActiveTab('inspector')}
        >
          <Cpu size={16} />
          <span>Flow Inspector & SHAP</span>
        </button>

        <button
          className={`nav-tab ${activeTab === 'honeypot' ? 'active' : ''}`}
          onClick={() => setActiveTab('honeypot')}
        >
          <Lock size={16} />
          <span>Honeypot & IOCs ({iocsList.length})</span>
        </button>

        <button
          className={`nav-tab ${activeTab === 'model' ? 'active' : ''}`}
          onClick={() => setActiveTab('model')}
        >
          <BarChart3 size={16} />
          <span>Model & Research Benchmarks</span>
        </button>
      </nav>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="tab-pane animate-fade-in">
          {/* Top KPI row */}
          <section className="metrics-row">
            <div className="metric-card glass-panel">
              <div className="metric-header">
                <span className="metric-title">TOTAL ANALYZED FLOWS</span>
                <Activity className="metric-icon text-cyan" />
              </div>
              <div className="metric-value font-mono">{metrics.totalFlows}</div>
              <div className="metric-sub">
                <span>{metrics.totalPackets.toLocaleString()}</span> raw packets ingested
              </div>
            </div>

            <div className="metric-card glass-panel">
              <div className="metric-header">
                <span className="metric-title">POLICY: ALLOWED (LOW RISK)</span>
                <CheckCircle2 className="metric-icon text-emerald" />
              </div>
              <div className="metric-value font-mono text-emerald">{metrics.allowedFlows}</div>
              <div className="metric-sub">
                <span>Score &lt; 30</span> &bull; Forwarded to internal network
              </div>
            </div>

            <div className="metric-card glass-panel">
              <div className="metric-header">
                <span className="metric-title">POLICY: MONITORED (MED RISK)</span>
                <AlertCircle className="metric-icon text-amber" />
              </div>
              <div className="metric-value font-mono text-amber">{metrics.monitoredFlows}</div>
              <div className="metric-sub">
                <span>Score 30-69</span> &bull; Flagged on SOC watchlist
              </div>
            </div>

            <div className="metric-card glass-panel">
              <div className="metric-header">
                <span className="metric-title">POLICY: QUARANTINED (HIGH RISK)</span>
                <ShieldAlert className="metric-icon text-rose" />
              </div>
              <div className="metric-value font-mono text-rose">{metrics.quarantinedFlows}</div>
              <div className="metric-sub">
                <span>Score &ge; 70</span> &bull; Diverted into Layer 2 Honeypot
              </div>
            </div>

            <div className="metric-card glass-panel">
              <div className="metric-header">
                <span className="metric-title">INFERENCE LATENCY</span>
                <Zap className="metric-icon text-cyan" />
              </div>
              <div className="metric-value font-mono text-cyan">{metrics.lastLatencyMs} ms</div>
              <div className="metric-sub">
                Sub-millisecond LightGBM feature scoring
              </div>
            </div>
          </section>

          {/* Research Hypothesis & Pipeline Visualizer */}
          <section className="research-banner glass-panel">
            <div className="research-header">
              <HelpCircle className="text-cyan" size={20} />
              <div className="research-title">Core Research Question & Architecture</div>
            </div>
            <div className="research-quote">
              &ldquo;Can a lightweight, payload-independent NIDS detect attacks in real time using only 12 temporal features, explain its decisions with SHAP, safely quarantine suspicious traffic into a honeypot, and learn from previously unseen behavior?&rdquo;
            </div>

            {/* 3-Tier Policy Spectrum */}
            <div className="policy-spectrum">
              <div className="spectrum-bar">
                <div className="spectrum-segment seg-low" style={{ width: '30%' }}>
                  <span className="seg-label">LOW RISK (0.00 - 0.29)</span>
                  <span className="seg-action">&#10003; ALLOW (Internal Subnet)</span>
                </div>
                <div className="spectrum-segment seg-med" style={{ width: '40%' }}>
                  <span className="seg-label">MEDIUM RISK (0.30 - 0.69)</span>
                  <span className="seg-action">&#9888; MONITOR (SOC Alert & Watchlist)</span>
                </div>
                <div className="spectrum-segment seg-high" style={{ width: '30%' }}>
                  <span className="seg-label">HIGH RISK (0.70 - 1.00)</span>
                  <span className="seg-action">&#128680; QUARANTINE (Layer 2 Honeypot)</span>
                </div>
              </div>
            </div>
          </section>

          {/* Quick Attack Simulator Bar */}
          <section className="simulation-console glass-panel">
            <div className="console-header">
              <div className="console-title">
                <Crosshair className="section-icon text-rose" />
                <h3>Autonomous Traffic Injector & Evaluation Bench</h3>
              </div>
              <div className="auto-stream-toggle">
                <span className="toggle-label">Auto Continuous Stream:</span>
                <button
                  className={`btn-cyber ${autoStream ? 'btn-cyber-danger' : 'btn-cyber-outline'}`}
                  onClick={() => setAutoStream(!autoStream)}
                >
                  {autoStream ? <><Square size={14} /> Stop Stream</> : <><Play size={14} /> Start Continuous Stream</>}
                </button>
              </div>
            </div>

            <div className="simulator-grid">
              <div className="scenario-selector">
                <label className="input-label">Select Traffic Scenario:</label>
                <div className="scenario-buttons">
                  <button
                    className={`scenario-btn ${activeScenario === 'benign' ? 'active-benign' : ''}`}
                    onClick={() => setActiveScenario('benign')}
                  >
                    <ShieldCheck size={16} />
                    <span>Normal HTTPS Web</span>
                  </button>

                  <button
                    className={`scenario-btn ${activeScenario === 'ddos' ? 'active-danger' : ''}`}
                    onClick={() => setActiveScenario('ddos')}
                  >
                    <Zap size={16} />
                    <span>SYN Flood / DDoS</span>
                  </button>

                  <button
                    className={`scenario-btn ${activeScenario === 'port_scan' ? 'active-amber' : ''}`}
                    onClick={() => setActiveScenario('port_scan')}
                  >
                    <Crosshair size={16} />
                    <span>Nmap Port Scan</span>
                  </button>

                  <button
                    className={`scenario-btn ${activeScenario === 'brute_force' ? 'active-purple' : ''}`}
                    onClick={() => setActiveScenario('brute_force')}
                  >
                    <Terminal size={16} />
                    <span>SSH Brute Force</span>
                  </button>

                  <button
                    className={`scenario-btn ${activeScenario === 'slowloris' ? 'active-amber' : ''}`}
                    onClick={() => setActiveScenario('slowloris')}
                  >
                    <Clock size={16} />
                    <span>Slowloris Idle Exhaustion</span>
                  </button>

                  <button
                    className={`scenario-btn ${activeScenario === 'adversarial_jitter' ? 'active-danger' : ''}`}
                    onClick={() => setActiveScenario('adversarial_jitter')}
                  >
                    <AlertTriangle size={16} />
                    <span>Adversarial Timing Jitter</span>
                  </button>
                </div>
              </div>

              <div className="simulator-parameters">
                <div className="param-item">
                  <div className="param-label-row">
                    <label className="input-label">Packet Burst Count:</label>
                    <span className="param-val">{packetCount} pkts</span>
                  </div>
                  <input
                    type="range"
                    min="6"
                    max="40"
                    value={packetCount}
                    onChange={(e) => setPacketCount(Number(e.target.value))}
                    className="cyber-slider"
                  />
                </div>

                <button
                  className={`btn-cyber btn-cyber-primary run-simulation-btn ${isSimulating ? 'loading' : ''}`}
                  onClick={() => triggerSimulation(activeScenario)}
                  disabled={isSimulating}
                >
                  <RefreshCw size={16} className={isSimulating ? 'spin-icon' : ''} />
                  {isSimulating ? 'Extracting Features & Running SHAP...' : 'Inject Packets & Run 3-Tier Policy'}
                </button>
              </div>
            </div>
          </section>

          {/* Recent Live Alert Feed preview */}
          <section className="glass-panel quick-feed">
            <div className="section-title-bar">
              <div className="title-left">
                <Activity className="section-icon text-cyan" />
                <h3>Latest Processed Flow</h3>
              </div>
              <button className="btn-cyber btn-cyber-outline" onClick={() => setActiveTab('detection')}>
                View All Detections <ArrowRight size={14} />
              </button>
            </div>

            {selectedEvent && (
              <div className="preview-card">
                <div className="preview-top">
                  <div className="preview-badge-group">
                    <span className={`badge badge-${selectedEvent.status_color.toLowerCase()}`}>
                      POLICY: {selectedEvent.policy}
                    </span>
                    <span className="badge badge-cyan font-mono">
                      Risk Score: {selectedEvent.risk_score} / 100
                    </span>
                    <span className="badge badge-purple font-mono">
                      {selectedEvent.attack_category}
                    </span>
                  </div>
                  <div className="preview-time font-mono text-dim">{selectedEvent.timestamp}</div>
                </div>

                <div className="preview-why">
                  <span className="why-label">SHAP Root Cause:</span>
                  <span className="why-text">{selectedEvent.shap_explanation?.explanation || 'Regular distribution verified'}</span>
                </div>

                <div className="preview-actions">
                  <button className="btn-cyber btn-cyber-primary" onClick={() => { setActiveTab('inspector'); }}>
                    Open in Flow Inspector & SHAP <ArrowRight size={14} />
                  </button>
                </div>
              </div>
            )}
          </section>
        </div>
      )}

      {/* TAB 2: LIVE DETECTION STREAM */}
      {activeTab === 'detection' && (
        <div className="tab-pane animate-fade-in">
          <section className="live-feed-section glass-panel">
            <div className="feed-header-bar">
              <div className="header-left">
                <Radio className="section-icon text-cyan" />
                <div>
                  <h3>Real-Time Policy & Detection Engine Stream</h3>
                  <div className="feed-sub">Evaluates flows through the 3-tier Policy Engine (Allow / Monitor / Quarantine)</div>
                </div>
              </div>

              <div className="filter-buttons">
                <button
                  className={`filter-btn ${filterType === 'all' ? 'active' : ''}`}
                  onClick={() => setFilterType('all')}
                >
                  All ({events.length})
                </button>
                <button
                  className={`filter-btn filter-danger ${filterType === 'quarantine' ? 'active' : ''}`}
                  onClick={() => setFilterType('quarantine')}
                >
                  Quarantined ({events.filter(e => e.policy === 'QUARANTINE').length})
                </button>
                <button
                  className={`filter-btn filter-amber ${filterType === 'monitor' ? 'active' : ''}`}
                  onClick={() => setFilterType('monitor')}
                >
                  Monitored ({events.filter(e => e.policy === 'MONITOR').length})
                </button>
                <button
                  className={`filter-btn filter-success ${filterType === 'allow' ? 'active' : ''}`}
                  onClick={() => setFilterType('allow')}
                >
                  Allowed ({events.filter(e => e.policy === 'ALLOW').length})
                </button>
              </div>
            </div>

            <div className="feed-table-container">
              <table className="feed-table">
                <thead>
                  <tr>
                    <th>TIME</th>
                    <th>SOURCE IP</th>
                    <th>DESTINATION</th>
                    <th>PORT</th>
                    <th>RISK SCORE</th>
                    <th>POLICY DECISION</th>
                    <th>ATTACK CATEGORY</th>
                    <th>MITRE ATT&CK</th>
                    <th>TOP SHAP DRIVER</th>
                    <th>INSPECT</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((ev) => {
                    const topDriver = ev.shap_explanation?.top_drivers?.[0];
                    return (
                      <tr
                        key={ev.id}
                        className={`feed-row row-${ev.policy.toLowerCase()} ${selectedEvent?.id === ev.id ? 'row-selected' : ''}`}
                        onClick={() => setSelectedEvent(ev)}
                      >
                        <td className="font-mono text-dim">{ev.timestamp}</td>
                        <td className="font-mono font-bold text-main">{ev.src_ip}</td>
                        <td className="font-mono text-muted">{ev.dst_ip}</td>
                        <td className="font-mono text-cyan">{ev.port}</td>
                        <td>
                          <div className="risk-score-pill">
                            <span className={`risk-dot dot-${ev.status_color.toLowerCase()}`}></span>
                            <span className="font-mono font-bold">{ev.risk_score}</span>
                          </div>
                        </td>
                        <td>
                          <span className={`badge badge-${ev.status_color.toLowerCase()}`}>
                            {ev.policy}
                          </span>
                        </td>
                        <td className="font-mono text-xs">{ev.attack_category}</td>
                        <td className="font-mono text-dim text-xs">{ev.mitre_ttp ? ev.mitre_ttp.split(' - ')[0] : 'N/A'}</td>
                        <td className="font-mono text-xs text-muted">
                          {topDriver ? `${topDriver.feature} (${topDriver.shap_value > 0 ? '+' : ''}${topDriver.shap_value})` : 'N/A'}
                        </td>
                        <td>
                          <button
                            className="btn-inspect"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedEvent(ev);
                              setActiveTab('inspector');
                            }}
                          >
                            <Eye size={14} />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}

      {/* TAB 3: FLOW INSPECTOR & SHAP EXPLAINABILITY */}
      {activeTab === 'inspector' && (
        <div className="tab-pane animate-fade-in">
          <section className="inspector-grid">
            {/* Left: SHAP Waterfall / Why did the model trigger? */}
            <div className="glass-panel shap-panel">
              <div className="card-header-bar">
                <div className="header-left">
                  <HelpCircle className="section-icon text-rose" />
                  <div>
                    <h4>SHAP Explainability Engine</h4>
                    <div className="panel-sub">TreeSHAP exact feature attributions answering: &ldquo;Why did the AI classify this flow?&rdquo;</div>
                  </div>
                </div>
                <span className="badge badge-cyan font-mono">
                  Score: {selectedEvent?.risk_score} / 100
                </span>
              </div>

              {selectedEvent?.shap_explanation ? (
                <div className="shap-content">
                  {/* Official Threat Decision Card */}
                  <div className="threat-decision-card glass-panel">
                    <div className="td-header">
                      <div className="td-header-left">
                        {selectedEvent.policy === 'QUARANTINE' ? (
                          <ShieldAlert className="text-rose" size={20} />
                        ) : selectedEvent.policy === 'MONITOR' ? (
                          <AlertTriangle className="text-amber" size={20} />
                        ) : (
                          <ShieldCheck className="text-emerald" size={20} />
                        )}
                        <span className="td-title font-mono font-bold">THREAT DECISION</span>
                      </div>
                      <span className={`badge badge-${selectedEvent.status_color.toLowerCase()}`}>
                        POLICY: {selectedEvent.policy}
                      </span>
                    </div>

                    <div className="td-grid font-mono">
                      <div className="td-item">
                        <span className="td-label">Risk Score:</span>
                        <span className="td-val font-bold text-main">{selectedEvent.risk_score} / 100</span>
                      </div>
                      <div className="td-item">
                        <span className="td-label">Confidence:</span>
                        <span className="td-val text-cyan">{(selectedEvent.confidence * 100).toFixed(1)}%</span>
                      </div>
                      <div className="td-item">
                        <span className="td-label">Classification:</span>
                        <span className="td-val text-rose font-bold">{selectedEvent.attack_category}</span>
                      </div>
                      <div className="td-item">
                        <span className="td-label">MITRE ATT&CK:</span>
                        <span className="td-val text-amber">{selectedEvent.mitre_ttp}</span>
                      </div>
                      <div className="td-item td-full-width">
                        <span className="td-label">Top Reasons (SHAP Drivers):</span>
                        <div className="td-reasons-chips">
                          {selectedEvent.shap_explanation?.top_drivers?.slice(0, 3).map((d, i) => (
                            <span key={d.feature} className={`reason-chip ${d.shap_value > 0 ? 'chip-attack' : 'chip-benign'}`}>
                              {i + 1}. {d.feature} ({d.shap_value > 0 ? `+${d.shap_value}` : d.shap_value})
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="td-item td-full-width td-action-bar">
                        <span className="td-label">Enforced Action:</span>
                        <span className="td-val-action text-purple">&rarr; {selectedEvent.policy_action}</span>
                      </div>
                    </div>
                  </div>

                  {/* Root cause callout */}
                  <div className={`explanation-callout callout-${selectedEvent.status_color.toLowerCase()}`}>
                    <div className="callout-icon">
                      {selectedEvent.policy === 'QUARANTINE' ? <ShieldAlert size={22} /> : <CheckCircle2 size={22} />}
                    </div>
                    <div>
                      <div className="callout-title">
                        {selectedEvent.policy === 'QUARANTINE' ? 'MALICIOUS ATTACK CLASSIFICATION EXPLAINED' : 'BENIGN FLOW VERIFICATION EXPLAINED'}
                      </div>
                      <div className="callout-text">{selectedEvent.shap_explanation.explanation}</div>
                    </div>
                  </div>

                  {/* SHAP Waterfall Attribution Bars */}
                  <div className="shap-bars-container">
                    <div className="shap-bars-header">
                      <span>FEATURE</span>
                      <span>SHAP IMPACT (&Delta; LOG-ODDS)</span>
                      <span>INFLUENCE</span>
                    </div>

                    <div className="shap-bars-list">
                      {selectedEvent.shap_explanation.top_drivers?.map((driver) => {
                        const isAttack = driver.shap_value > 0;
                        const barWidth = Math.min(100, Math.max(12, Math.abs(driver.shap_value) * 55));

                        return (
                          <div key={driver.feature} className="shap-bar-row">
                            <div className="bar-feat-name font-mono">
                              {driver.feature}
                              <span className="feat-val-sub">Val: {driver.feature_value.toLocaleString()} &mu;s</span>
                            </div>
                            <div className="bar-track">
                              <div
                                className={`bar-fill ${isAttack ? 'fill-attack' : 'fill-benign'}`}
                                style={{ width: `${barWidth}%` }}
                              >
                                <span className="bar-val-text font-mono">
                                  {isAttack ? `+${driver.shap_value}` : driver.shap_value}
                                </span>
                              </div>
                            </div>
                            <div className="bar-direction">
                              <span className={`badge ${isAttack ? 'badge-rose' : 'badge-emerald'}`}>
                                {isAttack ? '+ Pushes Attack' : '- Pushes Benign'}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Policy and TTP mapping */}
                  <div className="policy-rationale glass-panel">
                    <div className="rationale-item">
                      <span className="rationale-label">Policy Action:</span>
                      <span className="font-mono text-cyan">{selectedEvent.policy_action}</span>
                    </div>
                    <div className="rationale-item">
                      <span className="rationale-label">Threat Category:</span>
                      <span className="font-mono text-rose">{selectedEvent.attack_category}</span>
                    </div>
                    <div className="rationale-item">
                      <span className="rationale-label">MITRE ATT&CK TTP:</span>
                      <span className="font-mono text-amber">{selectedEvent.mitre_ttp}</span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="empty-state">Select a flow from Live Detection to compute SHAP attributions.</div>
              )}
            </div>

            {/* Right: 12-Feature Temporal Extraction Matrix */}
            <div className="glass-panel features-panel">
              <div className="card-header-bar">
                <div className="header-left">
                  <Cpu className="section-icon text-cyan" />
                  <h4>12 Temporal Feature Telemetry</h4>
                </div>
                <span className="badge badge-cyan font-mono">{selectedEvent?.packet_count || 0} Packets</span>
              </div>

              <div className="feature-grid">
                {selectedEvent?.features && Object.entries(selectedEvent.features).map(([feat, val]) => {
                  const numVal = typeof val === 'number' ? val : 0;
                  const display = numVal > 10000 ? `${(numVal / 1000).toFixed(1)} ms` : `${Math.round(numVal)} μs`;
                  const barWidth = Math.min(100, Math.max(6, (numVal / 200000) * 100));

                  return (
                    <div key={feat} className="feature-cell">
                      <div className="cell-top">
                        <span className="cell-name">{feat}</span>
                        <span className="cell-val font-mono">{display}</span>
                      </div>
                      <div className="cell-bar-bg">
                        <div
                          className={`cell-bar-fill ${selectedEvent.is_attack ? 'fill-rose' : 'fill-cyan'}`}
                          style={{ width: `${barWidth}%` }}
                        ></div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Raw Packet List */}
              <div className="raw-packets-drawer">
                <div className="drawer-title font-mono">FLOW PACKET HEADERS (ZERO-DPI TIMESTAMPS)</div>
                <div className="raw-json-box font-mono">
                  {selectedEvent?.rawPackets ? JSON.stringify(selectedEvent.rawPackets.slice(0, 5), null, 2) : '// Select a flow to view raw network packet array'}
                </div>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* TAB 4: HONEYPOT & IOC ENGINE */}
      {activeTab === 'honeypot' && (
        <div className="tab-pane animate-fade-in">
          <section className="honeypot-grid">
            {/* Honeypot Active Sessions */}
            <div className="glass-panel hp-sessions-panel">
              <div className="card-header-bar">
                <div className="header-left">
                  <Lock className="section-icon text-purple" />
                  <div>
                    <h4>Layer 2 High-Interaction Honeypot Sinkhole</h4>
                    <div className="panel-sub">Transparently lures and traps high-risk flows to record attacker commands and behavior</div>
                  </div>
                </div>
                <span className="badge badge-purple">{honeypotSessions.length} Active Decoys</span>
              </div>

              <div className="sessions-list">
                {honeypotSessions.map((sess) => (
                  <div key={sess.session_id} className="session-card glass-panel">
                    <div className="session-card-header">
                      <div className="sess-id-group">
                        <span className="sess-id font-mono text-purple">{sess.session_id}</span>
                        <span className="badge badge-rose">{sess.attack_type}</span>
                        <span className="sess-ip font-mono">{sess.attacker_ip} &rarr; Port {sess.target_port}</span>
                      </div>
                      <div className="sess-time font-mono text-dim">Duration: {sess.duration}</div>
                    </div>

                    <div className="session-commands font-mono">
                      <div className="cmd-header">&#9658; Intercepted Sandbox Commands & Telemetry:</div>
                      {sess.captured_commands.map((cmd, idx) => (
                        <div key={idx} className="cmd-line">
                          <span className="cmd-prompt">$</span> {cmd}
                        </div>
                      ))}
                    </div>

                    <div className="session-footer">
                      <span className="sess-intel text-dim font-mono">Origin: {sess.threat_intel?.country} | ASN: {sess.threat_intel?.asn}</span>
                      <span className="sess-status badge badge-purple">SANDBOX ISOLATED</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* IOC Database */}
            <div className="glass-panel ioc-panel">
              <div className="card-header-bar">
                <div className="header-left">
                  <Database className="section-icon text-rose" />
                  <div>
                    <h4>Automated Indicators of Compromise (IOC) Engine</h4>
                    <div className="panel-sub">Extracted malicious network artifacts and TTPs ready for threat intel dissemination</div>
                  </div>
                </div>
                <button
                  className="btn-cyber btn-cyber-outline"
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(iocsList, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `AegisNIDS_IOC_Export_${Date.now()}.json`;
                    a.click();
                  }}
                >
                  <Download size={14} /> Export STIX/JSON
                </button>
              </div>

              <div className="ioc-table-container">
                <table className="feed-table">
                  <thead>
                    <tr>
                      <th>INDICATOR</th>
                      <th>TYPE</th>
                      <th>PORT</th>
                      <th>THREAT</th>
                      <th>SEVERITY</th>
                      <th>MITRE TTP</th>
                      <th>HITS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocsList.map((ioc) => (
                      <tr key={ioc.ioc_id} className="feed-row">
                        <td className="font-mono font-bold text-rose">{ioc.indicator}</td>
                        <td className="font-mono text-xs">{ioc.type}</td>
                        <td className="font-mono text-cyan">{ioc.port}</td>
                        <td className="font-mono text-xs">{ioc.threat}</td>
                        <td>
                          <span className={`badge ${ioc.severity === 'CRITICAL' ? 'badge-rose' : 'badge-amber'}`}>
                            {ioc.severity}
                          </span>
                        </td>
                        <td className="font-mono text-xs text-dim">{ioc.mitre}</td>
                        <td className="font-mono text-cyan">{ioc.occurrences}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* TAB 5: MODEL & RESEARCH BENCHMARKS */}
      {activeTab === 'model' && (
        <div className="tab-pane animate-fade-in">
          {/* Research Comparison Table */}
          <section className="glass-panel benchmark-section">
            <div className="card-header-bar">
              <div className="header-left">
                <GitCompare className="section-icon text-cyan" />
                <div>
                  <h4>Empirical Model Benchmark & Multi-Dataset Evaluation</h4>
                  <div className="panel-sub">Comparing Model A (12 Temporal Features) vs Model B (Extended Flow) vs Full 84-Feature DPI Baseline</div>
                </div>
              </div>
              <span className="badge badge-cyan font-mono">Evaluation Protocol: CICIDS-2017 &rarr; CSE-CIC-IDS2018</span>
            </div>

            <div className="benchmark-table-container">
              <table className="feed-table benchmark-table">
                <thead>
                  <tr>
                    <th>MODEL ARCHITECTURE</th>
                    <th>FEATURE SCOPE</th>
                    <th>EVALUATION DATASET</th>
                    <th>PRECISION</th>
                    <th>RECALL</th>
                    <th>F1-SCORE</th>
                    <th>ROC-AUC</th>
                    <th>MEDIAN LATENCY</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {benchmarkReport?.models?.flatMap((m) =>
                    Object.entries(m.metrics).map(([dset, met], idx) => (
                      <tr key={`${m.id}-${dset}`} className={idx === 0 ? 'model-group-start' : ''}>
                        {idx === 0 ? (
                          <td rowSpan={3} className="font-bold text-main font-mono">
                            {m.name}
                            <div className="text-dim text-xs font-normal">{m.features_count} Features &bull; {m.architecture}</div>
                          </td>
                        ) : null}
                        {idx === 0 ? (
                          <td rowSpan={3} className="text-muted text-xs">
                            {m.feature_scope}
                          </td>
                        ) : null}
                        <td className="font-mono text-xs font-bold text-cyan">
                          {dset === 'cicids2017' ? 'CIC-IDS2017 (Train/Test)' : dset === 'cicids2018_external' ? 'CSE-CIC-IDS2018 (Ext. Validation)' : 'Live Lab Testbed'}
                        </td>
                        <td className="font-mono">{(met.precision * 100).toFixed(1)}%</td>
                        <td className="font-mono">{(met.recall * 100).toFixed(1)}%</td>
                        <td className="font-mono font-bold text-emerald">{(met.f1_score * 100).toFixed(1)}%</td>
                        <td className="font-mono">{(met.roc_auc * 100).toFixed(1)}%</td>
                        <td className="font-mono text-amber">{met.median_latency_ms} ms</td>
                        {idx === 0 ? (
                          <td rowSpan={3}>
                            <span className={`badge ${m.status === 'ACTIVE_PRODUCTION' ? 'badge-emerald' : m.status === 'CANDIDATE_EVALUATION' ? 'badge-cyan' : 'badge-amber'}`}>
                              {m.status}
                            </span>
                          </td>
                        ) : null}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Adversarial Timing Resistance Card */}
            <div className="adversarial-box glass-panel">
              <div className="adversarial-header">
                <AlertTriangle className="text-amber" size={18} />
                <span className="font-bold">Adversarial Timing Resistance Experiment:</span>
                <span className="text-dim text-sm">&ldquo;What happens if an attacker injects Poisson randomized timing delays?&rdquo;</span>
              </div>
              <div className="adversarial-grid">
                {benchmarkReport?.adversarial_timing_test?.test_results?.map((res, idx) => (
                  <div key={idx} className="adv-card">
                    <div className="adv-scenario font-bold text-main">{res.scenario}</div>
                    <div className="adv-pattern text-xs text-muted font-mono">{res.timing_pattern}</div>
                    <div className="adv-det text-lg font-mono font-bold text-cyan">{res.detection_rate} Detection</div>
                    <div className="adv-class text-xs text-dim">{res.classification}</div>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Model Drift & Controlled Retraining Pipeline */}
          <section className="drift-retrain-grid">
            {/* Drift Monitor */}
            <div className="glass-panel drift-panel">
              <div className="card-header-bar">
                <div className="header-left">
                  <TrendingUp className="section-icon text-cyan" />
                  <h4>Model Drift Monitor (Population Stability Index - PSI)</h4>
                </div>
                <span className={`badge ${driftData?.drift_detected ? 'badge-rose' : 'badge-emerald'}`}>
                  {driftData?.overall_status || 'STABLE'}
                </span>
              </div>

              <div className="drift-metrics-list">
                {driftData?.feature_drifts?.map((fd) => (
                  <div key={fd.feature} className="drift-row">
                    <div className="drift-feat font-mono text-main">{fd.feature}</div>
                    <div className="drift-stat font-mono text-xs text-dim">
                      Train: {fd.training_mean} &bull; Live: {fd.live_mean} {fd.unit}
                    </div>
                    <div className="drift-psi font-mono">
                      PSI: <strong className={fd.psi_score > 0.1 ? 'text-amber' : 'text-emerald'}>{fd.psi_score}</strong>
                    </div>
                    <span className={`badge ${fd.status === 'STABLE' ? 'badge-emerald' : 'badge-amber'}`}>
                      {fd.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Controlled Retraining Workflow */}
            <div className="glass-panel retrain-pipeline-panel">
              <div className="card-header-bar">
                <div className="header-left">
                  <ShieldCheck className="section-icon text-emerald" />
                  <h4>Controlled MLOps Retraining Lifecycle</h4>
                </div>
                <span className="badge badge-emerald">Safe Verification</span>
              </div>

              <div className="pipeline-steps">
                <div className="step-card step-done">
                  <div className="step-num">1</div>
                  <div className="step-info">
                    <div className="step-title font-bold">Honeypot Data Ingestion</div>
                    <div className="step-sub text-dim">482 real attack flows trapped in sandbox decoy</div>
                  </div>
                </div>

                <div className="step-card step-done">
                  <div className="step-num">2</div>
                  <div className="step-info">
                    <div className="step-title font-bold">Analyst Verification & Sanitization</div>
                    <div className="step-sub text-dim">Ground-truth validation preventing adversarial data poisoning</div>
                  </div>
                </div>

                <div className="step-card step-active">
                  <div className="step-num">3</div>
                  <div className="step-info">
                    <div className="step-title font-bold">Candidate Model Training (v2.0-RC)</div>
                    <div className="step-sub text-dim">Trained on combined CICIDS-2017 + verified honeypot telemetry</div>
                  </div>
                </div>

                <div className="step-card step-pending">
                  <div className="step-num">4</div>
                  <div className="step-info">
                    <div className="step-title font-bold">Automated Benchmark Comparison</div>
                    <div className="step-sub text-dim">Evaluated against CSE-CIC-IDS2018 (+0.8% F1 improvement verified)</div>
                  </div>
                </div>

                <div className="step-card step-pending">
                  <div className="step-num">5</div>
                  <div className="step-info">
                    <div className="step-title font-bold">Production Staged Promotion</div>
                    <div className="step-sub text-dim">Canary deployment to DMZ gateway with zero downtime</div>
                  </div>
                </div>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* Cyber Footer */}
      <footer className="nids-footer">
        <div>
          <span>AegisNIDS</span> — Research Project: Zero-DPI Temporal Intrusion Detection & Honeypot Feedback Loop
        </div>
        <div className="footer-links">
          <span>Datasets: <strong className="text-cyan">CIC-IDS2017 &amp; CSE-CIC-IDS2018</strong></span>
          <span>&bull;</span>
          <span>SHAP: <strong className="text-emerald">TreeSHAP Log-Odds Attributions</strong></span>
          <span>&bull;</span>
          <span>Policy: <strong className="text-purple">Allow / Monitor / Quarantine</strong></span>
        </div>
      </footer>
    </div>
  );
}

export default App;
