import React from 'react';
import {
  Server,
  Cpu,
  Clock,
  Lock
} from 'lucide-react';

export default function SystemView({ apiOnline, modelInfo, uptimeSeconds }) {
  const formatUptime = (secs) => {
    const hrs = Math.floor(secs / 3600);
    const mins = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  return (
    <div className="system-page">
      {/* 1. Header */}
      <section className="page-header-row">
        <div>
          <h1 className="page-title">System Status & Configuration</h1>
          <p className="page-subtitle">
            Health telemetry for ML inference engines, honeypot daemons, and security policies
          </p>
        </div>
      </section>

      {/* 2. Services Overview Cards */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Flask API</span>
            <Server size={16} className={apiOnline ? 'text-emerald' : 'text-rose'} />
          </div>
          <div className={`kpi-value font-mono ${apiOnline ? 'text-emerald' : 'text-rose'}`}>
            {apiOnline ? 'ONLINE' : 'OFFLINE'}
          </div>
          <div className="kpi-footer font-mono">Port 5000 · HTTP/REST</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Active Model</span>
            <Cpu size={16} className="text-cyan" />
          </div>
          <div className="kpi-value font-mono text-cyan">Aegis-v1.4</div>
          <div className="kpi-footer">LightGBM (12 Features)</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Honeypot Sandbox</span>
            <Lock size={16} className="text-purple" />
          </div>
          <div className="kpi-value font-mono text-purple">ACTIVE</div>
          <div className="kpi-footer">Layer 2 Decoy Deployed</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">System Uptime</span>
            <Clock size={16} className="text-muted" />
          </div>
          <div className="kpi-value font-mono">{formatUptime(uptimeSeconds)}</div>
          <div className="kpi-footer">Running continuously</div>
        </div>
      </div>

      {/* 3. Detailed Component Diagnostics */}
      <div className="overview-split-row">
        <div className="section-card">
          <div className="card-header-bar">
            <div className="card-title">Detection Engine Diagnostics</div>
          </div>

          <div className="system-specs-list font-mono">
            <div className="spec-item">
              <span className="spec-label">Model Architecture:</span>
              <span className="spec-val">LightGBM Gradient Boosted Trees</span>
            </div>
            <div className="spec-item">
              <span className="spec-label">Model File:</span>
              <span className="spec-val truncate max-w-xs">model.pkl (352 KB)</span>
            </div>
            <div className="spec-item">
              <span className="spec-label">Feature Input Dimensionality:</span>
              <span className="spec-val text-cyan">12 Temporal Features</span>
            </div>
            <div className="spec-item">
              <span className="spec-label">Explainability Method:</span>
              <span className="spec-val text-emerald">Native TreeSHAP (&lt;0.5 ms)</span>
            </div>
            <div className="spec-item">
              <span className="spec-label">Payload Inspection Requirement:</span>
              <span className="spec-val text-emerald">ZERO (Payload Independent)</span>
            </div>
          </div>
        </div>

        <div className="section-card">
          <div className="card-header-bar">
            <div className="card-title">Three-Tier Policy Engine Boundaries</div>
          </div>

          <div className="system-specs-list font-mono">
            <div className="spec-item">
              <span className="spec-label">ALLOW Boundary:</span>
              <span className="spec-val text-emerald">P(Attack) &lt; 0.20 (Score &lt; 30)</span>
            </div>
            <div className="spec-item">
              <span className="spec-label">MONITOR Boundary:</span>
              <span className="spec-val text-amber">0.20 &le; P(Attack) &lt; 0.75 (Score 30-69)</span>
            </div>
            <div className="spec-item">
              <span className="spec-label">QUARANTINE Boundary:</span>
              <span className="spec-val text-rose">P(Attack) &ge; 0.75 (Score &ge; 70)</span>
            </div>
            <div className="spec-item">
              <span className="spec-label">Threat Intel Format:</span>
              <span className="spec-val text-purple">OASIS STIX 2.1 JSON Schema</span>
            </div>
            <div className="spec-item">
              <span className="spec-label">Flow Key Timeout:</span>
              <span className="spec-val">5.0 seconds (canonical)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
