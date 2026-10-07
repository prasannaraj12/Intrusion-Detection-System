import React, { useState } from 'react';
import {
  Database,
  X,
  Terminal,
  ArrowRight
} from 'lucide-react';

export default function HoneypotView({ honeypotSessions, iocsList, onNavigateTo }) {
  const [selectedSession, setSelectedSession] = useState(null);

  return (
    <div className="honeypot-page">
      {/* 1. Header */}
      <section className="page-header-row">
        <div>
          <h1 className="page-title">Honeypot Operations</h1>
          <p className="page-subtitle">
            Layer 2 high-interaction sinkhole decoys containing quarantined adversaries
          </p>
        </div>
        <div className="honeypot-metrics-top font-mono">
          <div className="hp-stat-badge">
            <span className="hp-stat-label">Active Sessions:</span>
            <span className="hp-stat-val text-purple">{honeypotSessions.length}</span>
          </div>
          <div className="hp-stat-badge">
            <span className="hp-stat-label">Captured IOCs:</span>
            <span className="hp-stat-val text-rose">{iocsList.length}</span>
          </div>
        </div>
      </section>

      {/* 2. Session Table */}
      <div className="section-card">
        <div className="card-header-bar">
          <div className="card-title">Decoy Quarantine Sessions</div>
          <span className="card-caption">Click a session to inspect forensic telemetry</span>
        </div>

        <div className="table-responsive">
          <table className="clean-data-table">
            <thead>
              <tr>
                <th>SESSION</th>
                <th>SOURCE</th>
                <th>ATTACK TYPE</th>
                <th>STATUS</th>
                <th>STARTED</th>
                <th style={{ textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {honeypotSessions.length === 0 ? (
                <tr>
                  <td colSpan={6} className="table-empty-row">
                    No active honeypot sessions recorded.
                  </td>
                </tr>
              ) : (
                honeypotSessions.map((sess) => (
                  <tr
                    key={sess.session_id}
                    className={`honeypot-row ${selectedSession?.session_id === sess.session_id ? 'row-active' : ''}`}
                    onClick={() => setSelectedSession(sess)}
                  >
                    <td className="font-mono font-bold text-purple">{sess.session_id}</td>
                    <td className="font-mono font-bold text-main">
                      {sess.attacker_ip} &rarr; :{sess.target_port}
                    </td>
                    <td>
                      <span className="badge-severity badge-rose">{sess.attack_type}</span>
                    </td>
                    <td>
                      <span className="policy-badge badge-quarantine">
                        {sess.status || 'QUARANTINED'}
                      </span>
                    </td>
                    <td className="font-mono text-muted">{sess.start_time || 'Recent'}</td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn-table-investigate"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedSession(sess);
                        }}
                      >
                        Inspect Telemetry <ArrowRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 3. Detail Drawer (Progressive Disclosure) */}
      {selectedSession && (
        <div className="drawer-overlay" onClick={() => setSelectedSession(null)}>
          <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-header">
              <div>
                <span className="drawer-sub font-mono text-purple">SESSION FORENSICS</span>
                <h2 className="drawer-title font-mono">{selectedSession.session_id}</h2>
              </div>
              <button className="btn-drawer-close" onClick={() => setSelectedSession(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="drawer-body">
              {/* Session Overview */}
              <div className="drawer-section">
                <h4 className="drawer-section-title">Session Overview</h4>
                <div className="drawer-grid">
                  <div className="drawer-meta-item">
                    <span className="dm-label">Attacker IP</span>
                    <span className="dm-val font-mono">{selectedSession.attacker_ip}</span>
                  </div>
                  <div className="drawer-meta-item">
                    <span className="dm-label">Target Port</span>
                    <span className="dm-val font-mono">{selectedSession.target_port}</span>
                  </div>
                  <div className="drawer-meta-item">
                    <span className="dm-label">Attack Type</span>
                    <span className="dm-val font-mono text-rose">{selectedSession.attack_type}</span>
                  </div>
                  <div className="drawer-meta-item">
                    <span className="dm-label">Origin / ASN</span>
                    <span className="dm-val font-mono text-muted">
                      {selectedSession.threat_intel?.country || 'US'} · {selectedSession.threat_intel?.asn || 'AS41217'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Intercepted Commands & Telemetry */}
              <div className="drawer-section">
                <h4 className="drawer-section-title">Captured Telemetry & Commands</h4>
                <div className="terminal-box font-mono">
                  <div className="terminal-bar">
                    <Terminal size={13} />
                    <span>Decoy Sandbox Audit Log</span>
                  </div>
                  <div className="terminal-lines">
                    {selectedSession.captured_commands?.map((cmd, idx) => (
                      <div key={idx} className="terminal-line">
                        <span className="term-prompt">$</span> {cmd}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Captured Indicators */}
              <div className="drawer-section">
                <h4 className="drawer-section-title">Captured Indicators</h4>
                <div className="captured-indicators-card font-mono">
                  <div className="cap-ind-row">
                    <span className="text-muted">Extracted IPv4:</span>
                    <span className="text-cyan font-bold">{selectedSession.attacker_ip}</span>
                  </div>
                  <div className="cap-ind-row">
                    <span className="text-muted">MITRE Alignment:</span>
                    <span className="text-amber">{selectedSession.mitre_ttp || 'T1498.001'}</span>
                  </div>
                  <div className="cap-ind-row">
                    <span className="text-muted">Decoy Protocol:</span>
                    <span>{selectedSession.protocol || 'TCP/80'}</span>
                  </div>
                </div>
              </div>

              {/* STIX & Intelligence Action */}
              <div className="drawer-section">
                <button
                  className="btn-primary w-full"
                  onClick={() => {
                    setSelectedSession(null);
                    onNavigateTo('intelligence');
                  }}
                >
                  <Database size={14} /> View in STIX 2.1 Intelligence &rarr;
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
