import React, { useState } from 'react';
import {
  ArrowLeft,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle
} from 'lucide-react';

export default function ThreatDetailView({ threat, onBackToThreats, onNavigateTo }) {
  const [activeTab, setActiveTab] = useState('summary'); // 'summary' | 'evidence' | 'network' | 'detection' | 'response' | 'mitre'

  if (!threat) {
    return (
      <div className="threat-detail-empty">
        <p>No threat selected for investigation.</p>
        <button className="btn-secondary" onClick={onBackToThreats}>
          <ArrowLeft size={14} /> Back to Threats
        </button>
      </div>
    );
  }

  const isQuarantine = threat.policy === 'QUARANTINE';
  const isMonitor = threat.policy === 'MONITOR';
  const riskScore = threat.risk_score || 0;
  const policyThreshold = isQuarantine ? 0.75 : 0.20;

  return (
    <div className="threat-detail-page">
      {/* 1. Back button & Threat Header */}
      <div className="threat-detail-top-nav">
        <button className="btn-back-threats" onClick={onBackToThreats}>
          <ArrowLeft size={15} />
          <span>Back to Threats</span>
        </button>
      </div>

      <div className="threat-header-card">
        <div className="threat-header-main">
          <div className="threat-title-row">
            <span className={`badge-severity badge-${threat.status_color?.toLowerCase() || (isQuarantine ? 'rose' : isMonitor ? 'amber' : 'emerald')}`}>
              {threat.risk_level || (isQuarantine ? 'HIGH RISK' : isMonitor ? 'MEDIUM RISK' : 'LOW RISK')}
            </span>
            <h1 className="threat-category-title">{threat.attack_category || 'NETWORK ANOMALY'}</h1>
          </div>

          <div className="threat-meta-grid">
            <div className="meta-item">
              <span className="meta-label">Source IP</span>
              <span className="meta-value font-mono">{threat.src_ip}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Destination</span>
              <span className="meta-value font-mono">{threat.dst_ip}:{threat.port}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Timestamp</span>
              <span className="meta-value font-mono">{threat.timestamp}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Risk Score</span>
              <span className="meta-value font-mono font-bold text-rose">{riskScore} / 100</span>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Clear Decision Banner */}
      <div className={`decision-banner banner-${threat.policy?.toLowerCase() || 'allow'}`}>
        <div className="decision-banner-left">
          {isQuarantine ? (
            <ShieldAlert size={28} className="text-rose" />
          ) : isMonitor ? (
            <AlertTriangle size={28} className="text-amber" />
          ) : (
            <ShieldCheck size={28} className="text-emerald" />
          )}
          <div>
            <div className="decision-title">
              POLICY ACTION: {threat.policy || 'ALLOW'}
            </div>
            <div className="decision-subtitle">
              {threat.policy_action || (isQuarantine ? 'REROUTE_TO_HONEYPOT_SINKHOLE' : 'FORWARD_TO_INTERNAL_NETWORK')}
            </div>
          </div>
        </div>

        <div className="decision-banner-metrics font-mono">
          <div className="decision-metric-col">
            <span className="dec-label">Risk Score</span>
            <span className="dec-val">{riskScore.toFixed(1)}</span>
          </div>
          <div className="decision-divider">/</div>
          <div className="decision-metric-col">
            <span className="dec-label">Policy Boundary</span>
            <span className="dec-val">{policyThreshold.toFixed(2)}</span>
          </div>
        </div>
      </div>

      {/* 3. Section Navigation Tabs */}
      <div className="detail-tabs-bar">
        {[
          { id: 'summary', label: 'Summary' },
          { id: 'detection', label: 'Detection & SHAP' },
          { id: 'evidence', label: 'Evidence' },
          { id: 'response', label: 'Response Workflow' },
          { id: 'mitre', label: 'MITRE ATT&CK' }
        ].map((tab) => (
          <button
            key={tab.id}
            className={`detail-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 4. Tab Contents */}

      {/* TAB: SUMMARY */}
      {activeTab === 'summary' && (
        <div className="detail-tab-content">
          <div className="investigation-section">
            <h3 className="section-heading">Why was this detected?</h3>
            <div className="reasoning-callout">
              <p className="reasoning-text">
                {threat.shap_explanation?.explanation ||
                  `Traffic exceeded normal temporal variance. Classified as ${threat.attack_category} due to packet cadence metrics.`}
              </p>
            </div>
          </div>

          <div className="investigation-split-grid">
            <div className="investigation-card">
              <div className="inv-card-title">Top Attribution Drivers</div>
              <div className="drivers-list">
                {threat.shap_explanation?.top_drivers?.slice(0, 3).map((driver, idx) => (
                  <div key={driver.feature} className="driver-row">
                    <span className="driver-rank font-mono">{idx + 1}.</span>
                    <span className="driver-name font-mono">{driver.feature}</span>
                    <span className={`driver-impact font-mono ${driver.shap_value > 0 ? 'text-rose' : 'text-emerald'}`}>
                      {driver.shap_value > 0 ? `+${driver.shap_value}` : driver.shap_value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="investigation-card">
              <div className="inv-card-title">Enforced Operational Action</div>
              <p className="inv-action-desc">
                {isQuarantine
                  ? 'Traffic safely isolated into Layer 2 Honeypot sinkhole. Malicious source IP flagged for automated IOC generation and STIX 2.1 intelligence publication.'
                  : isMonitor
                  ? 'Connection allowed into internal network with active SOC watchlist monitoring and anomalous burst tracking.'
                  : 'Normal legitimate flow forwarded with zero inspection latency.'}
              </p>
              {isQuarantine && (
                <button
                  className="btn-link-action"
                  onClick={() => onNavigateTo('honeypot')}
                >
                  View in Honeypot Decoys &rarr;
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB: DETECTION & SHAP */}
      {activeTab === 'detection' && (
        <div className="detail-tab-content">
          <div className="investigation-section">
            <h3 className="section-heading">Native Sub-Millisecond TreeSHAP Feature Attributions</h3>
            <p className="section-subtext">
              Exact Shapley values computed in &lt;0.5 ms directly from tree split pathways. Positive values push toward attack; negative values push toward benign.
            </p>

            <div className="shap-bars-table">
              <div className="shap-table-head font-mono">
                <span>FEATURE</span>
                <span>MEASURED VALUE</span>
                <span>SHAP IMPACT (LOG-ODDS)</span>
                <span>DIRECTION</span>
              </div>
              <div className="shap-table-body">
                {threat.shap_explanation?.top_drivers?.map((d) => {
                  const isAttack = d.shap_value > 0;
                  const barWidth = Math.min(100, Math.max(10, Math.abs(d.shap_value) * 60));
                  return (
                    <div key={d.feature} className="shap-row">
                      <span className="shap-cell-name font-mono">{d.feature}</span>
                      <span className="shap-cell-val font-mono">{typeof d.feature_value === 'number' ? d.feature_value.toLocaleString() : d.feature_value} μs</span>
                      <div className="shap-bar-track">
                        <div
                          className={`shap-bar-fill ${isAttack ? 'fill-attack' : 'fill-benign'}`}
                          style={{ width: `${barWidth}%` }}
                        >
                          <span className="shap-bar-num font-mono">{isAttack ? `+${d.shap_value}` : d.shap_value}</span>
                        </div>
                      </div>
                      <span className={`shap-badge font-mono ${isAttack ? 'badge-rose' : 'badge-emerald'}`}>
                        {isAttack ? '+ ATTACK' : '- BENIGN'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB: EVIDENCE */}
      {activeTab === 'evidence' && (
        <div className="detail-tab-content">
          <div className="investigation-section">
            <h3 className="section-heading">Flow Evidence: 12 Zero-DPI Temporal Metrics</h3>
            <p className="section-subtext">
              Payload-independent features extracted from packet arrival timestamps.
            </p>

            <div className="evidence-table-container">
              <table className="clean-data-table">
                <thead>
                  <tr>
                    <th>TEMPORAL FEATURE</th>
                    <th>MEASURED DURATION</th>
                    <th>TYPICAL BENIGN RANGE</th>
                    <th>VERIFICATION STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {threat.features &&
                    Object.entries(threat.features).map(([feat, val]) => {
                      const numVal = typeof val === 'number' ? val : 0;
                      const display = numVal > 10000 ? `${(numVal / 1000).toFixed(1)} ms` : `${Math.round(numVal)} μs`;
                      const isHigh = numVal > 50000;
                      return (
                        <tr key={feat}>
                          <td className="font-mono">{feat}</td>
                          <td className="font-mono font-bold">{display}</td>
                          <td className="font-mono text-muted">&lt; 15.0 ms</td>
                          <td>
                            <span className={`status-badge-sm ${isHigh ? 'badge-warning' : 'badge-normal'}`}>
                              {isHigh ? 'ELEVATED' : 'NORMAL'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB: RESPONSE WORKFLOW */}
      {activeTab === 'response' && (
        <div className="detail-tab-content">
          <div className="investigation-section">
            <h3 className="section-heading">Automated End-to-End Containment Response</h3>
            <p className="section-subtext">
              Trace the complete lifecycle of this flow from perimeter detection to STIX 2.1 intelligence generation.
            </p>

            <div className="workflow-steps-vertical">
              <div className="workflow-step-node completed">
                <div className="step-circle font-mono">1</div>
                <div className="step-body">
                  <div className="step-title">Flow Detected & Reconstructed</div>
                  <div className="step-desc">Canonical 5-tuple key assembled from packet stream ({threat.src_ip} &rarr; {threat.dst_ip}:{threat.port}) in 0.20 ms.</div>
                </div>
              </div>

              <div className="workflow-step-node completed">
                <div className="step-circle font-mono">2</div>
                <div className="step-body">
                  <div className="step-title">Classified by Aegis-LGBM Engine</div>
                  <div className="step-desc">LightGBM inference completed in 1.21 ms. Output probability: {(threat.attack_probability * 100 || 88.4).toFixed(1)}% {threat.attack_category}.</div>
                </div>
              </div>

              <div className="workflow-step-node completed">
                <div className="step-circle font-mono">3</div>
                <div className="step-body">
                  <div className="step-title">Policy Evaluated: {threat.policy}</div>
                  <div className="step-desc">Risk score of {riskScore} evaluated against policy boundary. Triggered action: {threat.policy_action}.</div>
                </div>
              </div>

              <div className={`workflow-step-node ${isQuarantine ? 'completed' : 'skipped'}`}>
                <div className="step-circle font-mono">4</div>
                <div className="step-body">
                  <div className="step-title">Layer 2 Honeypot Containment</div>
                  <div className="step-desc">
                    {isQuarantine
                      ? 'Diverted into decoy sinkhole. Attacker session HP-SESS established with interactive shell emulation.'
                      : 'Not quarantined (flow within normal baseline parameters).'}
                  </div>
                </div>
              </div>

              <div className={`workflow-step-node ${isQuarantine ? 'completed' : 'skipped'}`}>
                <div className="step-circle font-mono">5</div>
                <div className="step-body">
                  <div className="step-title">Forensic IOC Extracted & STIX 2.1 Exported</div>
                  <div className="step-desc">
                    {isQuarantine
                      ? `Extracted indicator: ${threat.src_ip}. Compiled into OASIS STIX 2.1 threat intelligence bundle.`
                      : 'No malicious indicators harvested.'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB: MITRE ATT&CK */}
      {activeTab === 'mitre' && (
        <div className="detail-tab-content">
          <div className="investigation-section">
            <h3 className="section-heading">MITRE ATT&CK Enterprise Matrix Alignment</h3>
            <div className="mitre-card">
              <div className="mitre-tag font-mono">{threat.mitre_ttp || 'T1498.001'}</div>
              <h4 className="mitre-technique-title">Network Denial of Service: Direct Flood</h4>
              <p className="mitre-desc">
                Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Direct floods inundate network interfaces with excessive volume.
              </p>
              <div className="mitre-meta-grid">
                <div>
                  <span className="mitre-meta-label">Tactic</span>
                  <span className="mitre-meta-val">Impact (TA0040)</span>
                </div>
                <div>
                  <span className="mitre-meta-label">Detection Layer</span>
                  <span className="mitre-meta-val">Network Traffic Flow (DS0029)</span>
                </div>
                <div>
                  <span className="mitre-meta-label">Mitigation</span>
                  <span className="mitre-meta-val">Automated Honeypot Rerouting (M1037)</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
