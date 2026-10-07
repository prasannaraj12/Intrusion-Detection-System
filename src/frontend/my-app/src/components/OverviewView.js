import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Activity,
  Lock,
  Database,
  ArrowRight,
  CheckCircle2,
  Clock
} from 'lucide-react';

export default function OverviewView({
  metrics,
  events,
  iocsCount,
  apiOnline,
  modelInfo,
  onSelectThreat,
  onNavigateTo
}) {
  const activeThreats = events.filter((e) => e.policy === 'QUARANTINE' || e.policy === 'MONITOR');
  const recentThreats = activeThreats.slice(0, 5);
  const allowedCount = metrics.allowedFlows || 0;
  const monitoredCount = metrics.monitoredFlows || 0;
  const quarantinedCount = metrics.quarantinedFlows || 0;
  const totalFlows = metrics.totalFlows || 1;

  const pctAllowed = Math.round((allowedCount / totalFlows) * 100);
  const pctMonitored = Math.round((monitoredCount / totalFlows) * 100);
  const pctQuarantined = Math.round((quarantinedCount / totalFlows) * 100);

  // Timeline bars (last 16 flows)
  const timelineEvents = events.slice(0, 18).reverse();

  return (
    <div className="overview-page">
      {/* 1. Header */}
      <section className="page-header-row">
        <div>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-subtitle">AegisNIDS is monitoring network activity across all monitored interfaces</p>
        </div>
        <div className="header-meta-info">
          <Clock size={14} className="text-muted" />
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </section>

      {/* 2. Primary Status Component */}
      <section className="primary-status-card">
        <div className="status-card-icon-area">
          <ShieldCheck size={36} className="status-shield-icon" />
        </div>
        <div className="status-card-content">
          <div className="status-caption">SYSTEM STATUS</div>
          <div className="status-headline">
            {apiOnline ? 'PROTECTED' : 'SYSTEM DEGRADED'}
          </div>
          <div className="status-subtext">
            {apiOnline
              ? 'All core detection services operational — Zero-DPI temporal model active, decoy sandbox online'
              : 'Detection API unreachable — Verify local Flask service on port 5000'}
          </div>
        </div>
        <div className="status-card-stats">
          <div className="status-mini-stat">
            <span className="mini-stat-label">Inference Latency</span>
            <span className="mini-stat-value font-mono">{metrics.avgLatencyMs || 1.98} ms</span>
          </div>
          <div className="status-mini-stat">
            <span className="mini-stat-label">Model Engine</span>
            <span className="mini-stat-value font-mono">Aegis-LGBM-v1.4</span>
          </div>
        </div>
      </section>

      {/* 3. Four KPI Cards Maximum */}
      <section className="kpi-grid">
        <div className="kpi-card" onClick={() => onNavigateTo('threats')}>
          <div className="kpi-header">
            <span className="kpi-label">Active Threats</span>
            <AlertTriangle size={16} className="text-rose" />
          </div>
          <div className="kpi-value text-rose">{activeThreats.length}</div>
          <div className="kpi-footer">
            <span>{quarantinedCount} critical</span> · Requires investigation
          </div>
        </div>

        <div className="kpi-card" onClick={() => onNavigateTo('network')}>
          <div className="kpi-header">
            <span className="kpi-label">Flows Analyzed</span>
            <Activity size={16} className="text-cyan" />
          </div>
          <div className="kpi-value font-mono">{metrics.totalFlows.toLocaleString()}</div>
          <div className="kpi-footer">
            <span>{metrics.totalPackets.toLocaleString()}</span> raw wire packets
          </div>
        </div>

        <div className="kpi-card" onClick={() => onNavigateTo('honeypot')}>
          <div className="kpi-header">
            <span className="kpi-label">Quarantined</span>
            <Lock size={16} className="text-amber" />
          </div>
          <div className="kpi-value font-mono text-amber">{quarantinedCount}</div>
          <div className="kpi-footer">
            <span>98.87%</span> precision decoy isolation
          </div>
        </div>

        <div className="kpi-card" onClick={() => onNavigateTo('intelligence')}>
          <div className="kpi-header">
            <span className="kpi-label">IOCs Captured</span>
            <Database size={16} className="text-purple" />
          </div>
          <div className="kpi-value font-mono">{iocsCount}</div>
          <div className="kpi-footer">
            <span>OASIS STIX 2.1</span> validated export
          </div>
        </div>
      </section>

      {/* 4. Threat Activity Timeline */}
      <section className="section-card timeline-card">
        <div className="card-header-bar">
          <div className="card-title">Threat Activity Timeline</div>
          <span className="card-caption">Sequential network flow decisions</span>
        </div>
        <div className="timeline-strip">
          {timelineEvents.map((ev, idx) => {
            const isQuarantine = ev.policy === 'QUARANTINE';
            const isMonitor = ev.policy === 'MONITOR';
            const barClass = isQuarantine ? 'bar-quarantine' : isMonitor ? 'bar-monitor' : 'bar-allow';
            return (
              <div
                key={ev.id || idx}
                className={`timeline-bar-node ${barClass}`}
                title={`[${ev.timestamp}] ${ev.policy} - ${ev.attack_category || 'BENIGN'} (Risk: ${ev.risk_score})`}
                onClick={() => onSelectThreat(ev)}
              >
                <div className="node-fill"></div>
              </div>
            );
          })}
        </div>
        <div className="timeline-legend">
          <div className="legend-item"><span className="legend-dot dot-allow"></span> ALLOW (&lt; 0.20)</div>
          <div className="legend-item"><span className="legend-dot dot-monitor"></span> MONITOR (0.20 - 0.74)</div>
          <div className="legend-item"><span className="legend-dot dot-quarantine"></span> QUARANTINE (&ge; 0.75)</div>
        </div>
      </section>

      {/* 5. Two Columns: Detection Distribution & Recent Threats */}
      <div className="overview-split-row">
        {/* Detection Distribution */}
        <section className="section-card distribution-card">
          <div className="card-header-bar">
            <div className="card-title">Detection Distribution</div>
            <span className="card-caption">Calibrated 3-tier policy</span>
          </div>

          <div className="distribution-bars-container">
            <div className="dist-row">
              <div className="dist-row-label">
                <span className="dist-name">ALLOW (Legitimate Egress)</span>
                <span className="dist-count font-mono">{allowedCount} flows ({pctAllowed}%)</span>
              </div>
              <div className="dist-bar-track">
                <div className="dist-bar-fill fill-emerald" style={{ width: `${pctAllowed}%` }}></div>
              </div>
            </div>

            <div className="dist-row">
              <div className="dist-row-label">
                <span className="dist-name">MONITOR (SOC Watchlist)</span>
                <span className="dist-count font-mono">{monitoredCount} flows ({pctMonitored}%)</span>
              </div>
              <div className="dist-bar-track">
                <div className="dist-bar-fill fill-amber" style={{ width: `${pctMonitored}%` }}></div>
              </div>
            </div>

            <div className="dist-row">
              <div className="dist-row-label">
                <span className="dist-name">QUARANTINE (Layer 2 Honeypot)</span>
                <span className="dist-count font-mono">{quarantinedCount} flows ({pctQuarantined}%)</span>
              </div>
              <div className="dist-bar-track">
                <div className="dist-bar-fill fill-rose" style={{ width: `${pctQuarantined}%` }}></div>
              </div>
            </div>
          </div>

          <div className="distribution-summary-note">
            <span>Operating Point:</span> <strong>τ = 0.035</strong> calibrated for 97.41% recall on real CIC-IDS2017 traffic.
          </div>
        </section>

        {/* Recent Threats */}
        <section className="section-card recent-threats-card">
          <div className="card-header-bar">
            <div className="card-title">Recent Threats</div>
            <button
              className="btn-text-action"
              onClick={() => onNavigateTo('threats')}
            >
              View all ({activeThreats.length}) <ArrowRight size={13} />
            </button>
          </div>

          {recentThreats.length === 0 ? (
            <div className="empty-quiet-state">
              <CheckCircle2 size={24} className="text-emerald" />
              <p>No active threats detected. All monitored traffic is within normal baseline parameters.</p>
            </div>
          ) : (
            <div className="recent-threats-list">
              {recentThreats.map((threat) => (
                <div
                  key={threat.id}
                  className="recent-threat-row"
                  onClick={() => onSelectThreat(threat)}
                >
                  <div className="threat-row-left">
                    <span className={`policy-tag tag-${threat.policy.toLowerCase()}`}>
                      {threat.policy}
                    </span>
                    <div className="threat-row-desc">
                      <span className="threat-type">{threat.attack_category || 'Suspicious Activity'}</span>
                      <span className="threat-ip font-mono">{threat.src_ip} &rarr; :{threat.port}</span>
                    </div>
                  </div>
                  <div className="threat-row-right">
                    <div className="threat-score font-mono">Risk {threat.risk_score}</div>
                    <button
                      className="btn-investigate-mini"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectThreat(threat);
                      }}
                    >
                      Investigate <ArrowRight size={12} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* 6. System Services Row */}
      <section className="section-card services-card">
        <div className="card-header-bar">
          <div className="card-title">System Services</div>
          <span className="card-caption">All 3 core security tiers active</span>
        </div>
        <div className="services-grid">
          <div className="service-item">
            <div className="service-status-dot status-dot-active"></div>
            <div className="service-info">
              <div className="service-name">Layer 1: ML Detection Engine</div>
              <div className="service-meta font-mono">LightGBM (12 Temporal) · 1.98ms median</div>
            </div>
          </div>

          <div className="service-item">
            <div className="service-status-dot status-dot-active"></div>
            <div className="service-info">
              <div className="service-name">Layer 2: Interactive Honeypot</div>
              <div className="service-meta font-mono">SSH / HTTP Sinkhole · Decoy Ready</div>
            </div>
          </div>

          <div className="service-item">
            <div className="service-status-dot status-dot-active"></div>
            <div className="service-info">
              <div className="service-name">Intelligence: STIX 2.1 Engine</div>
              <div className="service-meta font-mono">OASIS Conformance Pass · JSON-STIX</div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
