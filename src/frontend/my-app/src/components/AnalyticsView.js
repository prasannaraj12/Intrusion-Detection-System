import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2
} from 'lucide-react';

export default function AnalyticsView({ benchmarkReport }) {
  const [activeTab, setActiveTab] = useState('performance'); // 'performance' | 'models' | 'attacks' | 'research'

  return (
    <div className="analytics-page">
      {/* 1. Header */}
      <section className="page-header-row">
        <div>
          <h1 className="page-title">Research & Empirical Analytics</h1>
          <p className="page-subtitle">
            Audited scientific metrics, model comparisons, and threshold calibration
          </p>
        </div>
      </section>

      {/* 2. Top Tabs */}
      <div className="analytics-tabs-bar">
        {[
          { id: 'performance', label: 'PERFORMANCE' },
          { id: 'models', label: 'MODELS (A vs B)' },
          { id: 'attacks', label: 'ATTACKS' },
          { id: 'research', label: 'RESEARCH & LIMITS' }
        ].map((tab) => (
          <button
            key={tab.id}
            className={`analytics-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 3. Tab Contents */}

      {/* TAB 1: PERFORMANCE */}
      {activeTab === 'performance' && (
        <div className="analytics-tab-content">
          {/* Key Metrics on Real 20,000-Flow Dataset */}
          <div className="section-card">
            <div className="card-header-bar">
              <div className="card-title">CIC-IDS2017 Real Dataset Evaluation (20,000 Flows)</div>
              <span className="card-caption">Calibrated Operating Point (τ = 0.035)</span>
            </div>

            <div className="perf-kpi-grid">
              <div className="perf-metric-box">
                <span className="perf-label">ROC-AUC</span>
                <span className="perf-value text-cyan">97.17%</span>
                <span className="perf-sub">Near-optimal separation</span>
              </div>
              <div className="perf-metric-box">
                <span className="perf-label">Recall</span>
                <span className="perf-value text-emerald">97.41%</span>
                <span className="perf-sub">9,741 / 10,000 attacks caught</span>
              </div>
              <div className="perf-metric-box">
                <span className="perf-label">F1-Score</span>
                <span className="perf-value text-purple">87.51%</span>
                <span className="perf-sub">Harmonic precision/recall</span>
              </div>
              <div className="perf-metric-box">
                <span className="perf-label">Precision</span>
                <span className="perf-value text-main">79.44%</span>
                <span className="perf-sub">Across all vectors</span>
              </div>
              <div className="perf-metric-box">
                <span className="perf-label">False Negatives</span>
                <span className="perf-value text-rose">2.59%</span>
                <span className="perf-sub">Perimeter leak minimized</span>
              </div>
              <div className="perf-metric-box">
                <span className="perf-label">Pipeline Latency</span>
                <span className="perf-value text-amber">1.98 ms</span>
                <span className="perf-sub">Audited median end-to-end</span>
              </div>
            </div>
          </div>

          {/* Confusion Matrix Table */}
          <div className="analytics-split-row">
            <div className="section-card">
              <div className="card-header-bar">
                <div className="card-title">Empirical Confusion Matrix (20,000 Flows)</div>
              </div>
              <table className="clean-data-table font-mono text-center">
                <thead>
                  <tr>
                    <th></th>
                    <th>PREDICTED ATTACK</th>
                    <th>PREDICTED BENIGN</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="font-bold text-left">ACTUAL ATTACK</td>
                    <td className="text-emerald font-bold bg-emerald-subtle">TP: 9,741</td>
                    <td className="text-rose font-bold bg-rose-subtle">FN: 259</td>
                  </tr>
                  <tr>
                    <td className="font-bold text-left">ACTUAL BENIGN</td>
                    <td className="text-amber font-bold bg-amber-subtle">FP: 2,521</td>
                    <td className="text-cyan font-bold bg-cyan-subtle">TN: 7,479</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="section-card">
              <div className="card-header-bar">
                <div className="card-title">Operational Latency Profile</div>
              </div>
              <div className="latency-list font-mono">
                <div className="latency-item">
                  <span>Feature Extraction:</span>
                  <strong>0.20 ms median (p95: 0.31 ms)</strong>
                </div>
                <div className="latency-item">
                  <span>Model Inference:</span>
                  <strong>1.21 ms median (p95: 2.01 ms)</strong>
                </div>
                <div className="latency-item">
                  <span>Total End-to-End:</span>
                  <strong className="text-cyan">1.98 ms median (p95: 3.16 ms)</strong>
                </div>
                <div className="latency-item">
                  <span>Batch Throughput:</span>
                  <strong className="text-emerald">&gt; 800,000 flows/sec</strong>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: MODELS */}
      {activeTab === 'models' && (
        <div className="analytics-tab-content">
          <div className="section-card">
            <div className="card-header-bar">
              <div className="card-title">Model Comparison: Model A vs Model B</div>
              <span className="card-caption">Evaluated on Tuesday Authentication Brute Force</span>
            </div>

            <div className="table-responsive">
              <table className="clean-data-table">
                <thead>
                  <tr>
                    <th>DIMENSION</th>
                    <th>MODEL A (12 TEMPORAL ONLY)</th>
                    <th>MODEL B (24 EXTENDED FLOW)</th>
                    <th>EMPIRICAL GAIN / DELTA</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><strong>Features Tracked</strong></td>
                    <td className="font-mono">12 (Zero-DPI Inter-Arrivals)</td>
                    <td className="font-mono">24 (Temporal + Port + Flags)</td>
                    <td className="text-muted">+12 transport features</td>
                  </tr>
                  <tr>
                    <td><strong>F1-Score</strong></td>
                    <td className="font-mono">88.37%</td>
                    <td className="font-mono font-bold text-emerald">99.86%</td>
                    <td className="font-mono font-bold text-emerald">+11.49% F1 gain</td>
                  </tr>
                  <tr>
                    <td><strong>Precision</strong></td>
                    <td className="font-mono">79.28%</td>
                    <td className="font-mono font-bold text-emerald">99.71%</td>
                    <td className="text-muted">Eliminates false alarms</td>
                  </tr>
                  <tr>
                    <td><strong>False Positive Rate (FPR)</strong></td>
                    <td className="font-mono text-rose">18.05%</td>
                    <td className="font-mono font-bold text-cyan">0.20%</td>
                    <td className="font-mono text-cyan">90x reduction in FPR</td>
                  </tr>
                  <tr>
                    <td><strong>FTP Patator Recall</strong></td>
                    <td className="font-mono text-amber">82.41%</td>
                    <td className="font-mono font-bold text-emerald">99.98%</td>
                    <td className="font-mono text-emerald">Resolves timing blind spot</td>
                  </tr>
                  <tr>
                    <td><strong>Inference Latency</strong></td>
                    <td className="font-mono">1.154 ms</td>
                    <td className="font-mono">1.171 ms</td>
                    <td className="font-mono text-muted">+17 μs latency delta</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="trade-off-box">
              <span className="font-bold">Key Architectural Takeaway:</span> Model A offers complete payload and port independence (zero privacy exposure), making it ideal for pure cadence anomaly detection. Model B resolves authentication brute force with 99.86% F1 by adding destination port and packet flag ratios with negligible (+17 μs) latency overhead.
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: ATTACKS */}
      {activeTab === 'attacks' && (
        <div className="analytics-tab-content">
          <div className="section-card">
            <div className="card-header-bar">
              <div className="card-title">Attack-Category Performance Breakdown</div>
              <span className="card-caption">Evaluated across 20,000 real flows</span>
            </div>

            <div className="table-responsive">
              <table className="clean-data-table">
                <thead>
                  <tr>
                    <th>ATTACK VECTOR</th>
                    <th>SAMPLES</th>
                    <th>DETECTED</th>
                    <th>RECALL</th>
                    <th>MITRE TTP</th>
                    <th>DETECTION CADENCE</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="font-bold text-main">DDoS (LOIC Flood)</td>
                    <td className="font-mono">3,500</td>
                    <td className="font-mono text-emerald font-bold">3,499</td>
                    <td className="font-mono font-bold text-emerald">99.97%</td>
                    <td className="font-mono text-muted">T1498.001</td>
                    <td>High-frequency burst inter-arrival</td>
                  </tr>
                  <tr>
                    <td className="font-bold text-main">PortScan (Nmap Recon)</td>
                    <td className="font-mono">3,500</td>
                    <td className="font-mono text-emerald font-bold">3,496</td>
                    <td className="font-mono font-bold text-emerald">99.89%</td>
                    <td className="font-mono text-muted">T1046</td>
                    <td>Rapid multi-port SYN cadence</td>
                  </tr>
                  <tr>
                    <td className="font-bold text-main">SSH-Patator (Brute Force)</td>
                    <td className="font-mono">1,500</td>
                    <td className="font-mono text-emerald font-bold">1,495</td>
                    <td className="font-mono font-bold text-emerald">99.67%</td>
                    <td className="font-mono text-muted">T1110.001</td>
                    <td>Repeated handshake timeouts</td>
                  </tr>
                  <tr>
                    <td className="font-bold text-main">FTP-Patator (Brute Force)</td>
                    <td className="font-mono">1,500</td>
                    <td className="font-mono text-amber font-bold">1,251</td>
                    <td className="font-mono font-bold text-amber">83.40%</td>
                    <td className="font-mono text-muted">T1110.001</td>
                    <td>Resolved by Model B (99.98%)</td>
                  </tr>
                  <tr>
                    <td className="font-bold text-main">BENIGN (Legitimate Web)</td>
                    <td className="font-mono">10,000</td>
                    <td className="font-mono text-cyan font-bold">7,479</td>
                    <td className="font-mono font-bold text-cyan">74.79%</td>
                    <td className="font-mono text-muted">N/A</td>
                    <td>Specific baseline activity</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: RESEARCH & LIMITS */}
      {activeTab === 'research' && (
        <div className="analytics-tab-content">
          <div className="section-card">
            <div className="card-header-bar">
              <div className="card-title">Scientific Limitations & Documented Findings</div>
            </div>

            <div className="research-limits-grid">
              <div className="limit-card">
                <div className="limit-title text-amber">
                  <AlertTriangle size={16} /> Cross-Attack Cadence Generalization
                </div>
                <p className="limit-desc">
                  Zero-shot transfer across distinct attack categories is constrained by differing temporal physics. A model trained exclusively on volumetric DDoS floods achieves only 21.4% recall on authentication brute-force attacks due to dissimilar packet inter-arrival patterns. Multi-vector training is mathematically essential.
                </p>
              </div>

              <div className="limit-card">
                <div className="limit-title text-rose">
                  <AlertTriangle size={16} /> CSE-CIC-IDS2018 Label Status
                </div>
                <p className="limit-desc">
                  The local Parquet archive (39,940 flows across 79 features) does not contain ground-truth labels. In compliance with strict research integrity standards, it is explicitly classified as <strong className="font-mono">AVAILABLE, NOT VALIDATED</strong> to prevent fabricated evaluation claims.
                </p>
              </div>

              <div className="limit-card">
                <div className="limit-title text-cyan">
                  <CheckCircle2 size={16} /> False Positive Distribution
                </div>
                <p className="limit-desc">
                  At the calibrated threshold of τ = 0.035, 95.1% of false alarms remain confined to passive MONITOR watchlist observation (median score: 0.144). Only 1.23% reach automatic QUARANTINE, preventing business workflow interruptions.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
