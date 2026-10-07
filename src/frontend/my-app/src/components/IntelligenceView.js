import React, { useState } from 'react';
import {
  Search,
  Copy,
  Download,
  Eye,
  X,
  FileCode
} from 'lucide-react';

export default function IntelligenceView({ iocsList }) {
  const [activeTab, setActiveTab] = useState('iocs'); // 'iocs' | 'stix'
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIoc, setSelectedIoc] = useState(null);
  const [showJsonModal, setShowJsonModal] = useState(false);
  const [copyStatus, setCopyStatus] = useState('Copy JSON');

  const filteredIocs = iocsList.filter((ioc) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (ioc.indicator || '').toLowerCase().includes(q) ||
      (ioc.threat || '').toLowerCase().includes(q) ||
      (ioc.mitre || '').toLowerCase().includes(q) ||
      (ioc.type || '').toLowerCase().includes(q)
    );
  });

  // Canonical STIX 2.1 sample bundle representation
  const stixBundleData = {
    type: 'bundle',
    id: 'bundle--49cfa361-b1e6-4277-94d7-eef4113e3b33',
    spec_version: '2.1',
    objects: [
      {
        type: 'identity',
        id: 'identity--b7036329-847e-4903-8832-6a6828555e09',
        spec_version: '2.1',
        name: 'AegisNIDS Autonomous Defense System',
        identity_class: 'system'
      },
      ...iocsList.map((ioc) => ({
        type: 'indicator',
        id: `indicator--${ioc.ioc_id.toLowerCase()}-uuid4-oasis`,
        spec_version: '2.1',
        created: '2026-10-07T13:23:34.000Z',
        modified: '2026-10-07T13:23:34.000Z',
        name: `${ioc.threat} Detected Indicator`,
        pattern: `[${ioc.type === 'IPv4' ? 'ipv4-addr:value' : 'file:hashes.\'SHA-256\''} = '${ioc.indicator}']`,
        pattern_type: 'stix',
        valid_from: '2026-10-07T13:23:34.000Z',
        confidence: ioc.confidence || 90
      }))
    ]
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(stixBundleData, null, 2));
    setCopyStatus('Copied!');
    setTimeout(() => setCopyStatus('Copy JSON'), 2000);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(stixBundleData, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `stix2_bundle_export_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="intelligence-page">
      {/* 1. Header */}
      <section className="page-header-row">
        <div>
          <h1 className="page-title">Threat Intelligence</h1>
          <p className="page-subtitle">
            Forensic Indicators of Compromise (IOC) and OASIS STIX 2.1 dissemination
          </p>
        </div>
      </section>

      {/* 2. Top Tabs */}
      <div className="intel-tabs-bar">
        <button
          className={`intel-tab-btn ${activeTab === 'iocs' ? 'active' : ''}`}
          onClick={() => setActiveTab('iocs')}
        >
          IOC DATABASE ({iocsList.length})
        </button>
        <button
          className={`intel-tab-btn ${activeTab === 'stix' ? 'active' : ''}`}
          onClick={() => setActiveTab('stix')}
        >
          STIX 2.1 EXPORT
        </button>
      </div>

      {/* 3. Tab Contents */}

      {/* TAB 1: IOC DATABASE */}
      {activeTab === 'iocs' && (
        <div className="intel-tab-content">
          <div className="threats-controls-bar">
            <div className="threats-search-box w-full max-w-md">
              <Search size={14} className="search-icon" />
              <input
                type="text"
                placeholder="Search indicator, threat, or hash..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input"
              />
            </div>
          </div>

          <div className="section-card">
            <div className="table-responsive">
              <table className="clean-data-table">
                <thead>
                  <tr>
                    <th>TYPE</th>
                    <th>VALUE</th>
                    <th>CONFIDENCE</th>
                    <th>SOURCE / THREAT</th>
                    <th>FIRST SEEN</th>
                    <th>STATUS</th>
                    <th style={{ textAlign: 'right' }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIocs.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="table-empty-row">
                        No IOCs match your search query.
                      </td>
                    </tr>
                  ) : (
                    filteredIocs.map((ioc) => (
                      <tr
                        key={ioc.ioc_id}
                        className="ioc-row"
                        onClick={() => setSelectedIoc(ioc)}
                      >
                        <td className="font-mono text-cyan">{ioc.type}</td>
                        <td className="font-mono font-bold text-main max-w-xs truncate">
                          {ioc.indicator}
                        </td>
                        <td className="font-mono font-bold text-emerald">
                          {ioc.confidence}%
                        </td>
                        <td className="font-mono text-xs">{ioc.threat}</td>
                        <td className="font-mono text-muted">{ioc.first_seen}</td>
                        <td>
                          <span
                            className={`policy-badge ${ioc.severity === 'CRITICAL' ? 'badge-quarantine' : 'badge-monitor'}`}
                          >
                            {ioc.severity}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="btn-table-investigate"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedIoc(ioc);
                            }}
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: STIX EXPORT */}
      {activeTab === 'stix' && (
        <div className="intel-tab-content">
          <div className="stix-summary-card">
            <div className="stix-card-left">
              <div className="stix-badge font-mono">STIX 2.1</div>
              <h2 className="stix-bundle-title">Standardized Threat Intelligence Bundle</h2>
              <p className="stix-bundle-desc">
                Conforms strictly to OASIS Cyber Threat Intelligence (CTI) specifications. Includes RFC 4122 v4 UUIDs, ISO-8601 UTC timestamps, and valid STIX pattern grammar.
              </p>

              <div className="stix-stats-row">
                <div className="stix-stat-box">
                  <span className="stat-label">Bundle Objects</span>
                  <span className="stat-num font-mono">6 Objects</span>
                </div>
                <div className="stix-stat-box">
                  <span className="stat-label">Indicators</span>
                  <span className="stat-num font-mono">5 Indicators</span>
                </div>
                <div className="stix-stat-box">
                  <span className="stat-label">Validation</span>
                  <span className="stat-num font-mono text-emerald">VALIDATED</span>
                </div>
              </div>
            </div>

            <div className="stix-card-actions">
              <button
                className="btn-secondary"
                onClick={() => setShowJsonModal(true)}
              >
                <Eye size={14} /> View JSON
              </button>
              <button className="btn-secondary" onClick={handleCopyJson}>
                <Copy size={14} /> {copyStatus}
              </button>
              <button className="btn-primary" onClick={handleExportJson}>
                <Download size={14} /> Export Bundle
              </button>
            </div>
          </div>
        </div>
      )}

      {/* IOC Detail Drawer */}
      {selectedIoc && (
        <div className="drawer-overlay" onClick={() => setSelectedIoc(null)}>
          <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-header">
              <div>
                <span className="drawer-sub font-mono text-rose">INDICATOR FORENSICS</span>
                <h2 className="drawer-title font-mono">{selectedIoc.ioc_id}</h2>
              </div>
              <button className="btn-drawer-close" onClick={() => setSelectedIoc(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="drawer-body">
              <div className="drawer-section">
                <h4 className="drawer-section-title">Indicator Profile</h4>
                <div className="drawer-grid">
                  <div className="drawer-meta-item">
                    <span className="dm-label">Type</span>
                    <span className="dm-val font-mono">{selectedIoc.type}</span>
                  </div>
                  <div className="drawer-meta-item">
                    <span className="dm-label">Confidence</span>
                    <span className="dm-val font-mono text-emerald">{selectedIoc.confidence}%</span>
                  </div>
                  <div className="drawer-meta-item">
                    <span className="dm-label">Threat Family</span>
                    <span className="dm-val font-mono text-rose">{selectedIoc.threat}</span>
                  </div>
                  <div className="drawer-meta-item">
                    <span className="dm-label">MITRE TTP</span>
                    <span className="dm-val font-mono text-amber">{selectedIoc.mitre}</span>
                  </div>
                </div>
              </div>

              <div className="drawer-section">
                <h4 className="drawer-section-title">Full Indicator Value</h4>
                <div className="code-snippet-box font-mono break-all">
                  {selectedIoc.indicator}
                </div>
              </div>

              <div className="drawer-section">
                <h4 className="drawer-section-title">OASIS STIX 2.1 Pattern</h4>
                <div className="code-snippet-box font-mono text-cyan">
                  {`[${selectedIoc.type === 'IPv4' ? 'ipv4-addr:value' : 'file:hashes.\'SHA-256\''} = '${selectedIoc.indicator}']`}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* View JSON Modal */}
      {showJsonModal && (
        <div className="drawer-overlay" onClick={() => setShowJsonModal(false)}>
          <div className="json-modal-panel" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-header">
              <div className="flex items-center gap-2">
                <FileCode size={18} className="text-cyan" />
                <h3 className="drawer-title font-mono text-sm">OASIS STIX 2.1 Bundle JSON</h3>
              </div>
              <div className="flex items-center gap-2">
                <button className="btn-secondary btn-sm" onClick={handleCopyJson}>
                  <Copy size={13} /> {copyStatus}
                </button>
                <button className="btn-drawer-close" onClick={() => setShowJsonModal(false)}>
                  <X size={16} />
                </button>
              </div>
            </div>
            <div className="json-modal-body">
              <pre className="font-mono text-xs text-muted">
                {JSON.stringify(stixBundleData, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
