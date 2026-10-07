import React, { useState } from 'react';
import {
  Search,
  ArrowRight
} from 'lucide-react';
import ThreatDetailView from './ThreatDetailView';

export default function ThreatsView({
  events,
  selectedThreat,
  onSelectThreat,
  onClearSelectedThreat,
  onNavigateTo
}) {
  const [filterType, setFilterType] = useState('all'); // 'all' | 'quarantine' | 'monitor' | 'allow'
  const [searchQuery, setSearchQuery] = useState('');

  // If a threat is currently selected for investigation, render the ThreatDetailView directly
  if (selectedThreat) {
    return (
      <ThreatDetailView
        threat={selectedThreat}
        onBackToThreats={onClearSelectedThreat}
        onNavigateTo={onNavigateTo}
      />
    );
  }

  const filteredEvents = events.filter((e) => {
    if (filterType === 'quarantine' && e.policy !== 'QUARANTINE') return false;
    if (filterType === 'monitor' && e.policy !== 'MONITOR') return false;
    if (filterType === 'allow' && e.policy !== 'ALLOW') return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const ip = (e.src_ip || '').toLowerCase();
      const cat = (e.attack_category || '').toLowerCase();
      const mitre = (e.mitre_ttp || '').toLowerCase();
      if (!ip.includes(q) && !cat.includes(q) && !mitre.includes(q)) return false;
    }
    return true;
  });

  const quarantineCount = events.filter((e) => e.policy === 'QUARANTINE').length;
  const monitorCount = events.filter((e) => e.policy === 'MONITOR').length;
  const allowCount = events.filter((e) => e.policy === 'ALLOW').length;

  return (
    <div className="threats-page">
      {/* Header */}
      <section className="page-header-row">
        <div>
          <h1 className="page-title">Threat Management</h1>
          <p className="page-subtitle">Real-time threat detection feed and automated policy dispositions</p>
        </div>
      </section>

      {/* Filter and Search Bar */}
      <div className="threats-controls-bar">
        <div className="filter-pills-group">
          <button
            className={`filter-pill-btn ${filterType === 'all' ? 'active' : ''}`}
            onClick={() => setFilterType('all')}
          >
            All Flows ({events.length})
          </button>
          <button
            className={`filter-pill-btn pill-quarantine ${filterType === 'quarantine' ? 'active' : ''}`}
            onClick={() => setFilterType('quarantine')}
          >
            Quarantined ({quarantineCount})
          </button>
          <button
            className={`filter-pill-btn pill-monitor ${filterType === 'monitor' ? 'active' : ''}`}
            onClick={() => setFilterType('monitor')}
          >
            Monitored ({monitorCount})
          </button>
          <button
            className={`filter-pill-btn pill-allow ${filterType === 'allow' ? 'active' : ''}`}
            onClick={() => setFilterType('allow')}
          >
            Allowed ({allowCount})
          </button>
        </div>

        <div className="threats-search-box">
          <Search size={14} className="search-icon" />
          <input
            type="text"
            placeholder="Search IP, category, or MITRE..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
      </div>

      {/* Threat List Table */}
      <div className="threats-table-container">
        <table className="clean-data-table">
          <thead>
            <tr>
              <th>TIME</th>
              <th>SOURCE IP</th>
              <th>DESTINATION</th>
              <th>PORT</th>
              <th>ATTACK CATEGORY</th>
              <th>RISK SCORE</th>
              <th>POLICY</th>
              <th>MITRE TTP</th>
              <th style={{ textAlign: 'right' }}>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={9} className="table-empty-row">
                  No threats matching selected filters.
                </td>
              </tr>
            ) : (
              filteredEvents.map((ev) => {
                const isQuarantine = ev.policy === 'QUARANTINE';
                const isMonitor = ev.policy === 'MONITOR';
                const rowPolicyClass = isQuarantine ? 'row-quarantine' : isMonitor ? 'row-monitor' : 'row-allow';

                return (
                  <tr
                    key={ev.id}
                    className={`threat-table-row ${rowPolicyClass}`}
                    onClick={() => onSelectThreat(ev)}
                  >
                    <td className="font-mono text-muted">{ev.timestamp}</td>
                    <td className="font-mono font-bold text-main">{ev.src_ip}</td>
                    <td className="font-mono text-muted">{ev.dst_ip}</td>
                    <td className="font-mono text-cyan">{ev.port}</td>
                    <td className="font-bold text-main">{ev.attack_category || 'BENIGN'}</td>
                    <td className="font-mono font-bold">
                      <span className={isQuarantine ? 'text-rose' : isMonitor ? 'text-amber' : 'text-emerald'}>
                        {ev.risk_score}
                      </span>
                    </td>
                    <td>
                      <span className={`policy-badge badge-${ev.policy.toLowerCase()}`}>
                        {ev.policy}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-muted">
                      {ev.mitre_ttp ? ev.mitre_ttp.split(' - ')[0] : '—'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn-table-investigate"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectThreat(ev);
                        }}
                      >
                        Investigate <ArrowRight size={12} />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
