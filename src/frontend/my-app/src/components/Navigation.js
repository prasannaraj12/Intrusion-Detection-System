import React from 'react';
import {
  Shield,
  Activity,
  AlertTriangle,
  Radio,
  Lock,
  Database,
  BarChart3,
  Server,
  Play
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'overview', label: 'OVERVIEW', icon: Activity },
  { id: 'threats', label: 'THREATS', icon: AlertTriangle },
  { id: 'network', label: 'NETWORK', icon: Radio },
  { id: 'honeypot', label: 'HONEYPOT', icon: Lock },
  { id: 'intelligence', label: 'INTELLIGENCE', icon: Database },
  { id: 'analytics', label: 'ANALYTICS', icon: BarChart3 },
  { id: 'system', label: 'SYSTEM', icon: Server }
];

export default function Navigation({
  activeTab,
  setActiveTab,
  apiOnline,
  activeThreatCount,
  onOpenSimulator
}) {
  return (
    <header className="aegis-nav-header">
      <div className="nav-brand-container">
        <div className="nav-brand-logo">
          <Shield size={20} className="brand-shield-icon" />
        </div>
        <div className="nav-brand-text">
          <div className="brand-name">
            Aegis<span>NIDS</span>
          </div>
          <div className="brand-edition">Enterprise SOC</div>
        </div>
      </div>

      <nav className="nav-links">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              className={`nav-link-btn ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <Icon size={15} />
              <span>{item.label}</span>
              {item.id === 'threats' && activeThreatCount > 0 && (
                <span className="nav-badge-threats">{activeThreatCount}</span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="nav-right-controls">
        <div className={`system-status-indicator ${apiOnline ? 'status-online' : 'status-offline'}`}>
          <span className="status-dot"></span>
          <span className="status-text">{apiOnline ? 'PROTECTED' : 'OFFLINE'}</span>
        </div>

        <button
          className="btn-quick-simulate"
          onClick={onOpenSimulator}
          title="Inject test network flows"
        >
          <Play size={13} />
          <span>Simulate Flow</span>
        </button>
      </div>
    </header>
  );
}
