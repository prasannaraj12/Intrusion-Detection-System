import React from 'react';
import {
  X,
  Play,
  Square,
  ShieldCheck,
  Zap,
  Crosshair,
  Terminal,
  Clock,
  AlertTriangle,
  RefreshCw
} from 'lucide-react';

const SCENARIOS = [
  { id: 'benign', label: 'Normal HTTPS Web', icon: ShieldCheck, color: 'emerald' },
  { id: 'ddos', label: 'SYN Flood / DDoS', icon: Zap, color: 'rose' },
  { id: 'port_scan', label: 'Nmap Port Scan', icon: Crosshair, color: 'amber' },
  { id: 'brute_force', label: 'SSH Brute Force', icon: Terminal, color: 'purple' },
  { id: 'slowloris', label: 'Slowloris Exhaustion', icon: Clock, color: 'amber' },
  { id: 'adversarial_jitter', label: 'Adversarial Jitter', icon: AlertTriangle, color: 'rose' }
];

export default function TrafficSimulatorModal({
  isOpen,
  onClose,
  activeScenario,
  setActiveScenario,
  packetCount,
  setPacketCount,
  isSimulating,
  onTriggerSimulation,
  autoStream,
  setAutoStream
}) {
  if (!isOpen) return null;

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="simulator-modal-panel" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-header">
          <div>
            <span className="drawer-sub font-mono text-cyan">TESTBENCH HARNESS</span>
            <h2 className="drawer-title">Inject Network Flows</h2>
          </div>
          <button className="btn-drawer-close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="simulator-modal-body">
          <p className="text-muted text-sm mb-4">
            Generate synthetic packet cadences to evaluate the zero-DPI temporal model and 3-tier policy response.
          </p>

          <div className="sim-scenario-grid">
            {SCENARIOS.map((sc) => {
              const Icon = sc.icon;
              const isSelected = activeScenario === sc.id;
              return (
                <button
                  key={sc.id}
                  className={`sim-scenario-btn ${isSelected ? `selected-${sc.color}` : ''}`}
                  onClick={() => setActiveScenario(sc.id)}
                >
                  <Icon size={18} />
                  <span>{sc.label}</span>
                </button>
              );
            })}
          </div>

          <div className="sim-param-box mt-4">
            <div className="flex justify-between items-center mb-2 font-mono text-xs">
              <span className="text-muted">Burst Packet Count:</span>
              <span className="text-cyan font-bold">{packetCount} packets</span>
            </div>
            <input
              type="range"
              min="6"
              max="40"
              value={packetCount}
              onChange={(e) => setPacketCount(Number(e.target.value))}
              className="clean-range-slider"
            />
          </div>

          <div className="sim-modal-actions mt-5 flex justify-between items-center">
            <button
              className={`btn-secondary ${autoStream ? 'btn-danger-outline' : ''}`}
              onClick={() => setAutoStream(!autoStream)}
            >
              {autoStream ? (
                <>
                  <Square size={13} /> Stop Continuous Stream
                </>
              ) : (
                <>
                  <Play size={13} /> Continuous Stream
                </>
              )}
            </button>

            <button
              className="btn-primary"
              disabled={isSimulating}
              onClick={() => {
                onTriggerSimulation(activeScenario);
                onClose();
              }}
            >
              <RefreshCw size={14} className={isSimulating ? 'spin-icon' : ''} />
              <span>{isSimulating ? 'Extracting...' : 'Inject & Evaluate'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
