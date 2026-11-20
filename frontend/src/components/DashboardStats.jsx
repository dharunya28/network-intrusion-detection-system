import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldX, Radio } from 'lucide-react';

export default function DashboardStats({ stats }) {
  const total = stats?.totalPackets || 0;
  const clean = stats?.cleanCount ?? stats?.cleanPackets ?? 0;
  const suspicious = stats?.suspiciousCount ?? stats?.suspiciousPackets ?? 0;
  const malicious = stats?.maliciousCount ?? stats?.maliciousPackets ?? 0;

  const threatPercentage = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;

  return (
    <div className="stats-grid">
      <div className="stat-card">
        <div>
          <div className="stat-label">Total Inspected Packets</div>
          <div className="stat-value">{total}</div>
          <div style={{ fontSize: '0.72rem', color: '#9ca3af', marginTop: '4px' }}>
            Automata + Regex Scan Pipeline
          </div>
        </div>
        <div style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '12px', borderRadius: '10px' }}>
          <Radio size={24} color="#38bdf8" />
        </div>
      </div>

      <div className="stat-card">
        <div>
          <div className="stat-label">Normal / Clean Traffic</div>
          <div className="stat-value" style={{ color: '#00ff88' }}>{clean}</div>
          <div style={{ fontSize: '0.72rem', color: '#9ca3af', marginTop: '4px' }}>
            Forwarded to campus servers
          </div>
        </div>
        <div style={{ background: 'rgba(0, 255, 136, 0.1)', padding: '12px', borderRadius: '10px' }}>
          <ShieldCheck size={24} color="#00ff88" />
        </div>
      </div>

      <div className="stat-card">
        <div>
          <div className="stat-label">Suspicious Packets</div>
          <div className="stat-value" style={{ color: '#fbbf24' }}>{suspicious}</div>
          <div style={{ fontSize: '0.72rem', color: '#9ca3af', marginTop: '4px' }}>
            Probes & Anomalies flagged
          </div>
        </div>
        <div style={{ background: 'rgba(251, 191, 36, 0.1)', padding: '12px', borderRadius: '10px' }}>
          <AlertTriangle size={24} color="#fbbf24" />
        </div>
      </div>

      <div className="stat-card">
        <div>
          <div className="stat-label">Malicious Intrusions Blocked</div>
          <div className="stat-value" style={{ color: '#f43f5e' }}>{malicious}</div>
          <div style={{ fontSize: '0.72rem', color: '#9ca3af', marginTop: '4px' }}>
            Threat Ratio: <strong style={{ color: '#f43f5e' }}>{threatPercentage}%</strong>
          </div>
        </div>
        <div style={{ background: 'rgba(244, 63, 94, 0.1)', padding: '12px', borderRadius: '10px' }}>
          <ShieldX size={24} color="#f43f5e" />
        </div>
      </div>
    </div>
  );
}
