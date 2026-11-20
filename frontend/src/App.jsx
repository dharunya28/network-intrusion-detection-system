import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import DashboardStats from './components/DashboardStats';
import PacketInjectorForm from './components/PacketInjectorForm';
import LiveTrafficTable from './components/LiveTrafficTable';
import AlertCenter from './components/AlertCenter';
import AutomataViewer from './components/AutomataViewer';
import SampleDataViewer from './components/SampleDataViewer';
import { fetchHealth, fetchTraffic, fetchStats, fetchAlerts, clearData } from './utils/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('monitor');
  const [trafficLogs, setTrafficLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadAllData = async () => {
    try {
      const [healthData, trafficData, alertsData, statsData] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchTraffic(50).catch(() => ({ logs: [] })),
        fetchAlerts(50).catch(() => ({ alerts: [] })),
        fetchStats().catch(() => ({ stats: null })),
      ]);

      if (healthData) setHealth(healthData);
      if (trafficData?.logs) setTrafficLogs(trafficData.logs);
      if (alertsData?.alerts) setAlerts(alertsData.alerts);
      if (statsData?.stats) {
        setStats(statsData.stats);
      } else if (trafficData?.logs) {
        const logs = trafficData.logs;
        setStats({
          totalPackets: logs.length,
          maliciousCount: logs.filter((t) => t.status === 'MALICIOUS').length,
          suspiciousCount: logs.filter((t) => t.status === 'SUSPICIOUS').length,
          cleanCount: logs.filter((t) => t.status === 'NORMAL').length,
        });
      }
    } catch (err) {
      console.error('Failed to sync network data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handlePacketSubmitted = (newResult) => {
    loadAllData();
  };

  const handleClearData = async () => {
    if (window.confirm('Are you sure you want to clear all traffic logs and alerts?')) {
      await clearData();
      loadAllData();
    }
  };

  return (
    <div className="app-layout">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        alertsCount={alerts.length}
        health={health}
        onClearData={handleClearData}
      />

      <main className="main-viewport">
        {/* Metric Cards Banner */}
        <DashboardStats stats={stats} />

        {/* Tab 1: Live Monitor & Form */}
        {activeTab === 'monitor' && (
          <div className="dashboard-grid">
            <PacketInjectorForm onPacketSubmitted={handlePacketSubmitted} />
            <LiveTrafficTable logs={trafficLogs} loading={loading} />
          </div>
        )}

        {/* Tab 2: Security Alert Center */}
        {activeTab === 'alerts' && (
          <AlertCenter alerts={alerts} onResolveAlert={loadAllData} />
        )}

        {/* Tab 3: Automata Theory & Transition Diagrams & Tables */}
        {activeTab === 'automata' && <AutomataViewer />}

        {/* Tab 4: Sample Inputs & Deliverables */}
        {activeTab === 'samples' && <SampleDataViewer />}
      </main>

      <footer
        style={{
          borderTop: '1px solid var(--border-color)',
          padding: '16px 24px',
          textAlign: 'center',
          fontSize: '0.75rem',
          color: '#6b7280',
          background: 'rgba(10, 13, 20, 0.95)',
          marginTop: 'auto',
        }}
      >
        <span>
          College Network Intrusion Detection System (NIDS) • Scenario 23 • Built with React, Node.js, Express, MongoDB, Finite Automata & Regular Expressions
        </span>
      </footer>
    </div>
  );
}
