import React, { useState } from 'react';
import { Send, AlertCircle, CheckCircle, ShieldAlert, Zap, Terminal } from 'lucide-react';
import { processPacket } from '../utils/api';

const IP_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

const PRESET_SCENARIOS = [
  {
    label: "SQL Injection (' OR 1=1)",
    type: 'danger',
    data: {
      sourceIP: '10.10.5.88',
      destinationIP: '172.16.0.5',
      port: 80,
      protocol: 'HTTP',
      payload: "POST /login HTTP/1.1\r\nusername=admin' OR 1=1--&password=pass",
    },
  },
  {
    label: 'XSS Attack (<script>)',
    type: 'danger',
    data: {
      sourceIP: '198.51.100.44',
      destinationIP: '172.16.0.5',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /search?query=<script>alert(document.cookie)</script> HTTP/1.1',
    },
  },
  {
    label: 'Path Traversal (../../)',
    type: 'danger',
    data: {
      sourceIP: '203.0.113.12',
      destinationIP: '172.16.0.10',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /download?file=../../etc/passwd HTTP/1.1',
    },
  },
  {
    label: 'Command Injection (; rm)',
    type: 'danger',
    data: {
      sourceIP: '192.168.1.99',
      destinationIP: '172.16.0.12',
      port: 8080,
      protocol: 'HTTP',
      payload: 'POST /status?ping=127.0.0.1; whoami; cat /etc/shadow',
    },
  },
  {
    label: 'Port Probe (Telnet: 23)',
    type: 'danger',
    data: {
      sourceIP: '198.51.100.99',
      destinationIP: '172.16.0.2',
      port: 23,
      protocol: 'TCP',
      payload: 'TCP SYN Packet handshake probe on port 23',
    },
  },
  {
    label: 'Clean HTTP Request',
    type: 'safe',
    data: {
      sourceIP: '192.168.10.15',
      destinationIP: '172.16.0.5',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /courses/syllabus?dept=cse&year=3 HTTP/1.1\r\nHost: college.edu',
    },
  },
];

export default function PacketInjectorForm({ onPacketSubmitted }) {
  const [formData, setFormData] = useState({
    sourceIP: '192.168.1.100',
    destinationIP: '172.16.0.5',
    port: 80,
    protocol: 'HTTP',
    payload: "GET /api/student?id=101' OR 1=1-- HTTP/1.1",
  });

  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [lastResult, setLastResult] = useState(null);

  // Client-Side Form Validation
  const validate = () => {
    const newErrors = {};

    // Source IP
    if (!formData.sourceIP.trim()) {
      newErrors.sourceIP = 'Source IPv4 address is required';
    } else if (!IP_REGEX.test(formData.sourceIP.trim())) {
      newErrors.sourceIP = 'Invalid IPv4 format. Must be X.X.X.X (0-255 each)';
    }

    // Destination IP
    if (!formData.destinationIP.trim()) {
      newErrors.destinationIP = 'Destination IPv4 address is required';
    } else if (!IP_REGEX.test(formData.destinationIP.trim())) {
      newErrors.destinationIP = 'Invalid IPv4 format. Must be X.X.X.X (0-255 each)';
    }

    // Port
    const portNum = Number(formData.port);
    if (!formData.port || isNaN(portNum) || portNum < 1 || portNum > 65535) {
      newErrors.port = 'Port must be an integer between 1 and 65535';
    }

    // Protocol
    if (!formData.protocol) {
      newErrors.protocol = 'Protocol selection is required';
    }

    // Payload
    if (!formData.payload || !formData.payload.trim()) {
      newErrors.payload = 'Packet payload cannot be empty';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    // Clear field-specific error as user types
    if (errors[name]) {
      setErrors((prev) => ({ ...prev, [name]: null }));
    }
  };

  const handleApplyPreset = (preset) => {
    setFormData(preset.data);
    setErrors({});
    setLastResult(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validate()) return;

    setSubmitting(true);
    setLastResult(null);

    try {
      const data = await processPacket(formData);

      if (!data || data.success === false) {
        if (data?.errors) {
          setErrors(data.errors);
        } else {
          setErrors({ form: data?.message || 'Error processing packet' });
        }
      } else {
        setLastResult(data);
        if (onPacketSubmitted) {
          onPacketSubmitted(data);
        }
      }
    } catch (err) {
      setErrors({ form: 'Inspection failed: ' + err.message });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">
          <Terminal size={18} color="#00ff88" />
          <span>Network Packet Injector & Validator</span>
        </h2>
        <span style={{ fontSize: '0.72rem', color: '#9ca3af', fontFamily: 'monospace' }}>
          Form Validation Engine
        </span>
      </div>

      {/* Preset Attacks for Viva / Lab Demo */}
      <div className="preset-section">
        <div className="preset-title">
          <Zap size={12} style={{ display: 'inline', marginRight: '4px' }} />
          Quick Test Attack Presets (1-Click Injection):
        </div>
        <div className="preset-btn-group">
          {PRESET_SCENARIOS.map((p, idx) => (
            <button
              key={idx}
              type="button"
              className={`btn-preset ${p.type === 'danger' ? 'danger' : ''}`}
              onClick={() => handleApplyPreset(p)}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleSubmit} noValidate>
        {errors.form && (
          <div className="form-error-msg" style={{ marginBottom: '12px' }}>
            <AlertCircle size={14} />
            <span>{errors.form}</span>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          {/* Source IP */}
          <div className="form-group">
            <label className="form-label">Source IP (IPv4)</label>
            <input
              type="text"
              name="sourceIP"
              className={`form-input ${errors.sourceIP ? 'is-invalid' : ''}`}
              value={formData.sourceIP}
              onChange={handleChange}
              placeholder="e.g. 192.168.1.100"
            />
            {errors.sourceIP && (
              <div className="form-error-msg">
                <AlertCircle size={12} />
                <span>{errors.sourceIP}</span>
              </div>
            )}
          </div>

          {/* Destination IP */}
          <div className="form-group">
            <label className="form-label">Destination IP (IPv4)</label>
            <input
              type="text"
              name="destinationIP"
              className={`form-input ${errors.destinationIP ? 'is-invalid' : ''}`}
              value={formData.destinationIP}
              onChange={handleChange}
              placeholder="e.g. 172.16.0.5"
            />
            {errors.destinationIP && (
              <div className="form-error-msg">
                <AlertCircle size={12} />
                <span>{errors.destinationIP}</span>
              </div>
            )}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '12px' }}>
          {/* Port */}
          <div className="form-group">
            <label className="form-label">Port (1-65535)</label>
            <input
              type="number"
              name="port"
              className={`form-input ${errors.port ? 'is-invalid' : ''}`}
              value={formData.port}
              onChange={handleChange}
              min="1"
              max="65535"
            />
            {errors.port && (
              <div className="form-error-msg">
                <AlertCircle size={12} />
                <span>{errors.port}</span>
              </div>
            )}
          </div>

          {/* Protocol */}
          <div className="form-group">
            <label className="form-label">Protocol</label>
            <select
              name="protocol"
              className={`form-select ${errors.protocol ? 'is-invalid' : ''}`}
              value={formData.protocol}
              onChange={handleChange}
            >
              <option value="HTTP">HTTP (Port 80/8080)</option>
              <option value="HTTPS">HTTPS (Port 443)</option>
              <option value="TCP">TCP Raw Socket</option>
              <option value="UDP">UDP Datagram</option>
              <option value="DNS">DNS Query (Port 53)</option>
              <option value="SSH">SSH Secure Shell (Port 22)</option>
              <option value="FTP">FTP File Transfer (Port 21)</option>
              <option value="ICMP">ICMP Echo Ping</option>
            </select>
          </div>
        </div>

        {/* Payload */}
        <div className="form-group">
          <label className="form-label">Packet Payload / Query String</label>
          <textarea
            name="payload"
            rows="3"
            className={`form-textarea ${errors.payload ? 'is-invalid' : ''}`}
            value={formData.payload}
            onChange={handleChange}
            placeholder="Enter HTTP headers, URI query, or raw byte string..."
          />
          {errors.payload && (
            <div className="form-error-msg">
              <AlertCircle size={12} />
              <span>{errors.payload}</span>
            </div>
          )}
        </div>

        <button type="submit" className="btn-primary" disabled={submitting}>
          {submitting ? (
            <span>Analyzing Packet with Automata...</span>
          ) : (
            <>
              <Send size={16} />
              <span>Transmit & Inspect Packet</span>
            </>
          )}
        </button>
      </form>

      {/* Immediate Inspection Results Box */}
      {lastResult && (
        <div
          style={{
            marginTop: '16px',
            padding: '14px',
            borderRadius: '10px',
            background:
              lastResult.analysis.status === 'MALICIOUS'
                ? 'rgba(244, 63, 94, 0.12)'
                : lastResult.analysis.status === 'SUSPICIOUS'
                ? 'rgba(245, 158, 11, 0.12)'
                : 'rgba(16, 185, 129, 0.12)',
            border: `1px solid ${
              lastResult.analysis.status === 'MALICIOUS'
                ? '#f43f5e'
                : lastResult.analysis.status === 'SUSPICIOUS'
                ? '#fbbf24'
                : '#10b981'
            }`,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {lastResult.analysis.status === 'NORMAL' ? (
                <CheckCircle size={18} color="#00ff88" />
              ) : (
                <ShieldAlert size={18} color="#f43f5e" />
              )}
              <strong style={{ fontSize: '0.9rem' }}>{lastResult.message}</strong>
            </div>
            <span
              className={`badge ${
                lastResult.analysis.status === 'NORMAL'
                  ? 'badge-clean'
                  : lastResult.analysis.status === 'SUSPICIOUS'
                  ? 'badge-suspicious'
                  : 'badge-malicious'
              }`}
            >
              Action: {lastResult.analysis.actionTaken}
            </span>
          </div>

          {lastResult.analysis.detectedAttacks.length > 0 && (
            <div style={{ marginTop: '10px', fontSize: '0.8rem' }}>
              <div style={{ color: '#9ca3af', marginBottom: '4px' }}>Detected Attacks:</div>
              {lastResult.analysis.detectedAttacks.map((att, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '6px 10px',
                    borderRadius: '6px',
                    background: 'rgba(0,0,0,0.3)',
                    marginBottom: '6px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#f87171', fontWeight: 'bold' }}>
                      {att.attackType} ({att.severity})
                    </span>
                    <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>
                      Via: {att.matchedBy}
                    </span>
                  </div>
                  <div style={{ color: '#9ca3af', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    Matched Pattern: <code style={{ color: '#fbbf24' }}>{att.matchedPattern}</code>
                  </div>

                  {att.automataTrace && att.automataTrace.length > 0 && (
                    <div style={{ marginTop: '6px' }}>
                      <div style={{ fontSize: '0.72rem', color: '#9ca3af' }}>DFA State Transitions:</div>
                      <div className="trace-sequence">
                        {att.automataTrace.map((tr, tIdx) => (
                          <div key={tIdx} className="trace-step">
                            <span>{tr.from}</span>
                            <span className="trace-arrow">--[{tr.input}]-&gt;</span>
                            <span style={{ color: '#38bdf8' }}>{tr.to}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
