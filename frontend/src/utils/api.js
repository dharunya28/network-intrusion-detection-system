import {
  inspectPacketClientSide,
  getAutomataSpecsClientSide,
  testAutomatonClientSide,
  ipv4ValidatorDFA,
} from './automataEngine';
import {
  getLocalTraffic,
  getLocalAlerts,
  getLocalStats,
  saveLocalPacketAndAlerts,
  clearLocalData,
} from './localStore';

const API_BASE = '/api';
const IP_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

const tryFetchJson = async (endpoint, options = {}) => {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, options);
    const contentType = res.headers.get('content-type') || '';
    if (res.ok && contentType.includes('application/json')) {
      const data = await res.json();
      return { ok: true, data };
    }
  } catch (e) {
    // Backend offline / network failed
  }
  return { ok: false, data: null };
};

export const fetchHealth = async () => {
  const result = await tryFetchJson('/health');
  if (result.ok && result.data) return result.data;

  return {
    status: 'UP',
    system: 'College Network Intrusion Detection System (NIDS)',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    database: { connected: false, mode: 'In-Memory / Browser' },
    automataEngine: {
      status: 'ACTIVE',
      supportedDFA: [
        'SQL Injection',
        'Cross-Site Scripting (XSS)',
        'Path Traversal',
        'IPv4 Form Validator',
      ],
    },
  };
};

export const fetchTraffic = async (limit = 100) => {
  const result = await tryFetchJson(`/traffic?limit=${limit}`);
  if (result.ok && result.data?.logs) return result.data;

  return {
    success: true,
    total: getLocalTraffic(limit).length,
    logs: getLocalTraffic(limit),
  };
};

export const fetchStats = async () => {
  const result = await tryFetchJson('/traffic/stats');
  if (result.ok && result.data?.stats) return result.data;

  return {
    success: true,
    stats: getLocalStats(),
  };
};

export const fetchAlerts = async (limit = 100) => {
  const result = await tryFetchJson(`/alerts?limit=${limit}`);
  if (result.ok && result.data?.alerts) return result.data;

  return {
    success: true,
    total: getLocalAlerts(limit).length,
    alerts: getLocalAlerts(limit),
  };
};

export const processPacket = async (packetData) => {
  // First attempt backend processing
  const backendResult = await tryFetchJson('/traffic/process', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(packetData),
  });

  if (backendResult.ok && backendResult.data) {
    return backendResult.data;
  }

  // Client-Side Automata Engine fallback
  const { sourceIP, destinationIP, port, protocol, payload } = packetData;
  const errors = {};

  // Validate IPs via IPv4 DFA + Regex
  if (!sourceIP || !sourceIP.trim()) {
    errors.sourceIP = 'Source IP is required';
  } else {
    const dfaCheck = ipv4ValidatorDFA.validate(sourceIP.trim());
    if (!dfaCheck.accepted || !IP_REGEX.test(sourceIP.trim())) {
      errors.sourceIP = 'Invalid IPv4 address format (e.g., 192.168.1.10)';
    }
  }

  if (!destinationIP || !destinationIP.trim()) {
    errors.destinationIP = 'Destination IP is required';
  } else {
    const dfaCheck = ipv4ValidatorDFA.validate(destinationIP.trim());
    if (!dfaCheck.accepted || !IP_REGEX.test(destinationIP.trim())) {
      errors.destinationIP = 'Invalid IPv4 address format (e.g., 172.16.0.5)';
    }
  }

  const portNum = Number(port);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    errors.port = 'Port must be a valid integer between 1 and 65535';
  }

  if (!payload || !payload.trim()) {
    errors.payload = 'Packet payload cannot be empty';
  }

  if (Object.keys(errors).length > 0) {
    return {
      success: false,
      message: 'Form validation failed',
      errors,
    };
  }

  // Run Formal DFA Automata & Regex Inspection
  const analysis = inspectPacketClientSide({
    sourceIP: sourceIP.trim(),
    destinationIP: destinationIP.trim(),
    port: Number(port),
    protocol: (protocol || 'HTTP').toUpperCase(),
    payload: payload.trim(),
  });

  // Save to Local Data Store
  const { savedLog, createdAlerts } = saveLocalPacketAndAlerts(packetData, analysis);

  return {
    success: true,
    message:
      analysis.status === 'NORMAL'
        ? 'Packet verified and forwarded (Clean traffic)'
        : `Alert! ${analysis.status} network activity detected`,
    log: savedLog,
    analysis,
    alerts: createdAlerts,
  };
};

export const fetchAutomataSpecs = async () => {
  const result = await tryFetchJson('/automata/specs');
  if (result.ok && result.data?.automata) return result.data;

  return getAutomataSpecsClientSide();
};

export const testAutomaton = async (automatonId, inputString) => {
  const result = await tryFetchJson('/automata/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ automatonId, inputString }),
  });

  if (result.ok && result.data) return result.data;

  return testAutomatonClientSide(automatonId, inputString);
};

export const clearData = async () => {
  const result = await tryFetchJson('/traffic', { method: 'DELETE' });
  if (result.ok && result.data) return result.data;

  return clearLocalData();
};
