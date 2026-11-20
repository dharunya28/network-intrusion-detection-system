/**
 * Local Data Store with localStorage Persistence
 * Provides high-fidelity resilient storage when backend API is disconnected (e.g. GitHub Pages)
 */

const STORAGE_TRAFFIC_KEY = 'college_nids_traffic';
const STORAGE_ALERTS_KEY = 'college_nids_alerts';

const INITIAL_TRAFFIC = [
  {
    _id: 'seed_trf_01',
    sourceIP: '198.51.100.44',
    destinationIP: '172.16.0.5',
    port: 80,
    protocol: 'HTTP',
    payload: 'GET /search?q=<script>alert(document.domain)</script> HTTP/1.1',
    status: 'MALICIOUS',
    threatScore: 85,
    actionTaken: 'BLOCKED',
    detectedAttacks: [
      {
        ruleId: 'dfa-xss',
        ruleName: 'DFA: XSS Injection (<script)',
        attackType: 'Cross-Site Scripting (XSS)',
        severity: 'HIGH',
        matchedPattern: '<script',
        matchedBy: 'DFA_AUTOMATON',
      },
    ],
    createdAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
  },
  {
    _id: 'seed_trf_02',
    sourceIP: '203.0.113.12',
    destinationIP: '172.16.0.10',
    port: 80,
    protocol: 'HTTP',
    payload: 'GET /download?file=../../../../etc/passwd HTTP/1.1',
    status: 'MALICIOUS',
    threatScore: 85,
    actionTaken: 'BLOCKED',
    detectedAttacks: [
      {
        ruleId: 'dfa-traversal',
        ruleName: 'DFA: Directory Traversal (../..)',
        attackType: 'Path Traversal',
        severity: 'HIGH',
        matchedPattern: '../../',
        matchedBy: 'DFA_AUTOMATON',
      },
    ],
    createdAt: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
  },
  {
    _id: 'seed_trf_03',
    sourceIP: '10.10.5.88',
    destinationIP: '172.16.0.5',
    port: 80,
    protocol: 'HTTP',
    payload: "POST /login HTTP/1.1\\r\\nusername=admin' OR 1=1--&password=x",
    status: 'MALICIOUS',
    threatScore: 95,
    actionTaken: 'BLOCKED',
    detectedAttacks: [
      {
        ruleId: 'dfa-sqli',
        ruleName: "DFA: SQL Injection (' OR 1=1)",
        attackType: 'SQL Injection',
        severity: 'CRITICAL',
        matchedPattern: "' OR 1=1",
        matchedBy: 'DFA_AUTOMATON',
      },
    ],
    createdAt: new Date(Date.now() - 1000 * 60 * 10).toISOString(),
  },
  {
    _id: 'seed_trf_04',
    sourceIP: '192.168.1.99',
    destinationIP: '172.16.0.12',
    port: 8080,
    protocol: 'HTTP',
    payload: 'POST /tools/ping?host=127.0.0.1; cat /etc/shadow',
    status: 'MALICIOUS',
    threatScore: 90,
    actionTaken: 'BLOCKED',
    detectedAttacks: [
      {
        ruleId: 'REG-CMD-01',
        ruleName: 'Command Injection - Shell Metacharacters',
        attackType: 'Command Injection',
        severity: 'CRITICAL',
        matchedPattern: '; cat',
        matchedBy: 'REGEX_SIGNATURE',
      },
    ],
    createdAt: new Date(Date.now() - 1000 * 60 * 6).toISOString(),
  },
  {
    _id: 'seed_trf_05',
    sourceIP: '198.51.100.99',
    destinationIP: '172.16.0.2',
    port: 23,
    protocol: 'TCP',
    payload: 'TCP SYN Packet handshake probe on port 23',
    status: 'SUSPICIOUS',
    threatScore: 25,
    actionTaken: 'ALERTED',
    detectedAttacks: [
      {
        ruleId: 'REG-PORT-01',
        ruleName: 'Suspicious Port Probe (Telnet / Metasploit / RDP)',
        attackType: 'Port Scan / Probe',
        severity: 'MEDIUM',
        matchedPattern: 'Targeted Port 23',
        matchedBy: 'REGEX_SIGNATURE',
      },
    ],
    createdAt: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
  },
  {
    _id: 'seed_trf_06',
    sourceIP: '192.168.10.15',
    destinationIP: '172.16.0.5',
    port: 80,
    protocol: 'HTTP',
    payload: 'GET /courses/syllabus?dept=cse&year=3 HTTP/1.1\\r\\nHost: college.edu',
    status: 'NORMAL',
    threatScore: 0,
    actionTaken: 'FORWARDED',
    detectedAttacks: [],
    createdAt: new Date(Date.now() - 1000 * 60 * 1).toISOString(),
  },
];

const INITIAL_ALERTS = [
  {
    _id: 'seed_alt_01',
    ruleId: 'dfa-xss',
    ruleName: 'DFA: XSS Injection (<script)',
    attackType: 'Cross-Site Scripting (XSS)',
    severity: 'HIGH',
    sourceIP: '198.51.100.44',
    destinationIP: '172.16.0.5',
    port: 80,
    protocol: 'HTTP',
    payloadSnippet: '<script>alert(document.domain)</script>',
    matchedPattern: '<script',
    detectionMechanism: 'DFA_AUTOMATON',
    status: 'ACTIVE',
    recommendedAction: 'Log security event, inspect access logs, and rate limit subnet.',
    createdAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
  },
  {
    _id: 'seed_alt_02',
    ruleId: 'dfa-traversal',
    ruleName: 'DFA: Directory Traversal (../..)',
    attackType: 'Path Traversal',
    severity: 'HIGH',
    sourceIP: '203.0.113.12',
    destinationIP: '172.16.0.10',
    port: 80,
    protocol: 'HTTP',
    payloadSnippet: '../../../../etc/passwd',
    matchedPattern: '../../',
    detectionMechanism: 'DFA_AUTOMATON',
    status: 'ACTIVE',
    recommendedAction: 'Log security event, inspect access logs, and rate limit subnet.',
    createdAt: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
  },
  {
    _id: 'seed_alt_03',
    ruleId: 'dfa-sqli',
    ruleName: "DFA: SQL Injection (' OR 1=1)",
    attackType: 'SQL Injection',
    severity: 'CRITICAL',
    sourceIP: '10.10.5.88',
    destinationIP: '172.16.0.5',
    port: 80,
    protocol: 'HTTP',
    payloadSnippet: "' OR 1=1",
    matchedPattern: "' OR 1=1",
    detectionMechanism: 'DFA_AUTOMATON',
    status: 'ACTIVE',
    recommendedAction: 'Immediately terminate TCP session and block source IP in campus firewall.',
    createdAt: new Date(Date.now() - 1000 * 60 * 10).toISOString(),
  },
  {
    _id: 'seed_alt_04',
    ruleId: 'REG-SQLI-01',
    ruleName: 'SQL Injection - UNION / SELECT / DROP Detection',
    attackType: 'SQL Injection',
    severity: 'CRITICAL',
    sourceIP: '10.10.5.88',
    destinationIP: '172.16.0.5',
    port: 80,
    protocol: 'HTTP',
    payloadSnippet: "' UNION SELECT username, password FROM users--",
    matchedPattern: "' UNION SELECT",
    detectionMechanism: 'REGEX_SIGNATURE',
    status: 'ACTIVE',
    recommendedAction: 'Immediately terminate TCP session and block source IP in campus firewall.',
    createdAt: new Date(Date.now() - 1000 * 60 * 9).toISOString(),
  },
  {
    _id: 'seed_alt_05',
    ruleId: 'REG-CMD-01',
    ruleName: 'Command Injection - Shell Metacharacters',
    attackType: 'Command Injection',
    severity: 'CRITICAL',
    sourceIP: '192.168.1.99',
    destinationIP: '172.16.0.12',
    port: 8080,
    protocol: 'HTTP',
    payloadSnippet: '; cat /etc/shadow',
    matchedPattern: '; cat',
    detectionMechanism: 'REGEX_SIGNATURE',
    status: 'ACTIVE',
    recommendedAction: 'Immediately terminate TCP session and block source IP in campus firewall.',
    createdAt: new Date(Date.now() - 1000 * 60 * 6).toISOString(),
  },
  {
    _id: 'seed_alt_06',
    ruleId: 'REG-PORT-01',
    ruleName: 'Suspicious Port Probe (Telnet / Metasploit / RDP)',
    attackType: 'Port Scan / Probe',
    severity: 'MEDIUM',
    sourceIP: '198.51.100.99',
    destinationIP: '172.16.0.2',
    port: 23,
    protocol: 'TCP',
    payloadSnippet: 'Targeted Port 23',
    matchedPattern: 'Targeted Port 23',
    detectionMechanism: 'REGEX_SIGNATURE',
    status: 'ACTIVE',
    recommendedAction: 'Enforce campus firewall ACL to drop inbound traffic on non-whitelisted ports.',
    createdAt: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
  },
];

const loadFromStorage = (key, fallback) => {
  try {
    const raw = localStorage.getItem(key);
    if (raw) return JSON.parse(raw);
  } catch (e) {
    // Ignore storage parse issues
  }
  return fallback;
};

const saveToStorage = (key, data) => {
  try {
    localStorage.setItem(key, JSON.stringify(data));
  } catch (e) {
    // Ignore quota issues
  }
};

export const getLocalTraffic = (limit = 100) => {
  const traffic = loadFromStorage(STORAGE_TRAFFIC_KEY, INITIAL_TRAFFIC);
  return traffic.slice(0, Number(limit));
};

export const getLocalAlerts = (limit = 100) => {
  const alerts = loadFromStorage(STORAGE_ALERTS_KEY, INITIAL_ALERTS);
  return alerts.slice(0, Number(limit));
};

export const getLocalStats = () => {
  const traffic = loadFromStorage(STORAGE_TRAFFIC_KEY, INITIAL_TRAFFIC);
  const alerts = loadFromStorage(STORAGE_ALERTS_KEY, INITIAL_ALERTS);

  const totalPackets = traffic.length;
  const maliciousCount = traffic.filter((t) => t.status === 'MALICIOUS').length;
  const suspiciousCount = traffic.filter((t) => t.status === 'SUSPICIOUS').length;
  const cleanCount = traffic.filter((t) => t.status === 'NORMAL').length;

  const attackTypeBreakdown = {};
  alerts.forEach((alt) => {
    attackTypeBreakdown[alt.attackType] = (attackTypeBreakdown[alt.attackType] || 0) + 1;
  });

  const protocolBreakdown = {};
  traffic.forEach((t) => {
    protocolBreakdown[t.protocol] = (protocolBreakdown[t.protocol] || 0) + 1;
  });

  return {
    totalPackets,
    maliciousPackets: maliciousCount,
    suspiciousPackets: suspiciousCount,
    cleanPackets: cleanCount,
    activeAlerts: alerts.filter((a) => a.status === 'ACTIVE').length,
    attackTypeBreakdown,
    protocolBreakdown,
    detectionRatio: totalPackets > 0 ? (((maliciousCount + suspiciousCount) / totalPackets) * 100).toFixed(1) : '0.0',
  };
};

export const saveLocalPacketAndAlerts = (packetData, analysis) => {
  const traffic = loadFromStorage(STORAGE_TRAFFIC_KEY, INITIAL_TRAFFIC);
  const alerts = loadFromStorage(STORAGE_ALERTS_KEY, INITIAL_ALERTS);

  const logId = 'trf_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);
  const newLog = {
    _id: logId,
    sourceIP: packetData.sourceIP.trim(),
    destinationIP: packetData.destinationIP.trim(),
    port: Number(packetData.port),
    protocol: packetData.protocol.toUpperCase(),
    payload: packetData.payload.trim(),
    status: analysis.status,
    threatScore: analysis.threatScore,
    detectedAttacks: analysis.detectedAttacks,
    actionTaken: analysis.actionTaken,
    createdAt: new Date().toISOString(),
  };

  traffic.unshift(newLog);
  if (traffic.length > 500) traffic.pop();
  saveToStorage(STORAGE_TRAFFIC_KEY, traffic);

  const createdAlerts = [];
  for (const attack of analysis.detectedAttacks) {
    const alertId = 'alt_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);
    const newAlert = {
      _id: alertId,
      ruleId: attack.ruleId,
      ruleName: attack.ruleName,
      attackType: attack.attackType,
      severity: attack.severity,
      sourceIP: packetData.sourceIP.trim(),
      destinationIP: packetData.destinationIP.trim(),
      port: Number(packetData.port),
      protocol: packetData.protocol.toUpperCase(),
      payloadSnippet: attack.matchedPattern || packetData.payload.trim().substring(0, 60),
      fullPayload: packetData.payload.trim(),
      matchedPattern: attack.matchedPattern,
      detectionMechanism: attack.matchedBy,
      automataTrace: attack.automataTrace || [],
      status: 'ACTIVE',
      recommendedAction:
        attack.severity === 'CRITICAL'
          ? 'Immediately terminate TCP session and block source IP in campus firewall.'
          : 'Log security event, inspect access logs, and rate limit subnet.',
      createdAt: new Date().toISOString(),
    };
    alerts.unshift(newAlert);
    createdAlerts.push(newAlert);
  }

  if (alerts.length > 300) alerts.length = 300;
  saveToStorage(STORAGE_ALERTS_KEY, alerts);

  return {
    savedLog: newLog,
    createdAlerts,
  };
};

export const clearLocalData = () => {
  saveToStorage(STORAGE_TRAFFIC_KEY, []);
  saveToStorage(STORAGE_ALERTS_KEY, []);
  return { message: 'All traffic and alert records cleared successfully.' };
};
