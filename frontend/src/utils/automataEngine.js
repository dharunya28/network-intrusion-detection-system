/**
 * Formal Deterministic Finite Automaton (DFA) Implementation
 * M = (Q, Sigma, delta, q0, F)
 */

export class DFA {
  constructor({ id, name, description, states, alphabet, transitions, startState, acceptStates, category }) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.states = states;
    this.alphabet = alphabet;
    this.transitions = transitions;
    this.startState = startState;
    this.acceptStates = new Set(acceptStates);
    this.category = category;
  }

  transition(currentState, inputChar) {
    const stateTransitions = this.transitions[currentState];
    if (!stateTransitions) return null;

    if (stateTransitions[inputChar] !== undefined) {
      return stateTransitions[inputChar];
    }

    const lower = inputChar.toLowerCase();
    if (stateTransitions[lower] !== undefined) {
      return stateTransitions[lower];
    }
    const upper = inputChar.toUpperCase();
    if (stateTransitions[upper] !== undefined) {
      return stateTransitions[upper];
    }

    if (stateTransitions['*'] !== undefined) {
      return stateTransitions['*'];
    }

    return null;
  }

  validate(inputString) {
    if (typeof inputString !== 'string') {
      return { accepted: false, finalState: null, trace: [], error: 'Input must be a string' };
    }

    let currentState = this.startState;
    const trace = [];

    for (let i = 0; i < inputString.length; i++) {
      const char = inputString[i];
      const nextState = this.transition(currentState, char);

      trace.push({
        step: i + 1,
        fromState: currentState,
        char: char === ' ' ? '[space]' : char,
        toState: nextState || 'REJECT_TRAP',
      });

      if (!nextState) {
        return {
          accepted: false,
          finalState: 'REJECT_TRAP',
          trace,
          haltReason: `No transition defined from state '${currentState}' for symbol '${char}'`,
        };
      }

      currentState = nextState;
    }

    const accepted = this.acceptStates.has(currentState);
    return {
      accepted,
      finalState: currentState,
      trace,
      haltReason: accepted
        ? `Successfully reached accept state '${currentState}' in F`
        : `Halted in non-accepting state '${currentState}'`,
    };
  }

  scan(payload) {
    if (!payload || typeof payload !== 'string') {
      return { detected: false, matchedSubstring: null, startIndex: -1, trace: [] };
    }

    for (let start = 0; start < payload.length; start++) {
      let currentState = this.startState;
      const trace = [];

      for (let i = start; i < payload.length; i++) {
        const char = payload[i];
        const nextState = this.transition(currentState, char);

        if (!nextState) {
          break;
        }

        trace.push({
          step: trace.length + 1,
          index: i,
          fromState: currentState,
          char: char === ' ' ? '[space]' : char,
          toState: nextState,
        });

        currentState = nextState;

        if (this.acceptStates.has(currentState)) {
          return {
            detected: true,
            matchedSubstring: payload.substring(start, i + 1),
            startIndex: start,
            endIndex: i,
            trace,
            acceptState: currentState,
          };
        }
      }
    }

    return { detected: false, matchedSubstring: null, startIndex: -1, trace: [] };
  }

  getTransitionTable() {
    const table = [];
    for (const state of this.states) {
      const row = {
        state,
        isStart: state === this.startState,
        isAccept: this.acceptStates.has(state),
        transitions: {},
      };

      for (const symbol of this.alphabet) {
        const next = this.transitions[state] ? this.transitions[state][symbol] : undefined;
        row.transitions[symbol] = next || 'Trap / Nil';
      }

      table.push(row);
    }
    return table;
  }
}

// 1. SQL Injection DFA
export const sqliDFAConfig = {
  id: 'dfa-sqli',
  name: "SQL Injection Detection Automaton (' OR 1=1)",
  description: "Detects classic SQL authentication bypass injection signature ' OR 1=1",
  category: 'INTRUSION_DETECTION',
  attackType: 'SQL Injection',
  severity: 'CRITICAL',
  states: ['q0', 'q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8'],
  alphabet: ["'", ' ', 'o', 'r', '1', '='],
  startState: 'q0',
  acceptStates: ['q8'],
  transitions: {
    q0: { "'": 'q1' },
    q1: { ' ': 'q2' },
    q2: { o: 'q3', O: 'q3' },
    q3: { r: 'q4', R: 'q4' },
    q4: { ' ': 'q5' },
    q5: { '1': 'q6' },
    q6: { '=': 'q7' },
    q7: { '1': 'q8' },
    q8: {},
  },
  mermaidDiagram: `stateDiagram-v2
    [*] --> q0
    q0 --> q1 : "'"
    q1 --> q2 : " " (space)
    q2 --> q3 : "o" | "O"
    q3 --> q4 : "r" | "R"
    q4 --> q5 : " " (space)
    q5 --> q6 : "1"
    q6 --> q7 : "="
    q7 --> q8 : "1"
    q8 --> [*] : ACCEPT (SQLi Alert)
`,
  formalTuple: {
    states: 'Q = { q0, q1, q2, q3, q4, q5, q6, q7, q8 }',
    alphabet: "Σ = { ' , [space], o, r, 1, = }",
    startState: 'q0',
    acceptStates: 'F = { q8 }',
    transitionFunction: 'δ: Q × Σ → Q as specified in transition table',
  },
};

// 2. Cross-Site Scripting (XSS) DFA
export const xssDFAConfig = {
  id: 'dfa-xss',
  name: 'Cross-Site Scripting (XSS) Automaton (<script)',
  description: 'Detects unauthorized inline script injection tags in network HTTP payloads',
  category: 'INTRUSION_DETECTION',
  attackType: 'Cross-Site Scripting (XSS)',
  severity: 'HIGH',
  states: ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7'],
  alphabet: ['<', 's', 'c', 'r', 'i', 'p', 't'],
  startState: 's0',
  acceptStates: ['s7'],
  transitions: {
    s0: { '<': 's1' },
    s1: { s: 's2', S: 's2' },
    s2: { c: 's3', C: 's3' },
    s3: { r: 's4', R: 's4' },
    s4: { i: 's5', I: 's5' },
    s5: { p: 's6', P: 's6' },
    s6: { t: 's7', T: 's7' },
    s7: {},
  },
  mermaidDiagram: `stateDiagram-v2
    [*] --> s0
    s0 --> s1 : "<"
    s1 --> s2 : "s" | "S"
    s2 --> s3 : "c" | "C"
    s3 --> s4 : "r" | "R"
    s4 --> s5 : "i" | "I"
    s5 --> s6 : "p" | "P"
    s6 --> s7 : "t" | "T"
    s7 --> [*] : ACCEPT (XSS Alert)
`,
  formalTuple: {
    states: 'Q = { s0, s1, s2, s3, s4, s5, s6, s7 }',
    alphabet: 'Σ = { <, s, c, r, i, p, t }',
    startState: 's0',
    acceptStates: 'F = { s7 }',
    transitionFunction: 'δ: Q × Σ → Q as specified in transition table',
  },
};

// 3. Path Traversal DFA
export const pathTraversalDFAConfig = {
  id: 'dfa-traversal',
  name: 'Path Traversal Automaton (../../)',
  description: 'Detects unauthorized directory climb attempts (../..) in URL queries & packet payloads',
  category: 'INTRUSION_DETECTION',
  attackType: 'Path Traversal',
  severity: 'HIGH',
  states: ['p0', 'p1', 'p2', 'p3', 'p4', 'p5'],
  alphabet: ['.', '/'],
  startState: 'p0',
  acceptStates: ['p5'],
  transitions: {
    p0: { '.': 'p1' },
    p1: { '.': 'p2' },
    p2: { '/': 'p3' },
    p3: { '.': 'p4' },
    p4: { '.': 'p5' },
    p5: {},
  },
  mermaidDiagram: `stateDiagram-v2
    [*] --> p0
    p0 --> p1 : "."
    p1 --> p2 : "."
    p2 --> p3 : "/"
    p3 --> p4 : "."
    p4 --> p5 : "."
    p5 --> [*] : ACCEPT (Path Traversal Alert)
`,
  formalTuple: {
    states: 'Q = { p0, p1, p2, p3, p4, p5 }',
    alphabet: 'Σ = { . , / }',
    startState: 'p0',
    acceptStates: 'F = { p5 }',
    transitionFunction: 'δ: Q × Σ → Q as specified in transition table',
  },
};

// 4. IPv4 Form Validator DFA
const digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
const buildIPv4Transitions = () => {
  const trans = {};
  const setDigits = (fromState, toState) => {
    trans[fromState] = trans[fromState] || {};
    digits.forEach((d) => {
      trans[fromState][d] = toState;
    });
  };

  setDigits('v0', 'v1');
  setDigits('v1', 'v2');
  trans['v1'] = trans['v1'] || {};
  trans['v1']['.'] = 'v4';

  setDigits('v2', 'v3');
  trans['v2'] = trans['v2'] || {};
  trans['v2']['.'] = 'v4';

  trans['v3'] = trans['v3'] || {};
  trans['v3']['.'] = 'v4';

  setDigits('v4', 'v5');
  setDigits('v5', 'v6');
  trans['v5'] = trans['v5'] || {};
  trans['v5']['.'] = 'v8';

  setDigits('v6', 'v7');
  trans['v6'] = trans['v6'] || {};
  trans['v6']['.'] = 'v8';

  trans['v7'] = trans['v7'] || {};
  trans['v7']['.'] = 'v8';

  setDigits('v8', 'v9');
  setDigits('v9', 'v10');
  trans['v9'] = trans['v9'] || {};
  trans['v9']['.'] = 'v12';

  setDigits('v10', 'v11');
  trans['v10'] = trans['v10'] || {};
  trans['v10']['.'] = 'v12';

  trans['v11'] = trans['v11'] || {};
  trans['v11']['.'] = 'v12';

  setDigits('v12', 'v13');
  setDigits('v13', 'v14');
  setDigits('v14', 'v15');

  return trans;
};

export const ipv4ValidatorConfig = {
  id: 'dfa-ipv4-validator',
  name: 'IPv4 Address Form Input Validator Automaton',
  description: 'Deterministic Finite Automaton verifying standard 4-octet IPv4 address structure',
  category: 'FORM_VALIDATION',
  attackType: 'Input Format Compliance',
  severity: 'INFO',
  states: [
    'v0', 'v1', 'v2', 'v3', 'v4',
    'v5', 'v6', 'v7', 'v8', 'v9',
    'v10', 'v11', 'v12', 'v13', 'v14', 'v15',
  ],
  alphabet: ['0-9', '.'],
  startState: 'v0',
  acceptStates: ['v13', 'v14', 'v15'],
  transitions: buildIPv4Transitions(),
  mermaidDiagram: `stateDiagram-v2
    [*] --> v0 : Start Input
    v0 --> v1 : digit
    v1 --> v2 : digit
    v1 --> v4 : "."
    v2 --> v3 : digit
    v2 --> v4 : "."
    v3 --> v4 : "."
    v4 --> v5 : digit
    v5 --> v6 : digit
    v5 --> v8 : "."
    v6 --> v7 : digit
    v6 --> v8 : "."
    v7 --> v8 : "."
    v8 --> v9 : digit
    v9 --> v10 : digit
    v9 --> v12 : "."
    v10 --> v11 : digit
    v10 --> v12 : "."
    v11 --> v12 : "."
    v12 --> v13 : digit (Accept 1-dig)
    v13 --> v14 : digit (Accept 2-dig)
    v14 --> v15 : digit (Accept 3-dig)
    v13 --> [*] : VALID IPv4
    v14 --> [*] : VALID IPv4
    v15 --> [*] : VALID IPv4
`,
  formalTuple: {
    states: 'Q = { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 }',
    alphabet: 'Σ = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, . }',
    startState: 'v0',
    acceptStates: 'F = { v13, v14, v15 }',
    transitionFunction: 'δ: Q × Σ → Q as specified in transition table',
  },
};

export const sqliDFA = new DFA(sqliDFAConfig);
export const xssDFA = new DFA(xssDFAConfig);
export const pathTraversalDFA = new DFA(pathTraversalDFAConfig);
export const ipv4ValidatorDFA = new DFA(ipv4ValidatorConfig);

export const REGEX_RULES = [
  {
    id: 'REG-SQLI-01',
    ruleName: 'SQL Injection - UNION / SELECT / DROP Detection',
    attackType: 'SQL Injection',
    severity: 'CRITICAL',
    regex: /((\%27)|(\'))\s*(union|select|insert|update|delete|drop)\b|union\s+select/i,
    description: 'Detects SQL data exfiltration or table tampering keywords',
    mitigation: 'Use parameterized queries / prepared statements',
  },
  {
    id: 'REG-SQLI-02',
    ruleName: 'SQL Injection - Boolean Tautology (OR 1=1)',
    attackType: 'SQL Injection',
    severity: 'CRITICAL',
    regex: /((\%27)|(\'))\s*or\s+[\'\"0-9a-zA-Z]+\s*=\s*[\'\"0-9a-zA-Z]+/i,
    description: 'Detects auth bypass logic tampering',
    mitigation: 'Implement strict input validation and ORM queries',
  },
  {
    id: 'REG-XSS-01',
    ruleName: 'Cross-Site Scripting - Script Tag & Event Handler',
    attackType: 'Cross-Site Scripting (XSS)',
    severity: 'HIGH',
    regex: /<script\b[^>]*>(.*?)<\/script>|onerror\s*=|onload\s*=|javascript:/i,
    description: 'Detects malicious JavaScript execution injection in parameters',
    mitigation: 'Sanitize HTML output using DOMPurify and set Content-Security-Policy',
  },
  {
    id: 'REG-LFI-01',
    ruleName: 'Path Traversal - Sensitive File Access',
    attackType: 'Path Traversal',
    severity: 'HIGH',
    regex: /(\.\.[\/\\])+|(etc\/passwd|windows\/system32|boot\.ini)/i,
    description: 'Detects attempts to break out of webroot and read operating system files',
    mitigation: 'Disallow dot-dot-slash sequence in path parameters',
  },
  {
    id: 'REG-CMD-01',
    ruleName: 'Command Injection - Shell Metacharacters',
    attackType: 'Command Injection',
    severity: 'CRITICAL',
    regex: /(;\s*(rm|cat|ls|whoami|curl|wget|nc|powershell|cmd\.exe))|(\|\s*(bash|sh))/i,
    description: 'Detects chained shell command execution attempts',
    mitigation: 'Never pass user-supplied input to child_process or system shell',
  },
  {
    id: 'REG-PORT-01',
    ruleName: 'Suspicious Port Probe (Telnet / Metasploit / RDP)',
    attackType: 'Port Scan / Probe',
    severity: 'MEDIUM',
    check: (port) => [23, 1433, 3389, 4444, 5555, 6667].includes(Number(port)),
    description: 'Detects connection attempts to vulnerable or remote administration ports',
    mitigation: 'Enforce campus firewall ACL to drop inbound traffic on non-whitelisted ports',
  },
];

export const inspectPacketClientSide = ({ sourceIP, destinationIP, port, protocol, payload }) => {
  const dfaList = [
    { dfa: sqliDFA, attackType: 'SQL Injection', severity: 'CRITICAL', ruleName: "DFA: SQL Injection (' OR 1=1)" },
    { dfa: xssDFA, attackType: 'Cross-Site Scripting (XSS)', severity: 'HIGH', ruleName: 'DFA: XSS Injection (<script)' },
    { dfa: pathTraversalDFA, attackType: 'Path Traversal', severity: 'HIGH', ruleName: 'DFA: Directory Traversal (../..)' },
  ];

  const detectedAttacks = [];
  let threatScore = 0;

  // 1. Run Formal DFA Automata Scanning
  for (const item of dfaList) {
    const scanResult = item.dfa.scan(payload);
    if (scanResult.detected) {
      detectedAttacks.push({
        ruleId: item.dfa.id,
        ruleName: item.ruleName,
        attackType: item.attackType,
        severity: item.severity,
        matchedPattern: scanResult.matchedSubstring,
        matchedBy: 'DFA_AUTOMATON',
        automataTrace: scanResult.trace,
      });

      threatScore += item.severity === 'CRITICAL' ? 50 : 35;
    }
  }

  // 2. Run Regular Expression Rules
  for (const rule of REGEX_RULES) {
    if (rule.regex) {
      const match = payload.match(rule.regex);
      if (match) {
        const alreadyMatched = detectedAttacks.some(
          (a) => a.ruleName === rule.ruleName || a.matchedPattern === match[0]
        );

        if (!alreadyMatched) {
          detectedAttacks.push({
            ruleId: rule.id,
            ruleName: rule.ruleName,
            attackType: rule.attackType,
            severity: rule.severity,
            matchedPattern: match[0],
            matchedBy: 'REGEX_SIGNATURE',
            automataTrace: [],
          });

          threatScore += rule.severity === 'CRITICAL' ? 45 : 30;
        }
      }
    } else if (rule.check && rule.check(port)) {
      detectedAttacks.push({
        ruleId: rule.id,
        ruleName: rule.ruleName,
        attackType: rule.attackType,
        severity: rule.severity,
        matchedPattern: `Targeted Port ${port}`,
        matchedBy: 'REGEX_SIGNATURE',
        automataTrace: [],
      });
      threatScore += 25;
    }
  }

  let status = 'NORMAL';
  let actionTaken = 'FORWARDED';

  if (threatScore >= 40) {
    status = 'MALICIOUS';
    actionTaken = threatScore >= 70 ? 'BLOCKED' : 'DROPPED';
  } else if (threatScore > 0) {
    status = 'SUSPICIOUS';
    actionTaken = 'ALERTED';
  }

  return {
    status,
    threatScore: Math.min(threatScore, 100),
    detectedAttacks,
    actionTaken,
  };
};

export const getAutomataSpecsClientSide = () => {
  return {
    success: true,
    total: 4,
    automata: [
      { ...sqliDFAConfig, transitionTable: sqliDFA.getTransitionTable() },
      { ...xssDFAConfig, transitionTable: xssDFA.getTransitionTable() },
      { ...pathTraversalDFAConfig, transitionTable: pathTraversalDFA.getTransitionTable() },
      { ...ipv4ValidatorConfig, transitionTable: ipv4ValidatorDFA.getTransitionTable() },
    ],
  };
};

export const testAutomatonClientSide = (automatonId, inputString) => {
  let targetDFA = ipv4ValidatorDFA;
  let targetConfig = ipv4ValidatorConfig;

  switch (automatonId) {
    case 'dfa-sqli':
      targetDFA = sqliDFA;
      targetConfig = sqliDFAConfig;
      break;
    case 'dfa-xss':
      targetDFA = xssDFA;
      targetConfig = xssDFAConfig;
      break;
    case 'dfa-traversal':
      targetDFA = pathTraversalDFA;
      targetConfig = pathTraversalDFAConfig;
      break;
    case 'dfa-ipv4-validator':
    default:
      targetDFA = ipv4ValidatorDFA;
      targetConfig = ipv4ValidatorConfig;
      break;
  }

  const validationResult = targetDFA.validate(inputString);
  const scanResult = targetDFA.scan(inputString);

  return {
    success: true,
    automaton: {
      id: targetConfig.id,
      name: targetConfig.name,
      formalTuple: targetConfig.formalTuple,
      mermaidDiagram: targetConfig.mermaidDiagram,
    },
    inputString,
    fullValidation: validationResult,
    substringScan: scanResult,
  };
};
