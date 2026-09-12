/**
 * mcp-server-audit — core scanning engine
 * 14 automated configuration-level security checks mapped to OWASP AISVS 1.0
 *
 * Scope (be honest about what this is):
 *  - This module performs STATIC, CONFIGURATION-LEVEL checks on MCP client/server
 *    configuration (mcpServers blocks in JSON/YAML).
 *  - The 5 "enforceable" checks (TLS, auth, hardcoded secrets, SSRF, version pinning)
 *    validate properties that genuinely live in this config file.
 *  - The other 9 are ADVISORY runtime/agent controls (timeouts, allowlists, budgets,
 *    logging, validation, kill switch, sandbox). They cannot be verified from a client
 *    config block — they are enforced by the agent runtime or server code, and are the
 *    subject of the separate 116-check manual audit / CCS runtime verification. We
 *    therefore never emit a high-severity WARN for their absence here; that would be a
 *    false positive that pressures users into adding config keys that do nothing.
 *  - Deep source-level/tool-poisoning analysis is NOT part of this CLI.
 */

'use strict';

// A server entry is a local stdio subprocess when it launches a command and has no
// remote URL. Local subprocesses use no network Authorization header and are exempt
// from transport-only (TLS / network-auth) requirements.
function isLocalStdio(s) {
  return !!s && !s.url && (!!s.command || Array.isArray(s.args));
}

// Package launchers that resolve a package from a registry at run time.
const REGISTRY_LAUNCHERS = ['npx', 'npm', 'pnpm', 'yarn', 'pnpmx', 'bunx', 'deno'];

// An argument token is considered version-pinned only when it carries an EXACT
// semver (pkg@1.2.3 / @scope/pkg@1.2.3). Bare names, tags (@latest) and ranges
// (^1.2.3, ~1.2.3, >=1) are not pinned.
const EXACT_PIN = /^(@?[a-z0-9_.-]+\/)?[a-z0-9_.-]+@\d+\.\d+\.\d+(?:[-+][\w.]+)?$/i;

function looksLikeCredentialKey(k) {
  return /(^|_)(api[_-]?key|token|secret|auth|credential|password)(s|$)/i.test(k);
}

const CHECKS = [
  {
    id: 'mcp-tls',
    category: 'MCP Transport (OWASP AISVS C10)',
    name: 'Encrypted transport (HTTPS/TLS)',
    severity: 'critical',
    confidence: 'high',
    aisvs: 'C10.1',
    check: (cfg) => {
      const servers = getServers(cfg);
      if (!servers.length) return 'info';
      return servers.every(s => !s.url || s.url.startsWith('https://') || s.url.startsWith('stdio:')) ? 'pass' : 'fail';
    },
    fix: 'Every remote MCP server URL must use https://. Plaintext http:// exposes tool traffic and credentials on the network. Local stdio servers are exempt.'
  },
  {
    id: 'mcp-auth',
    category: 'MCP Transport (OWASP AISVS C10)',
    name: 'Server authentication configured',
    severity: 'high',
    confidence: 'medium',
    aisvs: 'C10.2',
    check: (cfg) => {
      const servers = getServers(cfg);
      if (!servers.length) return 'info';
      const remote = servers.filter(s => s.url);
      if (!remote.length) return 'info'; // all servers are local stdio; auth is handled out-of-band
      const authed = remote.some(s =>
        s.headers?.authorization || s.headers?.Authorization ||
        Object.keys(s.env || {}).some(k => looksLikeCredentialKey(k) && !/^\$\{.*\}$/.test(String(s.env[k])))
      );
      return authed ? 'pass' : 'warn';
    },
    fix: 'For remote (URL-based) servers, send an Authorization header or an API-key/token env var so the server rejects unauthenticated callers. Local stdio servers are exempt.'
  },
  {
    id: 'mcp-timeout',
    category: 'Agent runtime controls (advisory — OWASP AISVS C9)',
    name: 'Connection / request timeout',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C9.1',
    check: (cfg) => JSON.stringify(cfg).includes('timeout') ? 'pass' : 'info',
    fix: 'Advisory: set a timeout so a hung or malicious server cannot stall the agent. Usually enforced by the agent runtime rather than this config block.'
  },
  {
    id: 'cred-exposure',
    category: 'Access Control (OWASP AISVS C5)',
    name: 'Hardcoded secrets in config',
    severity: 'critical',
    confidence: 'high',
    aisvs: 'C5.1',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      const patterns = [
        /sk-[a-zA-Z0-9]{20,}/,
        /AKIA[A-Z0-9]{16}/,
        /ghp_[a-zA-Z0-9]{36}/,
        /github_pat_[A-Za-z0-9_]{20,}/,
        /xox[baprs]-[A-Za-z0-9-]{10,}/,
        /password\s*:\s*["'][^"']+["']/i
      ];
      return patterns.some(p => p.test(str)) ? 'fail' : 'pass';
    },
    fix: 'Never commit real API keys/tokens in the config. Reference environment variables (e.g. ${API_KEY}) or a secret manager instead.'
  },
  {
    id: 'allowed-tools',
    category: 'Agent runtime controls (advisory — OWASP AISVS C9)',
    name: 'Tool allowlist (least privilege)',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C9.3',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('allowed_tools') || str.includes('allowedTools') || str.includes('permissions')) ? 'pass' : 'info';
    },
    fix: 'Advisory: restrict callable tools with an allowlist/permissions block. Often configured in the client/runtime, not in mcpServers.'
  },
  {
    id: 'budget-limit',
    category: 'Agent runtime controls (advisory — OWASP AISVS C9)',
    name: 'Token / cost budget cap',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C9.1',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('budget') || str.includes('max_tokens') || str.includes('token_limit') || str.includes('cost_limit')) ? 'pass' : 'info';
    },
    fix: 'Advisory: set a token/cost ceiling to bound blast radius from injection-driven tool loops. Enforced by the agent runtime.'
  },
  {
    id: 'ssrf-protection',
    category: 'MCP Transport (OWASP AISVS C10)',
    name: 'No internal / cloud-metadata endpoints',
    severity: 'critical',
    confidence: 'high',
    aisvs: 'C10.3',
    check: (cfg) => {
      const servers = getServers(cfg);
      const urls = servers.map(s => s.url || '').join(' ');
      const internal = /169\.254\.|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|localhost|127\.0\.0\.1|0\.0\.0\.0|::1/i;
      return internal.test(urls) ? 'fail' : 'pass';
    },
    fix: 'Do not point remote MCP server URLs at internal hosts or the cloud metadata endpoint (169.254.169.254); this is a classic SSRF path to instance credentials.'
  },
  {
    id: 'logging',
    category: 'Monitoring (advisory — OWASP AISVS C12)',
    name: 'Audit logging enabled',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C12.1',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('log') || str.includes('audit') || str.includes('trace') || str.includes('telemetry')) ? 'pass' : 'info';
    },
    fix: 'Advisory: enable audit logging of agent/tool calls. Normally a runtime/server-side control, verified in the manual audit.'
  },
  {
    id: 'sandbox',
    category: 'Infrastructure (advisory — OWASP AISVS C4)',
    name: 'Sandbox isolation considered',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C4.1',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('sandbox') || str.includes('isolation') || str.includes('container') || str.includes('docker')) ? 'pass' : 'info';
    },
    fix: 'Advisory: run MCP servers in a sandbox/container with scoped filesystem and network access.'
  },
  {
    id: 'version-pin',
    category: 'Supply Chain (OWASP AISVS C6)',
    name: 'Package / command version pinning',
    severity: 'medium',
    confidence: 'high',
    aisvs: 'C6.1',
    check: (cfg) => {
      const servers = getServers(cfg);
      if (!servers.length) return 'info';
      let sawUnpinned = false;
      for (const s of servers) {
        if (s.version) continue;                                       // explicit version: pinned
        if (s.url) continue;                                           // remote service: versioning is server-side
        if (!s.command) { sawUnpinned = true; continue; }
        const cmd = String(s.command).toLowerCase().split(/[\\/]/).pop();
        const args = (s.args || []).map(String);
        if (REGISTRY_LAUNCHERS.some(l => cmd === l || cmd === `${l}.cmd` || cmd === `${l}.exe`)) {
          // Launched from a registry: a bare package name (or one with -y and no
          // @exact-version) resolves "latest" on every run → rug-pull exposure.
          if (!args.some(a => EXACT_PIN.test(a))) sawUnpinned = true;
        }
        // A local binary / script (node ./server.js, /usr/bin/mcp-*) is not fetched
        // from a registry, so there is nothing in the config to pin → advisory only.
      }
      return sawUnpinned ? 'warn' : 'pass';
    },
    fix: 'Pin registry-launched MCP packages to an exact version (e.g. `npx -y some-mcp@1.2.3`). `npx -y some-mcp` pulls whatever "latest" is on every run, which is a supply-chain rug-pull risk.'
  },
  {
    id: 'error-handling',
    category: 'Monitoring (advisory — OWASP AISVS C12)',
    name: 'Error handling / fail-safe',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C12.2',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('retry') || str.includes('fallback') || str.includes('on_error')) ? 'pass' : 'info';
    },
    fix: 'Advisory: configure retry/fallback/fail-closed behaviour so the agent degrades safely. Enforced by the runtime/server.'
  },
  {
    id: 'input-validation',
    category: 'Input Validation (advisory — OWASP AISVS C2)',
    name: 'Input validation / sanitization',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C2.1',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('validation') || str.includes('schema') || str.includes('input_check') || str.includes('sanitize')) ? 'pass' : 'info';
    },
    fix: 'Advisory: validate/sanitize tool inputs to reduce prompt-injection and encoding smuggling. This is a runtime/code-level control, not a client config key.'
  },
  {
    id: 'output-validation',
    category: 'Output Control (advisory — OWASP AISVS C7)',
    name: 'Output validation / filtering',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C7.1',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('output') || str.includes('response_check') || str.includes('filter')) ? 'pass' : 'info';
    },
    fix: 'Advisory: validate tool output shape and filter sensitive data before it reaches the model. Enforced at runtime; verified in the manual audit.'
  },
  {
    id: 'kill-switch',
    category: 'Agent runtime controls (advisory — OWASP AISVS C9)',
    name: 'Kill switch / circuit breaker',
    severity: 'low',
    confidence: 'low',
    aisvs: 'C9.5',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('kill') || str.includes('circuit_breaker') || str.includes('emergency') || str.includes('abort')) ? 'pass' : 'info';
    },
    fix: 'Advisory: provide a kill switch/circuit breaker to halt the agent on anomalous tool activity. A runtime control, covered by CCS runtime verification.'
  }
];

function getServers(cfg) {
  if (cfg.mcpServers) return Object.values(cfg.mcpServers);
  if (cfg.servers) return cfg.servers;
  if (Array.isArray(cfg)) return cfg;
  return [];
}

/**
 * Run all 14 checks against a parsed config object.
 * @param {Object} config parsed MCP config
 * @returns {{results: Array, stats: Object}}
 */
function runScan(config) {
  const results = CHECKS.map(check => {
    let status;
    try {
      status = check.check(config);
    } catch (e) {
      status = 'info';
    }
    return {
      id: check.id,
      category: check.category,
      name: check.name,
      severity: check.severity,
      confidence: check.confidence,
      aisvs: check.aisvs,
      fix: check.fix,
      status
    };
  });

  const pass = results.filter(r => r.status === 'pass').length;
  const warn = results.filter(r => r.status === 'warn').length;
  const fail = results.filter(r => r.status === 'fail').length;
  const info = results.filter(r => r.status === 'info').length;
  const total = results.length;
  const score = Math.round(((pass * 10 + warn * 5 + info * 7) / (total * 10)) * 100);

  return { results, stats: { pass, warn, fail, info, total, score } };
}

/**
 * Parse config content. JSON/.toml parsed as JSON; other text falls back to a
 * minimal indentation-based YAML parser sufficient for flat mcpServers blocks.
 */
function parseConfig(rawContent, filename = '') {
  // Strip a UTF-8 BOM (common on Windows, e.g. files saved by Notepad/PowerShell
  // `Set-Content -Encoding UTF8`); otherwise JSON.parse throws and the file is
  // silently skipped, producing a dangerous false "0 findings".
  const content = rawContent.charCodeAt(0) === 0xFEFF ? rawContent.slice(1) : rawContent;
  if (filename.endsWith('.json') || filename.endsWith('.toml')) {
    return JSON.parse(content);
  }
  try { return JSON.parse(content); } catch (e) { /* fall through */ }
  return parseSimpleYAML(content);
}

function parseSimpleYAML(text) {
  const result = {};
  const lines = text.split('\n');
  const currentPath = [];
  const indentStack = [-1];
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const indent = line.search(/\S/);
    const match = line.trim().match(/^([^:]+):\s*(.*)/);
    if (!match) continue;
    const key = match[1].trim();
    let val = match[2].trim();
    while (indentStack.length > 1 && indent <= indentStack[indentStack.length - 1]) {
      indentStack.pop();
      currentPath.pop();
    }
    if (val === '' || val === '{}' || val === '[]') {
      currentPath.push(key);
      indentStack.push(indent);
    } else {
      val = val.replace(/^["']|["']$/g, '');
      setNestedValue(result, [...currentPath, key], val);
    }
  }
  return result;
}

function setNestedValue(obj, path, value) {
  let current = obj;
  for (let i = 0; i < path.length - 1; i++) {
    if (!current[path[i]]) current[path[i]] = {};
    current = current[path[i]];
  }
  current[path[path.length - 1]] = value;
}

const KNOWN_CONFIG_PATHS = [
  '.cursor/mcp.json',
  'claude_desktop_config.json',
  '.claude/mcp.json',
  'mcp.json',
  'mcp.yaml',
  'mcp.yml',
  '.vscode/mcp.json',
  'config/mcp.json',
  '.mcp/mcp.json',
  'mcp_config.json'
];

module.exports = { CHECKS, runScan, parseConfig, getServers, KNOWN_CONFIG_PATHS };
