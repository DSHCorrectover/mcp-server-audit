#!/usr/bin/env node
/**
 * Test suite for mcp-server-audit.
 * Tests only the checks that actually exist (14 automated config checks).
 */

'use strict';

const { CHECKS, runScan, parseConfig, getServers } = require('./core/scanner');

let pass = 0;
let fail = 0;

function assert(cond, name) {
  if (cond) { pass++; console.log(`  \u2705 ${name}`); }
  else { fail++; console.log(`  \u274c ${name}`); }
}

function statusOf(report, id) {
  const r = report.results.find(x => x.id === id);
  return r ? r.status : undefined;
}

console.log('\n[1] Engine shape');
assert(Array.isArray(CHECKS), 'CHECKS is an array');
assert(CHECKS.length === 14, `Exactly 14 automated checks (got ${CHECKS.length})`);
assert(CHECKS.every(c => c.id && c.name && c.severity && typeof c.check === 'function' && c.fix), 'Every check has id/name/severity/check/fix');
const ids = CHECKS.map(c => c.id);
assert(new Set(ids).size === ids.length, 'Check ids are unique');

console.log('\n[2] Transport checks (real high-severity gates)');
assert(statusOf(runScan({ mcpServers: { a: { url: 'http://example.com' } } }), 'mcp-tls') === 'fail', 'mcp-tls FAIL on plaintext http://');
assert(statusOf(runScan({ mcpServers: { a: { url: 'https://example.com' } } }), 'mcp-tls') === 'pass', 'mcp-tls PASS on https://');
assert(statusOf(runScan({ mcpServers: { a: { command: 'node', args: ['s.js'] } } }), 'mcp-tls') === 'pass', 'mcp-tls PASS for local stdio command');
assert(statusOf(runScan({ mcpServers: { a: { url: 'http://169.254.169.254/latest/meta-data/' } } }), 'ssrf-protection') === 'fail', 'ssrf FAIL on cloud metadata endpoint');
assert(statusOf(runScan({ mcpServers: { a: { url: 'http://192.168.1.1' } } }), 'ssrf-protection') === 'fail', 'ssrf FAIL on RFC1918 internal address');
assert(statusOf(runScan({ mcpServers: { a: { url: 'http://10.0.0.5' } } }), 'ssrf-protection') === 'fail', 'ssrf FAIL on 10.x internal address');
assert(statusOf(runScan({ mcpServers: { a: { url: 'https://api.example.com' } } }), 'ssrf-protection') === 'pass', 'ssrf PASS on public https host');

console.log('\n[3] Secrets / access control (real critical gates)');
assert(statusOf(runScan({ mcpServers: { a: { env: { TOKEN: 'sk-' + 'a'.repeat(30) } } } }), 'cred-exposure') === 'fail', 'cred-exposure FAIL on sk- key');
assert(statusOf(runScan({ mcpServers: { a: { env: { AK: 'AKIA' + 'A'.repeat(16) } } } }), 'cred-exposure') === 'fail', 'cred-exposure FAIL on AWS access key id');
assert(statusOf(runScan({ mcpServers: { a: { env: { GH: 'ghp_' + 'a'.repeat(36) } } } }), 'cred-exposure') === 'fail', 'cred-exposure FAIL on GitHub token');
assert(statusOf(runScan({ mcpServers: { a: { env: { API_KEY: '${API_KEY}' } } } }), 'cred-exposure') === 'pass', 'cred-exposure PASS when only env reference present');

console.log('\n[4] Authentication semantics');
assert(statusOf(runScan({ mcpServers: { a: { url: 'https://x' } } }), 'mcp-auth') === 'warn', 'mcp-auth WARN on remote server without auth');
assert(statusOf(runScan({ mcpServers: { a: { url: 'https://x', headers: { authorization: 'Bearer t' } } } }), 'mcp-auth') === 'pass', 'mcp-auth PASS with authorization header');
assert(statusOf(runScan({ mcpServers: { a: { command: 'npx', args: ['-y', 'some-mcp'] } } }), 'mcp-auth') === 'info', 'mcp-auth INFO (exempt) for local stdio launch with no network auth header');
assert(statusOf(runScan({ mcpServers: { a: { url: 'https://x', env: { SERVICE_TOKEN: 'abc123' } } } }), 'mcp-auth') === 'pass', 'mcp-auth PASS when a token-like env var is provided for a remote server');

console.log('\n[5] Supply-chain version pinning (must catch unpinned npx)');
assert(statusOf(runScan({ mcpServers: { a: { command: 'npx', args: ['-y', 'some-mcp'] } } }), 'version-pin') === 'warn', 'version-pin WARN: bare `npx -y pkg` resolves latest (rug-pull)');
assert(statusOf(runScan({ mcpServers: { a: { command: 'npx', args: ['-y', 'some-mcp@1.2.3'] } } }), 'version-pin') === 'pass', 'version-pin PASS: exact `pkg@1.2.3` is pinned');
assert(statusOf(runScan({ mcpServers: { a: { command: 'npx', args: ['-y', '@scope/pkg@2.0.0'] } } }), 'version-pin') === 'pass', 'version-pin PASS: scoped `@scope/pkg@2.0.0` is pinned');
assert(statusOf(runScan({ mcpServers: { a: { command: 'node', args: ['./s.js'] } } }), 'version-pin') === 'pass', 'version-pin PASS for a local binary (nothing registry-fetched to pin)');
assert(statusOf(runScan({ mcpServers: { a: { command: 'npx', args: ['-y', 'some-mcp@latest'] } } }), 'version-pin') === 'warn', 'version-pin WARN: tag @latest is not an exact pin');

console.log('\n[6] Advisory runtime controls: absence = info, not noise');
const minimal = runScan({ mcpServers: { a: { command: 'node', args: ['./s.js'] } } });
for (const id of ['mcp-timeout','allowed-tools','budget-limit','logging','sandbox','error-handling','input-validation','output-validation','kill-switch']) {
  assert(statusOf(minimal, id) === 'info', `${id} is INFO (advisory) when absent, not a high WARN`);
}
assert(statusOf(runScan({ mcpServers: { a: { url: 'https://x', allowed_tools: ['t'] } } }), 'allowed-tools') === 'pass', 'allowed-tools PASS when explicitly configured');
assert(statusOf(runScan({ mcpServers: { a: { url: 'https://x' } } }), 'kill-switch') === 'info', 'kill-switch INFO by default (runtime control)');

console.log('\n[7] Stats and score');
const r = runScan({ mcpServers: { a: { url: 'http://169.254.169.254/' } } });
assert(r.stats.total === 14, 'stats.total === 14');
assert(typeof r.stats.score === 'number' && r.stats.score >= 0 && r.stats.score <= 100, 'score within 0..100');
assert(r.stats.fail >= 2, 'insecure config reports multiple failures (tls + ssrf)');
const empty = runScan({});
assert(empty.stats.total === 14, 'empty config still evaluates all checks (info-gated)');

console.log('\n[8] Config parsing');
const parsed = parseConfig(JSON.stringify({ mcpServers: { x: { url: 'https://h' } } }), 'mcp.json');
assert(getServers(parsed).length === 1, 'parseConfig parses JSON and getServers reads mcpServers');
const yamlLike = parseConfig('mcpServers:\n  x:\n    url: https://h\n', 'mcp.yaml');
assert(getServers(yamlLike).length === 1, 'parseConfig falls back to simple YAML for mcpServers');
// BOM (Windows/Notepad) must be stripped, not cause a false-clean skip
const bom = '\uFEFF' + JSON.stringify({ mcpServers: { x: { url: 'http://h' } } });
const bomReport = runScan(parseConfig(bom, 'mcp.json'));
assert(statusOf(bomReport, 'mcp-tls') === 'fail', 'BOM-prefixed JSON still parses and detects insecure http://');

console.log('\n[9] v1.0.1 hardcoded-secret detection regression');
try {
  require('./test-secrets.js');
  assert(true, 'secret regression suite (sk-proj/sk-svcacct/sk-ant-api03/AIza/AKIA/ghp_/xoxb/sk_live positives + \${ENV} placeholder negatives)');
} catch (e) {
  assert(false, 'secret regression suite threw: ' + e.message);
}

console.log(`\n${fail === 0 ? '\u2705' : '\u274c'} ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
