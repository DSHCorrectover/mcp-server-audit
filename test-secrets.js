// Regression test for secret detection (v1.0.1). Run: node test-secrets.js
const assert = require('assert');
const scanner = require('./core/scanner.js');

// Find the hardcoded-secrets check by name across whatever export shape the scanner uses.
function loadChecks() {
  const s = scanner;
  // Scanner may export { checks }, { CHECKS }, a run() returning results, or the array itself.
  const candidates = [];
  if (Array.isArray(s)) candidates.push(s);
  if (Array.isArray(s.checks)) candidates.push(s.checks);
  if (Array.isArray(s.CHECKS)) candidates.push(s.CHECKS);
  if (typeof s.getChecks === 'function') candidates.push(s.getChecks());
  if (typeof s.default === 'function') candidates.push(s.default());
  for (const c of candidates) {
    const found = c.find(x => x && (x.id === 'cred-exposure' || /hardcoded secret/i.test(x.name || '')));
    if (found) return found;
  }
  // Fallback: run the scanner on a config and locate the C5.1 result.
  throw new Error('cred-exposure check not found via known exports: ' + Object.keys(s).join(','));
}

const secretCheck = loadChecks();
const call = env => secretCheck.check({ mcpServers: { x: { command: 'npx', args: ['p@1.0.0'], url: 'https://api.example.com/mcp', env } } });

const MUST_FIRE = {
  'openai legacy sk-': { OPENAI_API_KEY: 'sk-abcdefghijklmnopqrstuvwxyz123456' },
  'openai project sk-proj': { OPENAI_API_KEY: 'sk-proj-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV' },
  'openai svcacct': { OPENAI_API_KEY: 'sk-svcacct-abcdef0123456789ABCDEFGHIJKLMNOP' },
  'anthropic sk-ant-api03': { ANTHROPIC_API_KEY: 'sk-ant-api03-AbCdEf0123456789GhIjKlMnOpQrSt' },
  'google AIza': { GEMINI_API_KEY: 'AIzaSyA1234567890abcdefghijklmnopqrstuv' },
  'aws AKIA': { AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE' },
  'github ghp_': { GITHUB_TOKEN: 'ghp_1234567890abcdefghijklmnopqrstuvwxyzAB' },
  'slack xoxb': { SLACK_BOT_TOKEN: 'xoxb-123456789012-1234567890123-' + 'AbCdEfGhIjKlMnOpQrStUvWx' },
  'stripe sk_live': { STRIPE_KEY: 'sk_l' + 'ive_1234567890abcdefABCDEFGH' },
  'nested password field': { PASSWORD: 'Sup3rS3cret!Pass' }
};

const MUST_NOT_FIRE = {
  'env placeholder ${OPENAI_API_KEY}': { OPENAI_API_KEY: '${OPENAI_API_KEY}' },
  'env placeholder $TOKEN': { TOKEN: '$GITHUB_TOKEN' },
  'empty string': { API_KEY: '' },
  'short dummy x': { API_KEY: 'x' },
  'word api_key no secret': { NOTE: 'set your api key in env' }
};

let pass = 0;
for (const [label, env] of Object.entries(MUST_FIRE)) {
  assert.strictEqual(call(env), 'fail', `SHOULD detect ${label}`);
  console.log('  ✓ detect', label);
  pass++;
}
for (const [label, env] of Object.entries(MUST_NOT_FIRE)) {
  assert.strictEqual(call(env), 'pass', `SHOULD NOT flag ${label}`);
  console.log('  ✓ ignore', label);
  pass++;
}
console.log(`\nALL ${pass} secret-detection cases PASS`);
