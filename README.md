# mcp-server-audit

> Static security scanner for **MCP (Model Context Protocol) server configuration** — catch leaked secrets, SSRF, missing auth and over-permission **before you mount a server**. 14 automated checks mapped to **OWASP AISVS 1.0**. No sign-up, runs locally, nothing is uploaded.

[![npm version](https://img.shields.io/npm/v/mcp-server-audit)](https://www.npmjs.com/package/mcp-server-audit)
[![license](https://img.shields.io/npm/l/mcp-server-audit)](https://github.com/DSHCorrectover/mcp-server-audit/blob/main/LICENSE)

```bash
# audit a single config
npx mcp-server-audit mcp.json

# auto-detect configs in the current project
npx mcp-server-audit

# recurse a repo and emit SARIF for CI
npx mcp-server-audit -r -f sarif -o mcp-audit.sarif
```

You get a 0–100 security score, a per-check PASS/WARN/FAIL/INFO result, OWASP AISVS mapping, a confidence label, and a concrete fix for every issue. The exit code is `1` when any critical check fails, so it can gate CI.

## What it checks (14 automated checks)

Five checks are **enforceable config gates** — they verify properties that genuinely live in this config file and fail the build (exit `1`) when violated. The other nine are **advisory runtime controls** flagged as `INFO`/`WARN`, because they are enforced by the agent runtime or the server's own code and cannot be proven from a client config block. We deliberately do *not* emit a high-severity warning for their absence — that would only pressure you into adding config keys that do nothing.

**Enforceable gates**

| # | Check | Severity | AISVS |
|---|-------|----------|-------|
| 1 | Encrypted transport (HTTPS/TLS, no plaintext `http://`; local stdio exempt) | 🔴 Critical | C10.1 |
| 2 | Authentication on **remote** servers (local stdio exempt) | 🟠 High | C10.2 |
| 4 | Hardcoded secrets (`sk-…`, AWS keys, `ghp_…`, `github_pat_…`, Slack tokens, passwords) | 🔴 Critical | C5.1 |
| 7 | No internal / cloud-metadata endpoints (SSRF, `169.254.169.254`, RFC1918, `localhost`) | 🔴 Critical | C10.3 |
| 10 | Registry packages pinned to an exact version (`npx pkg@1.2.3` ✅, bare `npx pkg` ⚠️ rug-pull) | 🟡 Medium | C6.1 |

**Advisory runtime controls**

| # | Check | Severity | AISVS |
|---|-------|----------|-------|
| 3 | Connection / request timeout | ⚪ Advisory | C9.1 |
| 5 | Tool allowlist / least privilege | ⚪ Advisory | C9.3 |
| 6 | Token / cost budget cap | ⚪ Advisory | C9.1 |
| 8 | Audit logging enabled | ⚪ Advisory | C12.1 |
| 9 | Sandbox isolation considered | ⚪ Advisory | C4.1 |
| 11 | Error handling / fail-safe | ⚪ Advisory | C12.2 |
| 12 | Input validation / sanitization | ⚪ Advisory | C2.1 |
| 13 | Output validation / filtering | ⚪ Advisory | C7.1 |
| 14 | Kill switch / circuit breaker | ⚪ Advisory | C9.5 |

These runtime controls are exactly what the deeper **CCS runtime verification** enforces in-process (sub-millisecond) and what the manual audit reviews — see [Scope](#scope--automated-cli-vs-manual-audit).

Each finding carries a **confidence** label: `high` for deterministic secret-scheme / internal-IP / exact-pin detection, `medium`/`low` for heuristics — so you know which results to act on first. A UTF-8 BOM on Windows-saved files is stripped automatically (otherwise it silently produced a false "0 findings").

## Detected config files

`.cursor/mcp.json`, `claude_desktop_config.json`, `.claude/mcp.json`, `mcp.json`, `mcp.yaml`, `mcp.yml`, `.vscode/mcp.json`, `.mcp/mcp.json`, `config/mcp.json`, `mcp_config.json` — plus any `mcp*.{json,yaml,yml}` in common tool directories (use `-r` to discover recursively).

## Output formats

```bash
mcp-server-audit mcp.json                 # terminal report (default)
mcp-server-audit mcp.json -f json         # machine-readable JSON
mcp-server-audit mcp.json -f sarif        # SARIF 2.1.0 for GitHub code scanning
```

## Programmatic use

```js
const { runScan, parseConfig } = require('mcp-server-audit/core/scanner');
const { results, stats } = runScan(parseConfig(configText, 'mcp.json'));
console.log(stats.score, results.filter(r => r.status === 'fail'));
```

## Scope — automated CLI vs. manual audit

This open-source CLI is deliberately scoped and honest:

- **It does** 14 fast, deterministic **configuration-level** checks locally (the table above).
- **It does not** read your MCP server source, trace live traffic, or claim to cover every agent-risk class.

Deeper review — tool-poisoning / rug-pull analysis across server code, schema and permission analysis, and a **116-check manual audit across the 7-dimension CCS conformance model** (Structure, Schema, Latency, Cost, Identity, Integrity, Security), delivered as a **cryptographically signed audit report** — is a separate human-led service: **https://correctover.com/audit-service**

## Standards

- Checks are mapped to the **OWASP AI Security Verification Standard (AISVS) 1.0** control IDs.
- "CCS" refers to Correctover's own conformance methodology documented in an individual IETF Internet-Draft. That document is an *individual submission*, **not an RFC and not an IETF endorsement, standard, or certification**.

## Links

- Manual audit service: https://correctover.com/audit-service
- Source & issues: https://github.com/DSHCorrectover/mcp-server-audit
- Product: https://correctover.com

## License

MIT © Correctover
