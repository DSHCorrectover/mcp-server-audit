#!/usr/bin/env node
/**
 * mcp-server-audit — static security scanner for MCP (Model Context Protocol)
 * server configuration files.
 *
 * Usage:
 *   npx mcp-server-audit [config-file|directory] [options]
 *
 * This CLI runs 14 automated configuration-level checks. It does NOT perform
 * the deeper 116-check manual audit or issue signed receipts; see README.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { runScan, parseConfig, KNOWN_CONFIG_PATHS } = require('./core/scanner');

const VERSION = '1.0.0';

const c = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', blue: '\x1b[34m', cyan: '\x1b[36m', gray: '\x1b[90m'
};
const icons = { pass: '✅', warn: '⚠️ ', fail: '❌', info: 'ℹ️ ' };

// Human/progress messages go to stderr so that stdout stays pure payload in
// json/sarif modes (safe to pipe into jq or upload to a code-scanning API).
function info(msg) { console.error(msg); }

function banner() {
  info(`
${c.bold}${c.blue}  ╔══════════════════════════════════════════╗
  ║   mcp-server-audit  by Correctover       ║
  ║   MCP config security scanner            ║
  ╚══════════════════════════════════════════╝${c.reset}
  ${c.dim}v${VERSION} · 14 automated checks · mapped to OWASP AISVS 1.0${c.reset}
`);
}

function findConfigFiles(dir) {
  const found = [];
  for (const relPath of KNOWN_CONFIG_PATHS) {
    const fullPath = path.resolve(dir, relPath);
    if (fs.existsSync(fullPath)) found.push(fullPath);
  }
  const scanDirs = ['.', '.cursor', '.claude', '.vscode', '.mcp', 'config'];
  for (const d of scanDirs) {
    const dirPath = path.resolve(dir, d);
    if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
      try {
        for (const f of fs.readdirSync(dirPath)) {
          if (/^mcp[_-]?.*\.(json|yaml|yml)$/.test(f)) {
            const fp = path.join(dirPath, f);
            if (!found.includes(fp)) found.push(fp);
          }
        }
      } catch (e) { /* ignore unreadable dirs */ }
    }
  }
  return found;
}

function findRecursive(dir, acc = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return acc; }
  for (const entry of entries) {
    if (entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      findRecursive(full, acc);
    } else if (/mcp[_-]?.*\.(json|yaml|yml)$/.test(entry.name) || /claude_desktop_config\.json$/.test(entry.name)) {
      if (!acc.includes(full)) acc.push(full);
    }
  }
  return acc;
}

function colorStatus(s) {
  return s === 'pass' ? c.green + 'PASS' : s === 'fail' ? c.red + 'FAIL' : s === 'warn' ? c.yellow + 'WARN' : c.blue + 'INFO';
}

function formatResults(results, stats, filename) {
  const out = [];
  out.push(`${c.bold}📄 ${filename}${c.reset}`);
  out.push('─'.repeat(52));
  const scoreColor = stats.score >= 80 ? c.green : stats.score >= 60 ? c.yellow : c.red;
  out.push(`\n${c.bold}Security score: ${scoreColor}${c.bold}${stats.score}/100${c.reset}`);
  out.push(`  ${c.green}✓ ${stats.pass} passed${c.reset}  ${c.yellow}⚠ ${stats.warn} warnings${c.reset}  ${c.red}✗ ${stats.fail} critical${c.reset}  ${c.blue}ℹ ${stats.info} info${c.reset}\n`);

  const byCat = {};
  for (const r of results) (byCat[r.category] = byCat[r.category] || []).push(r);
  for (const [cat, list] of Object.entries(byCat)) {
    out.push(`${c.dim}── ${cat} ──${c.reset}`);
    for (const r of list) {
      out.push(`  ${icons[r.status]} ${r.name} ${c.reset}[${colorStatus(r.status)}${c.reset}] ${c.dim}${r.aisvs} · ${r.confidence} confidence${c.reset}`);
    }
    out.push('');
  }

  const issues = results.filter(r => r.status === 'fail' || r.status === 'warn');
  if (issues.length) {
    out.push(`${c.bold}${c.yellow}How to fix:${c.reset}\n`);
    for (const r of issues) {
      out.push(`  ${r.status === 'fail' ? '🔴' : '🟡'} ${c.bold}${r.name}${c.reset} ${c.dim}[${r.severity.toUpperCase()}]${c.reset}`);
      out.push(`     ${c.gray}${r.fix}${c.reset}\n`);
    }
  } else {
    out.push(`${c.green}${c.bold}🎉 All automated checks passed.${c.reset}\n`);
  }
  return out.join('\n');
}

function toSARIF(results, filename) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: {
        name: 'mcp-server-audit',
        version: VERSION,
        informationUri: 'https://www.npmjs.com/package/mcp-server-audit',
        rules: results.map(r => ({
          id: r.id,
          name: r.name,
          shortDescription: { text: `${r.category}: ${r.name}` },
          properties: { aisvs: r.aisvs, severity: r.severity, confidence: r.confidence }
        }))
      } },
      results: results.filter(r => r.status === 'fail' || r.status === 'warn').map(r => ({
        ruleId: r.id,
        level: r.status === 'fail' ? 'error' : 'warning',
        message: { text: r.fix },
        locations: [{ physicalLocation: { artifactLocation: { uri: filename } } }]
      }))
    }]
  };
}

function help() {
  console.log(`
mcp-server-audit v${VERSION} — static MCP config security scanner

Usage:
  mcp-server-audit [config-file|directory] [options]
  npx mcp-server-audit                         auto-detect configs in cwd

Options:
  -d, --dir <path>      Directory to scan (default: cwd)
  -r, --recursive       Recursively discover mcp config files
  -f, --format <type>   text | json | sarif (default: text)
  -o, --output <file>   Write output to a file
  -v, --version         Show version
  -h, --help            Show this help

Exit codes:
  0  no critical failures   1  one or more critical (fail) checks found

Examples:
  npx mcp-server-audit mcp.json
  npx mcp-server-audit -d ./my-project -r
  npx mcp-server-audit mcp.json -f sarif -o mcp-audit.sarif
`);
}

function main() {
  const args = process.argv.slice(2);
  let target = null;
  let scanDir = process.cwd();
  let recursive = false;
  let format = 'text';
  let outputFile = null;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '-v' || a === '--version') { console.log(`mcp-server-audit v${VERSION}`); process.exit(0); }
    else if (a === '-h' || a === '--help') { help(); process.exit(0); }
    else if (a === '-f' || a === '--format') format = args[++i];
    else if (a === '-d' || a === '--dir') scanDir = args[++i];
    else if (a === '-o' || a === '--output') outputFile = args[++i];
    else if (a === '-r' || a === '--recursive') recursive = true;
    else if (!a.startsWith('-')) target = a;
  }

  if (target) {
    const stat = fs.existsSync(target) ? fs.statSync(target) : null;
    if (stat && stat.isDirectory()) { scanDir = target; target = null; }
  }

  banner();

  let files = [];
  if (target) {
    if (!fs.existsSync(target)) {
      console.error(`${c.red}Error: file not found: ${target}${c.reset}`);
      process.exit(2);
    }
    files = [target];
  } else {
    info(`${c.dim}Scanning ${recursive ? 'recursively ' : ''}in ${scanDir} ...${c.reset}`);
    files = recursive ? findRecursive(path.resolve(scanDir)) : findConfigFiles(scanDir);
  }

  if (!files.length) {
    info(`${c.yellow}No MCP configuration files found.${c.reset}`);
    info(`${c.dim}Looked for: ${KNOWN_CONFIG_PATHS.join(', ')}${c.reset}`);
    if (format === 'json') console.log(JSON.stringify({ scanner: 'mcp-server-audit', version: VERSION, reports: [] }, null, 2));
    else if (format === 'sarif') console.log(JSON.stringify({ version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [] }, null, 2));
    else info(`${c.dim}Tip: point at a file, or use -r to recurse.${c.reset}`);
    process.exit(0);
  }
  info(`${c.dim}Found ${files.length} config file(s).${c.reset}\n`);

  const reports = [];
  let totalFail = 0;

  for (const fp of files) {
    try {
      const config = parseConfig(fs.readFileSync(fp, 'utf-8'), fp);
      const { results, stats } = runScan(config);
      const rel = path.relative(process.cwd(), fp) || fp;
      reports.push({ file: rel, results, stats });
      totalFail += stats.fail;
    } catch (e) {
      console.error(`${c.red}Error scanning ${fp}: ${e.message}${c.reset}\n`);
    }
  }

  // Build the full payload for the requested format exactly once, so that -o
  // writes the same bytes a piped consumer would receive on stdout.
  let payload = '';
  if (format === 'json') {
    payload = JSON.stringify({ scanner: 'mcp-server-audit', version: VERSION, reports }, null, 2);
  } else if (format === 'sarif') {
    const runs = [];
    for (const r of reports) runs.push(...toSARIF(r.results, r.file).runs);
    payload = JSON.stringify({ version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs }, null, 2);
  } else {
    const blocks = reports.map(r => formatResults(r.results, r.stats, r.file) + '\n');
    if (reports.length > 1) {
      const p = reports.reduce((a, r) => a + r.stats.pass, 0);
      const w = reports.reduce((a, r) => a + r.stats.warn, 0);
      const f = reports.reduce((a, r) => a + r.stats.fail, 0);
      const i = reports.reduce((a, r) => a + r.stats.info, 0);
      const score = Math.round(((p * 10 + w * 5 + i * 7) / ((p + w + f + i) * 10)) * 100);
      blocks.push(`${c.bold}═══ Summary ═══${c.reset}`);
      blocks.push(`  Files: ${reports.length}   Aggregate score: ${score}/100`);
      blocks.push(`  ${c.green}✓ ${p}${c.reset}  ${c.yellow}⚠ ${w}${c.reset}  ${c.red}✗ ${f}${c.reset}  ${c.blue}ℹ ${i}${c.reset}\n`);
    }
    blocks.push(`${c.dim}── Need deeper coverage? ─────────────────────────${c.reset}`);
    blocks.push(`${c.dim}This CLI covers 14 automated config checks. A 116-check manual audit across the 7-dimension CCS model, delivered as a cryptographically signed report, is available separately.${c.reset}`);
    blocks.push(`${c.cyan}  → https://correctover.com/audit-service${c.reset}\n`);
    payload = blocks.join('\n');
  }

  if (outputFile) {
    fs.writeFileSync(outputFile, payload);
    info(`${c.green}Wrote ${format} report to ${outputFile}${c.reset}`);
  } else {
    process.stdout.write(payload + '\n');
  }
  process.exit(totalFail > 0 ? 1 : 0);
}

main();
