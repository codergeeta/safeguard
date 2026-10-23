#!/usr/bin/env node
// One-command checkup: runs every scanner on a project and writes a visual HTML dashboard.
// Usage: node safeguard.mjs [project-dir] [--home] [--no-user] [--deep] [--out report.html] [--open] [--json]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs, isDir } from './lib/common.mjs';
import { renderDashboard, score } from './lib/render.mjs';
import { openFile, stamp } from './lib/open.mjs';

const args = parseArgs(process.argv.slice(2), { flags: ['home', 'no-user', 'deep', 'open', 'json', 'help'], options: ['out'] });
if (args.help) {
  console.log(`Usage: node safeguard.mjs [project-dir] [options]
  --home      also check credential files in your home directory
  --no-user   skip user-level agent config (~/.claude, editor MCP configs)
  --deep      include node_modules and virtualenvs in the code scan
  --out FILE  where to write the HTML report (default: your temp folder)
  --open      open the report in your browser
  --json      print combined JSON instead of the text summary`);
  process.exit(0);
}

const here = path.dirname(fileURLToPath(import.meta.url));
const project = path.resolve(args._[0] || process.cwd());
if (!isDir(project)) { console.error(`Not a folder: ${project}`); process.exit(1); }

function run(script, ...a) {
  const r = spawnSync(process.execPath, [path.join(here, script), ...a, '--json'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.error) return { error: r.error.message };
  try { return JSON.parse(r.stdout); } catch { return { error: (r.stderr || r.stdout || 'no output').slice(0, 500) }; }
}

const raw = {
  agent: run('audit_agent_config.mjs', '--project', project, ...(args['no-user'] ? ['--no-user'] : [])),
  deps: run('check_deps.mjs', project),
  code: run('scan_package.mjs', project, ...(args.deep ? ['--deep'] : [])),
  secrets: run('scan_secrets.mjs', project, ...(args.home ? ['--home'] : [])),
};

// Several scanners look at the same files (e.g. .claude/, package.json); keep each finding once.
const seen = new Set();
const areas = {};
const notes = [];
for (const [id, r] of Object.entries(raw)) {
  if (r.error) { notes.push(`${id} scan failed: ${r.error}`); continue; }
  const findings = [];
  for (const f of r.findings) {
    const abs = f.file ? path.resolve(r.root || '', f.file) : '';
    const relToProject = abs && !path.relative(project, abs).startsWith('..') ? path.relative(project, abs) || path.basename(abs) : abs;
    const key = `${abs.toLowerCase()}|${f.line}|${f.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({ ...f, file: relToProject });
  }
  areas[id] = { findings, meta: r.meta || {} };
  for (const n of r.notes || []) if (!notes.includes(n)) notes.push(n);
}

const generated = new Date().toLocaleString();
const all = Object.values(areas).flatMap(a => a.findings);
const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
for (const f of all) counts[f.severity]++;
const health = score(all);

const out = path.resolve(args.out || path.join(os.tmpdir(), `safeguard-report-${stamp()}.html`));
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, renderDashboard({ generated, target: project, areas, notes }));

if (args.json) {
  console.log(JSON.stringify({ project, health, counts, report: out, areas, notes }, null, 2));
} else {
  const verdict = counts.HIGH ? 'ACTION NEEDED' : counts.MEDIUM ? 'REVIEW RECOMMENDED' : 'NO RED FLAGS FOUND';
  console.log(`== safeguard checkup: ${verdict} ==`);
  console.log(`Project: ${project}`);
  console.log(`Health score: ${health}/100   (${counts.HIGH} high, ${counts.MEDIUM} medium, ${counts.LOW} low, ${counts.INFO} info)\n`);
  for (const [id, a] of Object.entries(areas)) {
    const c = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const f of a.findings) if (c[f.severity] != null) c[f.severity]++;
    console.log(`  ${id.padEnd(8)} ${c.HIGH} high, ${c.MEDIUM} medium, ${c.LOW} low`);
  }
  const highs = all.filter(f => f.severity === 'HIGH').slice(0, 10);
  if (highs.length) {
    console.log('\nHIGH findings:');
    for (const f of highs) console.log(`  - ${f.file}${f.line ? ':' + f.line : ''} — ${f.message}`);
  }
  console.log(`\nVisual report: ${out}`);
}
if (args.open) openFile(out);
process.exitCode = counts.HIGH ? 2 : 0;
