#!/usr/bin/env node
// CI runner (used by the GitHub Action): full checkup, job summary, outputs, and a pass/fail gate.
// Usage: node ci.mjs <path> [--fail-on high|medium|low|never] [--out report.html]
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from './lib/common.mjs';

const USAGE = 'Usage: node ci.mjs <path> [--fail-on high|medium|low|never] [--out report.html]';
const args = parseArgs(process.argv.slice(2), { flags: ['help'], options: ['fail-on', 'out'] }, USAGE);
if (args.help) { console.log(USAGE); process.exit(0); }
const target = path.resolve(args._[0] || '.');
const failOn = String(args['fail-on'] || 'high').toLowerCase();
if (!['high', 'medium', 'low', 'never'].includes(failOn)) { console.error(`--fail-on must be high, medium, low or never (got ${failOn})`); process.exit(1); }
const out = path.resolve(args.out || 'safeguard-report.html');

const here = path.dirname(fileURLToPath(import.meta.url));
const r = spawnSync(process.execPath, [path.join(here, 'safeguard.mjs'), target, '--no-user', '--json', '--out', out], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
let res;
try { res = JSON.parse(r.stdout); } catch { console.error(r.stderr || r.stdout); process.exit(1); }

const all = Object.entries(res.areas).flatMap(([area, a]) => a.findings.map(f => ({ ...f, area })));
const order = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];
all.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
const c = res.counts;
const icon = { HIGH: '🔴', MEDIUM: '🟠', LOW: '🟡', INFO: '⚪' };
const cell = s => String(s ?? '').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').replace(/</g, '&lt;').slice(0, 200);

const md = [
  `## 🛡️ Safeguard: ${c.HIGH ? 'action needed' : c.MEDIUM ? 'review recommended' : 'no red flags'} — health ${res.health}/100`,
  '',
  `| 🔴 High | 🟠 Medium | 🟡 Low | ⚪ Info |`, `|---|---|---|---|`, `| ${c.HIGH} | ${c.MEDIUM} | ${c.LOW} | ${c.INFO} |`,
  '',
  ...(all.some(f => f.severity !== 'INFO') ? ['| | Finding | Where |', '|---|---|---|', ...all.filter(f => f.severity !== 'INFO').slice(0, 50).map(f => `| ${icon[f.severity]} | ${cell(f.message)} | \`${cell(f.file)}${f.line ? ':' + f.line : ''}\` |`)] : ['No issues found.']),
  '',
  `Full visual report: download the **safeguard-report** artifact. Gate: fail on ${failOn}.`,
].join('\n');

if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
else console.log(md);
if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `health=${res.health}\nhigh=${c.HIGH}\nmedium=${c.MEDIUM}\nlow=${c.LOW}\nreport=${out}\n`);
// GitHub annotations for the top findings.
for (const f of all.filter(x => x.severity === 'HIGH' || x.severity === 'MEDIUM').slice(0, 20)) {
  const level = f.severity === 'HIGH' ? 'error' : 'warning';
  const file = f.file && !path.isAbsolute(f.file) ? `file=${f.file.replace(/\\/g, '/')}${f.line ? `,line=${f.line}` : ''},` : '';
  console.log(`::${level} ${file}title=Safeguard ${f.severity}::${f.message.replace(/[\r\n%]/g, ' ')}`);
}

const fail = failOn === 'never' ? false : failOn === 'high' ? c.HIGH > 0 : failOn === 'medium' ? c.HIGH + c.MEDIUM > 0 : c.HIGH + c.MEDIUM + c.LOW > 0;
process.exitCode = fail ? 1 : 0;
