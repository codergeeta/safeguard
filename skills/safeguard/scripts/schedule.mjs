#!/usr/bin/env node
// Weekly (or daily) automatic re-check of a folder, using the operating system's own scheduler:
// Windows Task Scheduler, macOS launchd, or cron on Linux. The job writes a fresh report to
// ~/.safeguard/reports/ and opens it only when something needs attention (HIGH findings).
// Prints the plan by default; nothing changes until you add --apply.
//   node schedule.mjs <folder> [--daily] [--site <domain>] [--apply]
//   node schedule.mjs <folder> --remove [--apply]
//   node schedule.mjs --list
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs, isDir, homeDir } from './lib/common.mjs';

const USAGE = `Usage: node schedule.mjs <folder> [--daily] [--site <domain>] [--apply]
       node schedule.mjs <folder> --remove [--apply]
       node schedule.mjs --list
  Without --apply it only prints what it would do.`;
const args = parseArgs(process.argv.slice(2), { flags: ['apply', 'remove', 'daily', 'list', 'help'], options: ['site', 'home'] }, USAGE);
if (args.help) { console.log(USAGE); process.exit(0); }

const home = args.home ? path.resolve(args.home) : homeDir();
const sgDir = path.join(home, '.safeguard');
const here = path.dirname(fileURLToPath(import.meta.url));
const node = process.execPath;
const plat = process.platform;

if (args.list) {
  const jobs = fs.existsSync(path.join(sgDir, 'jobs')) ? fs.readdirSync(path.join(sgDir, 'jobs')) : [];
  console.log(jobs.length ? `Safeguard scheduled checks (${path.join(sgDir, 'jobs')}):\n${jobs.map(j => `  ${j}`).join('\n')}` : 'No Safeguard scheduled checks.');
  process.exit(0);
}
if (!args._[0]) { console.log(USAGE); process.exit(1); }
const target = path.resolve(args._[0]);
if (!isDir(target)) { console.error(`Not a folder: ${target}`); process.exit(1); }
if (args.site && !/^[a-z0-9.-]+\.[a-z]{2,63}$/i.test(args.site)) { console.error(`Not a valid domain: ${args.site}`); process.exit(1); }

const id = crypto.createHash('sha1').update(target.toLowerCase()).digest('hex').slice(0, 8);
const name = `safeguard-${path.basename(target).replace(/[^\w.-]/g, '_')}-${id}`;
const reportDir = path.join(sgDir, 'reports');
const report = path.join(reportDir, `${name}-latest.html`);
const jobDir = path.join(sgDir, 'jobs');
const runner = path.join(jobDir, `${name}.mjs`);
const freq = args.daily ? 'daily' : 'weekly';

// The job: run the checkup, keep the latest report, open it only if there are HIGH findings.
const runnerSrc = `// Safeguard scheduled check for ${target} (created ${new Date().toISOString()})
import { spawnSync } from 'node:child_process';
const r = spawnSync(${JSON.stringify(node)}, [${JSON.stringify(path.join(here, 'safeguard.mjs'))}, ${JSON.stringify(target)}, '--out', ${JSON.stringify(report)}${args.site ? `, '--site', ${JSON.stringify(args.site)}, '--i-own-this'` : ''}], { stdio: 'ignore' });
if (r.status === 2) spawnSync(${JSON.stringify(node)}, ['-e', ${JSON.stringify(`import(${JSON.stringify('file:///' + path.join(here, 'lib', 'open.mjs').replace(/\\/g, '/'))}).then(m => m.openFile(${JSON.stringify(report)}))`)}], { stdio: 'ignore' });
`;

const run = (cmd, a) => spawnSync(cmd, a, { encoding: 'utf8' });
let steps = [];
if (plat === 'win32') {
  const task = `\\Safeguard\\${name}`;
  steps = args.remove
    ? [['schtasks', ['/Delete', '/TN', task, '/F']]]
    : [['schtasks', ['/Create', '/TN', task, '/SC', args.daily ? 'DAILY' : 'WEEKLY', ...(args.daily ? [] : ['/D', 'MON']), '/ST', '09:30', '/TR', `"${node}" "${runner}"`, '/F']]];
} else if (plat === 'darwin') {
  const label = `com.codergeeta.${name}`;
  const plist = path.join(home, 'Library', 'LaunchAgents', `${label}.plist`);
  const interval = args.daily ? '<dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>30</integer></dict>' : '<dict><key>Weekday</key><integer>1</integer><key>Hour</key><integer>9</integer><key>Minute</key><integer>30</integer></dict>';
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>Label</key><string>${label}</string><key>ProgramArguments</key><array><string>${node}</string><string>${runner}</string></array><key>StartCalendarInterval</key>${interval}</dict></plist>\n`;
  steps = args.remove
    ? [['launchctl', ['unload', plist]], ['rm', [plist]]]
    : [['write', [plist, xml]], ['launchctl', ['load', plist]]];
} else {
  const line = `30 9 * * ${args.daily ? '*' : '1'} "${node}" "${runner}" # ${name}`;
  steps = [['crontab', [args.remove ? 'remove-line' : 'add-line', name, line]]];
}

console.log(`${args.remove ? 'Remove' : 'Create'} a ${freq} Safeguard check of ${target}${args.site ? ` (+ live check of ${args.site})` : ''}`);
if (!args.remove) console.log(`  job script: ${runner}\n  report:     ${report} (opens automatically only when there are HIGH findings)`);
for (const [cmd, a] of steps) console.log(`  ${cmd === 'write' ? `write ${a[0]}` : cmd === 'crontab' ? `crontab: ${a[0]} "${a[2] || a[1]}"` : `${cmd} ${a.join(' ')}`}`);
if (!args.apply) { console.log('\nNothing changed. Add --apply to do it.'); process.exit(0); }

if (!args.remove) {
  fs.mkdirSync(jobDir, { recursive: true });
  fs.mkdirSync(reportDir, { recursive: true });
  fs.writeFileSync(runner, runnerSrc);
}
let ok = true;
for (const [cmd, a] of steps) {
  if (cmd === 'write') { fs.mkdirSync(path.dirname(a[0]), { recursive: true }); fs.writeFileSync(a[0], a[1]); continue; }
  if (cmd === 'rm') { fs.rmSync(a[0], { force: true }); continue; }
  if (cmd === 'crontab') {
    const cur = run('crontab', ['-l']);
    const lines = (cur.status === 0 ? cur.stdout : '').split('\n').filter(l => l && !l.includes(`# ${a[1]}`));
    if (a[0] === 'add-line') lines.push(a[2]);
    const w = spawnSync('crontab', ['-'], { input: lines.join('\n') + '\n', encoding: 'utf8' });
    if (w.status !== 0) { console.error(`  crontab failed: ${w.stderr}`); ok = false; }
    continue;
  }
  const r = run(cmd, a);
  if (r.status !== 0) { console.error(`  ${cmd} failed: ${(r.stderr || r.stdout).trim()}`); ok = false; }
}
if (args.remove && ok) fs.rmSync(runner, { force: true });
console.log(ok ? `\n✓ ${args.remove ? 'Removed' : `Scheduled ${freq}`}.${args.remove ? '' : ' Run it once now to check: node "' + runner + '"'}` : '\nSome steps failed (see above).');
process.exitCode = ok ? 0 : 1;
