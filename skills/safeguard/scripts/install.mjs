#!/usr/bin/env node
// Installs (or removes) this skill for any agent that reads SKILL.md folders.
// Usage: node install.mjs [--agent a,b | --all] [--project <dir>] [--dry-run] [--list] [--uninstall]
//   default: every agent detected on this machine, user-level (global) install.
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs, exists, homeDir, readText, samePath, SKILL_ROOT } from './lib/common.mjs';
import { AGENTS, expand } from './lib/agents.mjs';

const USAGE = `Usage: safeguard install [--agent <id,id> | --all] [--project <dir>] [--dry-run]
       safeguard install --list
       safeguard install --uninstall [--agent <id,id> | --all] [--project <dir>]
  (no --agent)   install for every agent detected on this machine
  --agent        comma-separated ids from --list
  --all          every supported agent, detected or not
  --project      install into a project folder instead of your user profile
  --dry-run      show what would happen, change nothing`;

const args = parseArgs(process.argv.slice(2), { flags: ['all', 'dry-run', 'list', 'uninstall', 'help'], options: ['agent', 'project', 'home'] }, USAGE);
if (args.help) { console.log(USAGE); process.exit(0); }
const home = args.home ? path.resolve(args.home) : homeDir();

if (args.list) {
  console.log('Supported agents (id — name — user-level skills folder):');
  for (const a of AGENTS) console.log(`  ${a.id.padEnd(15)} ${a.name.padEnd(42)} ${a.global}${exists(expand(a.detect, home)) ? '   ← detected' : ''}`);
  console.log('\nAny other Agent Skills reader: `npx skills add codergeeta/safeguard`. MCP clients: `safeguard mcp-config`.');
  process.exit(0);
}

let chosen;
if (args.agent) {
  const ids = args.agent.split(',').map(s => s.trim()).filter(Boolean);
  const unknown = ids.filter(id => !AGENTS.some(a => a.id === id));
  if (unknown.length) { console.error(`Unknown agent id(s): ${unknown.join(', ')}. See: safeguard install --list`); process.exit(1); }
  chosen = AGENTS.filter(a => ids.includes(a.id));
} else if (args.all) chosen = AGENTS;
else chosen = AGENTS.filter(a => exists(expand(a.detect, home)));

if (!chosen.length) {
  console.log('No supported agents detected. Pick one with --agent (see --list), or use --all.');
  process.exit(1);
}

const project = args.project ? path.resolve(args.project) : null;
const targets = new Map(); // destination -> agent names (several agents share a folder)
for (const a of chosen) {
  const base = project ? path.join(project, a.project) : expand(a.global, home);
  const dest = path.join(base, 'safeguard');
  targets.set(dest, [...(targets.get(dest) || []), a.name]);
}

const isSafeguard = dir => /^name:\s*safeguard\s*$/m.test(readText(path.join(dir, 'SKILL.md')) || '');
const dry = args['dry-run'];
let changed = 0, problems = 0;
for (const [dest, names] of targets) {
  const label = names.join(', ');
  if (samePath(dest) === samePath(SKILL_ROOT)) { console.log(`  = ${dest}  (${label}) — this is the running copy`); continue; }
  if (exists(dest) && !isSafeguard(dest)) { console.log(`  ! ${dest}  (${label}) — a different skill named "safeguard" is already here; left untouched`); problems++; continue; }
  if (args.uninstall) {
    if (!exists(dest)) { console.log(`  - ${dest}  (${label}) — not installed`); continue; }
    if (!dry) fs.rmSync(dest, { recursive: true, force: true });
    console.log(`  ✓ removed ${dest}  (${label})`);
  } else {
    if (!dry) {
      if (exists(dest)) fs.rmSync(dest, { recursive: true, force: true });
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.cpSync(SKILL_ROOT, dest, { recursive: true, filter: src => !/[\\/](node_modules|\.git)([\\/]|$)/.test(src) });
    }
    console.log(`  ✓ ${exists(dest) && dry ? 'would update' : dry ? 'would install' : 'installed'} ${dest}  (${label})`);
  }
  changed++;
}
console.log(dry ? '\nDry run: nothing was changed.' : `\n${changed} location(s) ${args.uninstall ? 'cleaned' : 'ready'}.${args.uninstall ? '' : ' Restart your agent, then ask it e.g. "is this message a scam?" or "audit this project".'}`);
process.exitCode = problems ? 1 : 0;
