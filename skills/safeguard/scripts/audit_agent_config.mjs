#!/usr/bin/env node
// Read-only audit of AI-agent configuration across agents: Claude Code hooks and permissions;
// MCP servers in Claude Code/Desktop, Codex, Cursor, VS Code, Gemini CLI, Windsurf, Cline, Zed;
// Codex approval/sandbox settings; installed skills for ~20 agents; and rules files.
// Usage: node audit_agent_config.mjs [--project <dir>] [--no-user] [--home <dir>] [--json]
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs, exists, isDir, readJson, readText, Report, homeDir } from './lib/common.mjs';
import { auditSettings, auditMcpConfig } from './lib/agentcfg.mjs';
import { scanTree, scanFile } from './lib/scanner.mjs';
import { MCP_CONFIGS, PROJECT_MCP_CONFIGS, PROJECT_RULES, PROJECT_SKILL_DIRS, expand, globalSkillDirs } from './lib/agents.mjs';
import { parseToml } from './lib/toml.mjs';

const USAGE = 'Usage: node audit_agent_config.mjs [--project <dir>] [--no-user] [--json]\n  --project  repo to audit (default: current directory)\n  --no-user  skip user-level config in your home directory';
const args = parseArgs(process.argv.slice(2), { flags: ['json', 'no-user', 'help'], options: ['project', 'home'] }, USAGE);
if (args.help) {
  console.log(USAGE);
  process.exit(0);
}
const home = args.home ? path.resolve(args.home) : homeDir();
const project = path.resolve(args.project || process.cwd());
const report = new Report('safeguard: AI agent configuration audit', null);
const inventory = { settings: 0, mcpFiles: 0, skillDirs: 0, rules: 0 };
const seenDirs = new Set();

function settingsFile(file, scope, projectDir) {
  if (!exists(file)) return;
  const json = readJson(file);
  if (json === undefined) { report.add('LOW', 'agent:config', file, null, 'Could not parse JSON'); return; }
  if (!json) return;
  inventory.settings++;
  auditSettings(json, file, report, { scope, projectDir });
}

// Reads JSON, JSON-with-comments (Zed), or TOML (Codex) and audits the MCP servers in it.
function mcpFile(file, format, scope) {
  if (!file || !exists(file)) return;
  let cfg;
  if (format === 'toml') {
    const text = readText(file);
    if (text == null) return;
    cfg = parseToml(text);
    codexPolicy(cfg, file, scope);
    cfg = { mcpServers: cfg.mcp_servers || {} };
  } else {
    cfg = format === 'jsonc' ? parseJsonc(readText(file)) : readJson(file);
    if (!cfg || typeof cfg !== 'object') return;
    if (cfg.context_servers) cfg = { mcpServers: normalizeZed(cfg.context_servers) }; // Zed
  }
  inventory.mcpFiles++;
  auditMcpConfig(cfg, file, report, { scope });
}

function parseJsonc(text) {
  if (text == null) return null;
  try {
    return JSON.parse(text.replace(/^\uFEFF/, '').replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m, s) => s || '').replace(/,(\s*[}\]])/g, '$1'));
  } catch {
    return null;
  }
}

function normalizeZed(servers) {
  const out = {};
  for (const [name, s] of Object.entries(servers || {})) {
    if (!s || typeof s !== 'object') continue;
    const cmd = s.command && typeof s.command === 'object' ? s.command : s;
    out[name] = { command: cmd.path || cmd.command, args: cmd.args, env: cmd.env, url: s.url };
  }
  return out;
}

// Codex: never asking for approval while sandboxing is off means any injected instruction runs unchecked.
function codexPolicy(cfg, file, scope) {
  const sev = scope === 'project' ? 'HIGH' : 'MEDIUM';
  if (cfg.approval_policy === 'never' && cfg.sandbox_mode === 'danger-full-access') {
    report.add(sev, 'agent:permissions', file, null, 'Codex runs with approval_policy "never" and sandbox "danger-full-access" — every command runs unchecked');
  } else if (cfg.sandbox_mode === 'danger-full-access') {
    report.add('LOW', 'agent:permissions', file, null, 'Codex sandbox_mode is "danger-full-access" (no sandbox)');
  }
}

function contentDir(dir, label) {
  if (!dir || !isDir(dir)) return;
  const key = path.resolve(dir).toLowerCase();
  if (seenDirs.has(key)) return;
  seenDirs.add(key);
  let entries = [];
  try { entries = fs.readdirSync(dir); } catch { /* unreadable */ }
  if (!entries.length) return;
  inventory.skillDirs++;
  if (/skills$/.test(dir)) report.bump('skills', entries.length);
  const n = scanTree(dir, report, { maxFiles: 20000 });
  report.note(`${label}: ${entries.length} entries, ${n} files scanned in ${dir}`);
}

// User level.
if (!args['no-user'] && home) {
  const c = path.join(home, '.claude');
  settingsFile(path.join(c, 'settings.json'), 'user', home);
  settingsFile(path.join(c, 'settings.local.json'), 'user', home);
  for (const sub of ['commands', 'agents', 'hooks', 'plugins']) contentDir(path.join(c, sub), `Claude Code ${sub}`);
  for (const dir of globalSkillDirs(home)) contentDir(dir, 'Installed skills');
  for (const f of [path.join(c, 'CLAUDE.md'), path.join(home, '.codex', 'AGENTS.md'), path.join(home, '.gemini', 'GEMINI.md')]) if (exists(f)) { scanFile(f, report); inventory.rules++; }
  for (const [p, format] of MCP_CONFIGS) mcpFile(expand(p, home), format, 'user');
}

// Project level.
const pc = path.join(project, '.claude');
settingsFile(path.join(pc, 'settings.json'), 'project', project);
settingsFile(path.join(pc, 'settings.local.json'), 'local', project);
for (const [p, format] of PROJECT_MCP_CONFIGS) mcpFile(path.join(project, p), format, 'project');
for (const d of [...PROJECT_SKILL_DIRS, '.claude/commands', '.claude/agents', '.claude/hooks']) contentDir(path.join(project, d), `Project ${d}`);
for (const r of [...PROJECT_RULES, '.vscode/tasks.json']) {
  const p = path.join(project, r);
  if (isDir(p)) { contentDir(p, `Rules ${r}`); inventory.rules++; } else if (exists(p)) { scanFile(p, report); inventory.rules++; }
}

report.meta.settingsFiles = inventory.settings;
report.meta.mcpFiles = inventory.mcpFiles;
report.meta.rulesFiles = inventory.rules;
report.note(`Project audited: ${project}`);
report.note(`Read ${inventory.settings} settings file(s), ${inventory.mcpFiles} MCP config file(s), ${inventory.rules} rules file(s), ${inventory.skillDirs} skill/command/plugin folder(s) across all known agents. Nothing was changed.`);
report.finish(args.json);
