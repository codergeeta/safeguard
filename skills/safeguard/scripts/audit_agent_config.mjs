#!/usr/bin/env node
// Read-only audit of Claude Code and other AI-agent configuration:
// hooks, permissions, MCP servers, skills, commands, agents, plugins.
// Usage: node audit_agent_config.mjs [--project <dir>] [--no-user] [--json]
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs, exists, isDir, readJson, Report, homeDir } from './lib/common.mjs';
import { auditSettings, auditMcpConfig } from './lib/agentcfg.mjs';
import { scanTree, scanFile } from './lib/scanner.mjs';

const USAGE = 'Usage: node audit_agent_config.mjs [--project <dir>] [--no-user] [--json]\n  --project  repo to audit (default: current directory)\n  --no-user  skip user-level config in your home directory';
const args = parseArgs(process.argv.slice(2), { flags: ['json', 'no-user', 'help'], options: ['project'] }, USAGE);
if (args.help) {
  console.log(USAGE);
  process.exit(0);
}
const home = homeDir();
const project = path.resolve(args.project || process.cwd());
const report = new Report('safeguard: AI agent configuration audit', null);
const inventory = { settings: 0, mcpFiles: 0, skillDirs: 0 };

function settingsFile(file, scope, projectDir) {
  if (!exists(file)) return;
  const json = readJson(file);
  if (json === undefined) { report.add('LOW', 'agent:config', file, null, 'Could not parse JSON'); return; }
  if (!json) return;
  inventory.settings++;
  auditSettings(json, file, report, { scope, projectDir });
}

function mcpFile(file, scope) {
  if (!exists(file)) return;
  const json = readJson(file);
  if (!json) return;
  inventory.mcpFiles++;
  auditMcpConfig(json, file, report, { scope });
}

function contentDir(dir, label) {
  if (!isDir(dir)) return;
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
  mcpFile(path.join(home, '.claude.json'), 'user');
  contentDir(path.join(c, 'skills'), 'User skills');
  contentDir(path.join(c, 'commands'), 'User commands');
  contentDir(path.join(c, 'agents'), 'User agents');
  contentDir(path.join(c, 'hooks'), 'User hook scripts');
  contentDir(path.join(c, 'plugins'), 'Installed plugins');
  if (exists(path.join(c, 'CLAUDE.md'))) scanFile(path.join(c, 'CLAUDE.md'), report);

  const appData = process.env.APPDATA;
  const others = [
    appData && path.join(appData, 'Claude', 'claude_desktop_config.json'),
    appData && path.join(appData, 'Code', 'User', 'mcp.json'),
    path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    path.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'),
    path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    path.join(home, '.config', 'Code', 'User', 'mcp.json'),
    path.join(home, '.cursor', 'mcp.json'),
    path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
  ];
  for (const f of others) if (f) mcpFile(f, 'user');
}

// Project level.
const pc = path.join(project, '.claude');
settingsFile(path.join(pc, 'settings.json'), 'project', project);
settingsFile(path.join(pc, 'settings.local.json'), 'local', project);
mcpFile(path.join(project, '.mcp.json'), 'project');
mcpFile(path.join(project, '.cursor', 'mcp.json'), 'project');
mcpFile(path.join(project, '.vscode', 'mcp.json'), 'project');
contentDir(path.join(pc, 'skills'), 'Project skills');
contentDir(path.join(pc, 'commands'), 'Project commands');
contentDir(path.join(pc, 'agents'), 'Project agents');
contentDir(path.join(pc, 'hooks'), 'Project hook scripts');
for (const f of ['CLAUDE.md', 'AGENTS.md', '.cursorrules', path.join('.vscode', 'tasks.json'), path.join('.github', 'copilot-instructions.md')]) {
  const p = path.join(project, f);
  if (exists(p)) scanFile(p, report);
}

report.meta.settingsFiles = inventory.settings;
report.meta.mcpFiles = inventory.mcpFiles;
report.note(`Project audited: ${project}`);
report.note(`Read ${inventory.settings} settings file(s), ${inventory.mcpFiles} MCP config file(s), ${inventory.skillDirs} skill/command/plugin folder(s). Nothing was changed.`);
report.finish(args.json);
