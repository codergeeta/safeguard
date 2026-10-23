#!/usr/bin/env node
// `safeguard` command: one entry point for people, scripts, CI, and any AI agent.
// Usage: safeguard <command> [options]   (run `safeguard help`)
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(fs.readFileSync(path.join(here, '..', 'version.json'), 'utf8')).version;
const MCP = path.join(here, 'mcp_server.mjs');

const COMMANDS = {
  scan: ['safeguard.mjs', 'Full checkup of a folder + visual HTML dashboard', 'safeguard scan . --open'],
  deps: ['check_deps.mjs', 'Dependencies & CI in every ecosystem', 'safeguard deps .'],
  agent: ['audit_agent_config.mjs', 'AI-agent config: hooks, MCP servers, skills, rules (all major agents)', 'safeguard agent --project .'],
  package: ['scan_package.mjs', 'Vet a package, skill, MCP server, extension, repo or website folder', 'safeguard package ./downloaded-skill'],
  secrets: ['scan_secrets.mjs', 'Plaintext secrets (values redacted); --home for credential files', 'safeguard secrets . --home'],
  site: ['site_check.mjs', 'Live outside-in check of a website YOU own (online, opt-in)', 'safeguard site example.com --i-own-this --open'],
  guard: ['guard.mjs', 'Block dangerous AI-agent actions before they run (Claude Code, Cursor, Gemini CLI)', 'safeguard guard --install'],
  precommit: ['precommit.mjs', 'Git hook that blocks commits containing secrets', 'safeguard precommit --install'],
  schedule: ['schedule.mjs', 'Weekly automatic re-check via the OS scheduler', 'safeguard schedule . --apply'],
  ci: ['ci.mjs', 'CI mode: job summary, annotations, fail-on gate', 'safeguard ci . --fail-on high'],
  checkup: ['checkup.mjs', 'Interactive personal security checkup page (no AI needed)', 'safeguard checkup --open'],
  'scam-card': ['scam_card.mjs', 'Render a scam explainer card from a JSON verdict', 'safeguard scam-card card.json --open'],
  install: ['install.mjs', 'Install the skill into Claude Code, Codex, Cursor, Copilot, Gemini CLI, Windsurf, Cline, ...', 'safeguard install'],
  mcp: ['mcp_server.mjs', 'Run the MCP server (stdio) for any MCP client', 'safeguard mcp'],
};

function help() {
  console.log(`safeguard ${VERSION} — protect yourself and your code from 2026-era attacks\n\nCommands:`);
  for (const [name, [, desc, ex]] of Object.entries(COMMANDS)) console.log(`  ${name.padEnd(11)} ${desc}\n  ${' '.repeat(11)} e.g. ${ex}`);
  console.log(`  ${'mcp-config'.padEnd(11)} Print MCP setup for Claude Desktop, ChatGPT, Cursor, VS Code, Codex, Gemini CLI, Windsurf, Zed\n  ${'prompt'.padEnd(11)} Print chat-app instructions (ChatGPT GPTs/Projects, Gemini Gems, Claude Projects)\n\nAll scanners are read-only and offline; add --json for machine output. Exit code 2 = HIGH findings.`);
}

function mcpConfig() {
  const node = process.execPath.replace(/\\/g, '/');
  const server = MCP.replace(/\\/g, '/');
  const j = o => JSON.stringify(o, null, 2);
  const std = { command: node, args: [server] };
  console.log(`Safeguard MCP server: ${server}\n(Paths below point to this copy. Alternatively use: "command": "npx", "args": ["-y", "github:codergeeta/safeguard", "mcp"])\n`);
  console.log(`— Claude Desktop (claude_desktop_config.json), Cursor (~/.cursor/mcp.json), Windsurf (~/.codeium/windsurf/mcp_config.json), Gemini CLI (~/.gemini/settings.json), Cline:\n${j({ mcpServers: { safeguard: std } })}\n`);
  console.log(`— VS Code / GitHub Copilot (.vscode/mcp.json or user mcp.json):\n${j({ servers: { safeguard: { type: 'stdio', ...std } } })}\n`);
  console.log(`— Codex (~/.codex/config.toml), or run: codex mcp add safeguard -- "${node}" "${server}"\n[mcp_servers.safeguard]\ncommand = "${node}"\nargs = ["${server}"]\n`);
  console.log(`— Claude Code: claude mcp add safeguard -- "${node}" "${server}"\n`);
  console.log(`— Zed (settings.json):\n${j({ context_servers: { safeguard: { command: { path: node, args: [server] } } } })}\n`);
  console.log('— ChatGPT desktop / other clients: add a local (stdio) MCP server with the command and args above.');
}

const [cmd, ...rest] = process.argv.slice(2);
if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') { help(); process.exit(0); }
if (cmd === '--version' || cmd === '-v' || cmd === 'version') { console.log(VERSION); process.exit(0); }
if (cmd === 'mcp-config') { mcpConfig(); process.exit(0); }
if (cmd === 'prompt') {
  const f = path.join(here, '..', 'chat', 'INSTRUCTIONS.md');
  process.stdout.write(fs.readFileSync(f, 'utf8'));
  console.error(`\n(Also upload the files in ${path.join(here, '..', 'references')} as knowledge, if your chat app allows.)`);
  process.exit(0);
}
const entry = COMMANDS[cmd];
if (!entry) { console.error(`Unknown command: ${cmd}\n`); help(); process.exit(1); }
const r = spawnSync(process.execPath, [path.join(here, entry[0]), ...rest], { stdio: 'inherit' });
process.exit(r.status ?? 1);
