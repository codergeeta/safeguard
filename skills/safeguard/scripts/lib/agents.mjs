// Where AI agents keep skills, MCP configs, and rules files. Skill paths follow the
// vercel-labs/skills agent table (docs/agents.md, checked 2026-10-23); `detect` is a
// folder whose presence means the agent is installed for this user.
import path from 'node:path';

export const AGENTS = [
  { id: 'claude-code', name: 'Claude Code', project: '.claude/skills', global: '~/.claude/skills', detect: '~/.claude' },
  { id: 'codex', name: 'OpenAI Codex', project: '.agents/skills', global: '~/.agents/skills', detect: '~/.codex' },
  { id: 'cursor', name: 'Cursor', project: '.agents/skills', global: '~/.cursor/skills', detect: '~/.cursor' },
  { id: 'github-copilot', name: 'GitHub Copilot', project: '.agents/skills', global: '~/.copilot/skills', detect: '~/.copilot' },
  { id: 'gemini-cli', name: 'Gemini CLI', project: '.agents/skills', global: '~/.gemini/skills', detect: '~/.gemini' },
  { id: 'antigravity', name: 'Antigravity', project: '.agents/skills', global: '~/.gemini/antigravity/skills', detect: '~/.gemini/antigravity' },
  { id: 'windsurf', name: 'Windsurf', project: '.windsurf/skills', global: '~/.codeium/windsurf/skills', detect: '~/.codeium/windsurf' },
  { id: 'cline', name: 'Cline', project: '.agents/skills', global: '~/.agents/skills', detect: '~/.cline' },
  { id: 'opencode', name: 'OpenCode', project: '.agents/skills', global: '~/.config/opencode/skills', detect: '~/.config/opencode' },
  { id: 'goose', name: 'Goose', project: '.goose/skills', global: '~/.config/goose/skills', detect: '~/.config/goose' },
  { id: 'roo', name: 'Roo Code', project: '.roo/skills', global: '~/.roo/skills', detect: '~/.roo' },
  { id: 'kilo', name: 'Kilo Code', project: '.agents/skills', global: '~/.kilo/skills', detect: '~/.kilo' },
  { id: 'kiro-cli', name: 'Kiro', project: '.kiro/skills', global: '~/.kiro/skills', detect: '~/.kiro' },
  { id: 'continue', name: 'Continue', project: '.continue/skills', global: '~/.continue/skills', detect: '~/.continue' },
  { id: 'junie', name: 'JetBrains Junie', project: '.junie/skills', global: '~/.junie/skills', detect: '~/.junie' },
  { id: 'qwen-code', name: 'Qwen Code', project: '.qwen/skills', global: '~/.qwen/skills', detect: '~/.qwen' },
  { id: 'trae', name: 'Trae', project: '.trae/skills', global: '~/.trae/skills', detect: '~/.trae' },
  { id: 'droid', name: 'Factory Droid', project: '.agents/skills', global: '~/.factory/skills', detect: '~/.factory' },
  { id: 'openhands', name: 'OpenHands', project: '.openhands/skills', global: '~/.openhands/skills', detect: '~/.openhands' },
  { id: 'universal', name: 'Amp, Zed, Warp and other .agents readers', project: '.agents/skills', global: '~/.config/agents/skills', detect: '~/.config/agents' },
];

// MCP server config files: [path, format]. Paths starting with % use the Windows APPDATA folder.
export const MCP_CONFIGS = [
  ['~/.claude.json', 'json'],
  ['%APPDATA%/Claude/claude_desktop_config.json', 'json'],
  ['~/Library/Application Support/Claude/claude_desktop_config.json', 'json'],
  ['~/.config/Claude/claude_desktop_config.json', 'json'],
  ['~/.codex/config.toml', 'toml'],
  ['~/.cursor/mcp.json', 'json'],
  ['~/.gemini/settings.json', 'json'],
  ['~/.codeium/windsurf/mcp_config.json', 'json'],
  ['%APPDATA%/Code/User/mcp.json', 'json'],
  ['~/Library/Application Support/Code/User/mcp.json', 'json'],
  ['~/.config/Code/User/mcp.json', 'json'],
  ['%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json', 'json'],
  ['~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json', 'json'],
  ['~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json', 'json'],
  ['~/.config/zed/settings.json', 'jsonc'],
  ['%APPDATA%/Zed/settings.json', 'jsonc'],
];

export const PROJECT_MCP_CONFIGS = [
  ['.mcp.json', 'json'], ['.cursor/mcp.json', 'json'], ['.vscode/mcp.json', 'json'],
  ['.gemini/settings.json', 'json'], ['.codex/config.toml', 'toml'], ['.roo/mcp.json', 'json'], ['.zed/settings.json', 'jsonc'],
];

// Files agents read as standing instructions: a place to hide prompt injection.
export const PROJECT_RULES = [
  'CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'CONVENTIONS.md', '.cursorrules', '.windsurfrules', '.clinerules',
  '.github/copilot-instructions.md', '.cursor/rules', '.windsurf/rules', '.roo/rules', '.kiro/steering',
  '.github/instructions', '.continue/rules', '.junie/guidelines.md',
];

export function expand(p, home) {
  if (p.startsWith('%APPDATA%')) return process.env.APPDATA ? path.join(process.env.APPDATA, p.slice('%APPDATA%/'.length)) : null;
  return p.startsWith('~') ? path.join(home, p.slice(2)) : p;
}

// Distinct global skill folders across all agents (several agents share ~/.agents/skills).
export function globalSkillDirs(home) {
  return [...new Set(AGENTS.map(a => expand(a.global, home)))];
}

export const PROJECT_SKILL_DIRS = [...new Set(AGENTS.map(a => a.project))];
