// Audits Claude Code / agent settings, hooks, permissions, and MCP server configs.
import path from 'node:path';
import { exists, redact, homeDir } from './common.mjs';
import { COMMAND_RULES, matchRules } from './patterns.mjs';
import { scanFile } from './scanner.mjs';

const SECRET_KEY = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)/i;
const BROAD_ALLOW = [
  { re: /^Bash$|^Bash\(\*\)$|^Bash\(\*:\*\)$|^Bash\(:\*\)$/, msg: 'Allows ANY shell command without asking' },
  { re: /^Bash\((curl|wget|sh|bash|powershell|pwsh|python3?|node|npx|bunx|uvx|eval|iex)\b[^)]*\*?\)$/i, msg: 'Allows a download/interpreter command without asking' },
  { re: /^WebFetch$|^WebFetch\(\*\)$/, msg: 'Allows fetching any URL without asking (data can be sent out via URLs)' },
  { re: /^(Read|Edit|Write)\((~|\/|[A-Za-z]:[\\/])?\*{1,2}\)$/, msg: 'Allows reading/writing any file without asking' },
  { re: /^mcp__\w+$|^mcp__\*$/, msg: 'Allows every tool of an MCP server without asking' },
];

// Commands may point to a script file; scan it too. Paths are tried exactly as written
// (absolute, ~, $CLAUDE_PROJECT_DIR, or relative to the project).
function scanReferencedScripts(cmd, projectDir, report) {
  const tokens = String(cmd).match(/"[^"]+"|'[^']+'|[^\s"';&|<>()]+/g) || [];
  for (let tok of tokens) {
    tok = tok.replace(/^["']|["']$/g, '');
    if (!/\.(sh|bash|ps1|py|js|mjs|cjs|ts|bat|cmd|rb|php|pl)$/i.test(tok)) continue;
    tok = tok.replace(/^(\$\{?CLAUDE_PROJECT_DIR\}?|%CLAUDE_PROJECT_DIR%)[\\/]?/, projectDir ? `${projectDir}${path.sep}` : '')
      .replace(/^~(?=[\\/])/, homeDir());
    const candidates = path.isAbsolute(tok) ? [tok] : [projectDir && path.resolve(projectDir, tok), projectDir && path.resolve(projectDir, '.claude', tok)];
    const hit = candidates.find(p => p && exists(p));
    if (hit) scanFile(hit, report);
  }
}

function checkCommand(cmd, file, report, ctx, baseSev, label) {
  const hits = matchRules(COMMAND_RULES, cmd);
  const worst = hits.find(h => h.sev === 'HIGH') || hits.find(h => h.sev === 'MEDIUM');
  if (worst) report.add(worst.sev, `agent:${label}`, file, null, `${label}: ${worst.msg}`, cmd);
  else report.add(baseSev, `agent:${label}`, file, null, `${label} runs automatically — confirm you added it`, cmd);
  scanReferencedScripts(cmd, ctx.projectDir, report);
}

export function auditSettings(json, file, report, ctx = {}) {
  const projectScope = ctx.scope === 'project';
  const hookBase = projectScope ? 'MEDIUM' : 'INFO';

  // Hooks: { Event: [ { matcher, hooks: [ { type: 'command', command } ] } ] }
  for (const [event, groups] of Object.entries(json.hooks || {})) {
    for (const g of [].concat(groups || [])) {
      for (const h of [].concat(g?.hooks || [])) {
        if (h?.type === 'command' && h.command) {
          report.bump('hooks');
          checkCommand(String(h.command), file, report, ctx, hookBase, `${event} hook${g.matcher ? ` (${g.matcher})` : ''}`);
        }
      }
    }
  }

  for (const key of ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper']) {
    if (typeof json[key] === 'string') checkCommand(json[key], file, report, ctx, projectScope ? 'MEDIUM' : 'INFO', key);
  }
  if (json.statusLine?.command) checkCommand(String(json.statusLine.command), file, report, ctx, 'INFO', 'statusLine command');

  const perms = json.permissions || {};
  if (perms.defaultMode === 'bypassPermissions') {
    report.add(projectScope ? 'HIGH' : 'MEDIUM', 'agent:permissions', file, null,
      projectScope ? 'Repository sets bypassPermissions — the agent would run everything without asking' : 'Default mode is bypassPermissions — every tool call runs without asking');
  }
  if (perms.defaultMode === 'acceptEdits' && projectScope) {
    report.add('LOW', 'agent:permissions', file, null, 'Repository sets acceptEdits as the default mode');
  }
  for (const rule of [].concat(perms.allow || [])) {
    const hit = BROAD_ALLOW.find(b => b.re.test(String(rule)));
    if (hit) report.add(projectScope ? 'HIGH' : 'MEDIUM', 'agent:permissions', file, null, `Allow rule "${rule}": ${hit.msg}`);
  }
  const deny = [].concat(perms.deny || []).join(' ');
  if (!projectScope && !/\.env|\.ssh|\.aws/.test(deny)) {
    report.add('INFO', 'agent:permissions', file, null, 'No deny rules for secrets — consider denying Read of ~/.ssh, ~/.aws, and .env files');
  }

  if (json.enableAllProjectMcpServers === true) {
    report.add('MEDIUM', 'agent:mcp', file, null, 'enableAllProjectMcpServers is on — any cloned repo\'s .mcp.json servers start without approval');
  }
  for (const [k, v] of Object.entries(json.env || {})) {
    if (SECRET_KEY.test(k) && typeof v === 'string' && v.length > 8) {
      report.add('MEDIUM', 'secret', file, null, `Secret "${k}" stored in plaintext settings (${redact(v)}) — prefer an OS keychain or apiKeyHelper`);
    }
  }
  if (json.mcpServers) auditMcpServers(json.mcpServers, file, report, ctx);
}

export function auditMcpConfig(json, file, report, ctx = {}) {
  if (json.mcpServers) auditMcpServers(json.mcpServers, file, report, ctx);
  if (json.servers) auditMcpServers(json.servers, file, report, ctx); // VS Code format
  // ~/.claude.json keeps per-project servers under projects[path].mcpServers
  for (const [proj, cfg] of Object.entries(json.projects || {})) {
    if (cfg?.mcpServers && Object.keys(cfg.mcpServers).length) {
      auditMcpServers(cfg.mcpServers, file, report, { ...ctx, label: `project ${proj}` });
    }
  }
}

function auditMcpServers(servers, file, report, ctx) {
  const where = ctx.label ? ` [${ctx.label}]` : '';
  for (const [name, s] of Object.entries(servers || {})) {
    if (!s || typeof s !== 'object') continue;
    report.bump('mcpServers');
    const tag = `MCP "${name}"${where}`;
    const url = s.url || s.serverUrl;
    if (url) {
      const u = String(url);
      const local = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(u);
      if (/^http:\/\//i.test(u) && !local) report.add('MEDIUM', 'agent:mcp', file, null, `${tag} uses unencrypted http to a remote host`, u);
      else if (/^https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(u) && !local) report.add('MEDIUM', 'agent:mcp', file, null, `${tag} connects to a raw IP address`, u);
      else report.add('INFO', 'agent:mcp', file, null, `${tag} is a remote server — confirm you trust ${u.replace(/^(https?:\/\/[^/]+).*/, '$1')}`);
    }
    if (s.command) {
      const cmdline = [s.command, ...[].concat(s.args || [])].join(' ');
      const hits = matchRules(COMMAND_RULES, cmdline);
      const fromTemp = /(^|[\\/])(tmp|temp|Downloads)[\\/]/i.test(cmdline);
      const worst = hits.find(h => h.sev === 'HIGH') || hits.find(h => h.sev === 'MEDIUM' && !(fromTemp && h.id === 'temp-exec'));
      if (worst) report.add(worst.sev, 'agent:mcp', file, null, `${tag}: ${worst.msg}`, cmdline);
      if (fromTemp) report.add('HIGH', 'agent:mcp', file, null, `${tag} runs from a temp or Downloads folder`, cmdline);
      const runner = /^(npx|bunx|pnpx|uvx|pipx)$/i.test(path.basename(String(s.command)).replace(/\.(cmd|exe)$/i, ''))
        || /\b(pnpm|yarn)\s+dlx\b/.test(cmdline) || /\bcmd(\.exe)?\b.*\/c\s+npx\b/i.test(cmdline);
      if (runner) {
        const pkgArg = [].concat(s.args || []).map(String).find(a => !a.startsWith('-') && !/^(dlx|run|exec|\/c|npx)$/i.test(a));
        const pinned = pkgArg && /(@|==)v?\d+(\.\d+){1,3}([-+.][\w.]+)?$/.test(pkgArg.replace(/^@[^/]+\//, ''));
        if (!pinned) report.add('MEDIUM', 'agent:mcp', file, null, `${tag} downloads ${pkgArg || 'a package'} unpinned on every start — pin an exact version`, cmdline);
      }
      if (/\bdocker\b/.test(cmdline) && /--privileged|-v\s+(\/|~|[A-Za-z]:\\)(\s|:)|--network[= ]host/.test(cmdline)) {
        report.add('MEDIUM', 'agent:mcp', file, null, `${tag} runs a container with broad host access`, cmdline);
      }
    }
    for (const [k, v] of Object.entries(s.env || {})) {
      if (SECRET_KEY.test(k) && typeof v === 'string' && v.length > 8 && !/^\$\{?\w+\}?$/.test(v)) {
        report.add('LOW', 'secret', file, null, `${tag} has secret "${k}" in plaintext config (${redact(v)})`);
      }
    }
    for (const [k, v] of Object.entries(s.headers || {})) {
      if (/authorization|token|key/i.test(k) && typeof v === 'string' && v.length > 12 && !/\$\{?\w+\}?/.test(v)) {
        report.add('LOW', 'secret', file, null, `${tag} has credential header "${k}" in plaintext config (${redact(v)})`);
      }
    }
  }
}
