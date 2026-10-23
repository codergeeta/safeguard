// Static file/tree scanner used by scan_package and audit_agent_config.
import fs from 'node:fs';
import path from 'node:path';
import { walk, readText, readHeadTail, fileSize, MAX_TEXT_BYTES, readJson, lineOf, lineText, samePath, isInside, isOwnFile, SKILL_ROOT } from './common.mjs';
import { COMMAND_RULES, CODE_RULES, INJECTION_RULES, NULLED_RULE, SIGNALS, matchRules, findBase64Blobs, judgePth } from './patterns.mjs';
import { auditSettings, auditMcpConfig } from './agentcfg.mjs';

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.py', '.pyw', '.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phar', '.inc', '.rb', '.go', '.rs', '.java', '.kt', '.cs', '.ps1', '.psm1', '.sh', '.bash', '.zsh', '.bat', '.cmd', '.vbs', '.lua', '.pl']);
const PHP_EXT = new Set(['.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phar', '.inc']);
const DOC_EXT = new Set(['.md', '.markdown', '.rst', '.txt', '.adoc']);
const BINARY_EXEC_EXT = new Set(['.exe', '.dll', '.so', '.dylib', '.bin', '.scr', '.msi', '.jar', '.pyd']);
const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare', 'prepublish', 'preuninstall', 'uninstall', 'postuninstall'];
const COMPOSER_EVENTS = /^(pre|post)-(install|update|autoload-dump|root-package-install|create-project|package-install|package-update)-cmd$|^(pre|post)-package-(install|update)$/;

function isAgentInstructionFile(file) {
  const base = path.basename(file).toLowerCase();
  return base === 'skill.md' || base === 'claude.md' || base === 'agents.md' || /[\\/]\.claude[\\/]/.test(file) || /[\\/](commands|agents)[\\/][^\\/]+\.md$/i.test(file);
}

export function scanFile(file, report, opts = {}) {
  const ext = path.extname(file).toLowerCase();
  const base = path.basename(file);
  const lower = base.toLowerCase();

  if (isOwnFile(file)) { report.bump('ownFilesSkipped'); return; }
  if (BINARY_EXEC_EXT.has(ext)) {
    report.add('LOW', 'binary', file, null, `Bundled ${ext} binary — cannot be reviewed as text; ask why the package needs it`);
    return;
  }
  let text = readText(file);
  if (text == null) {
    if (fileSize(file) <= MAX_TEXT_BYTES) return; // binary or unreadable
    const ht = readHeadTail(file);
    if (!ht) return;
    text = ht.text;
    report.add('INFO', 'coverage', file, null, `Large file (${(ht.size / 1048576).toFixed(1)} MB): only the first and last 1 MB were scanned`);
  }

  const isCode = CODE_EXT.has(ext) || lower === 'dockerfile' || lower === 'makefile' || lower === 'rakefile' || lower === 'build.rs';
  const isDoc = DOC_EXT.has(ext);
  const agentFile = isAgentInstructionFile(file);

  // Python startup hooks.
  if (ext === '.pth') {
    const v = judgePth(base, text);
    if (v) report.add(v.sev, 'python-startup', file, v.line, v.msg, v.evidence);
    return;
  }
  if (lower === 'sitecustomize.py' || lower === 'usercustomize.py') {
    const risky = SIGNALS.network.test(text) || SIGNALS.exec.test(text) || /base64|exec\s*\(/.test(text);
    report.add(risky ? 'HIGH' : 'MEDIUM', 'python-startup', file, null, `${base} runs on every Python start${risky ? ' and contains network/exec/decoding code' : ' — confirm you created it'}`);
  }

  // PHP in upload folders is almost always a webshell.
  // (WordPress ships empty "Silence is golden" index.php stubs there; those have no code.)
  if (['.php', '.phtml', '.phar', '.php5', '.php7'].includes(ext) && /[\\/]uploads?[\\/]/i.test(file)) {
    const code = text.replace(/<\?php/gi, '').replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|#[^\n]*|\?>/g, '').trim();
    if (code) report.add('HIGH', 'webshell', file, null, 'PHP file inside an upload folder — uploads should never be executable code');
    else report.add('INFO', 'webshell', file, null, 'Empty PHP stub in an upload folder (normal for WordPress)');
  }

  siteConfig(file, lower, text, report);

  // Manifests.
  if (lower === 'package.json') scanPackageJson(file, report);
  if (lower === 'composer.json') scanComposerJson(file, report);
  if (lower === 'setup.py') report.add('INFO', 'install-hook', file, null, 'setup.py runs at source install — read it fully');
  if (lower === 'build.rs') report.add('INFO', 'install-hook', file, null, 'build.rs runs at compile time (and in IDE analysis) — read it fully');
  if (lower === 'extconf.rb') report.add('INFO', 'install-hook', file, null, 'extconf.rb runs at gem install — read it fully');
  if (lower === 'skill.md') report.add('INFO', 'agent-skill', file, null, 'Agent skill: read the whole SKILL.md and every script it tells the agent to run');
  if (/^settings(\.local)?\.json$/.test(lower) && /[\\/]\.claude[\\/]/.test(file)) {
    const json = readJson(file);
    if (json) auditSettings(json, file, report, { scope: opts.settingsScope || 'project', projectDir: path.dirname(path.dirname(file)) });
  }
  if (lower === '.mcp.json' || (lower === 'mcp.json' && /[\\/]\.(cursor|vscode)[\\/]/.test(file))) {
    const json = readJson(file);
    if (json) auditMcpConfig(json, file, report, { scope: 'project' });
  }
  if (lower === 'tasks.json' && /[\\/]\.vscode[\\/]/.test(file) && /"runOn"\s*:\s*"folderOpen"/.test(text)) {
    const cmdHit = matchRules(COMMAND_RULES, text).some(h => h.sev === 'HIGH');
    report.add(cmdHit ? 'HIGH' : 'MEDIUM', 'editor-autorun', file, lineOf(text, text.search(/folderOpen/)), 'VS Code task runs automatically when the folder is opened');
  }

  // Command patterns (in docs, downgrade unless the doc is an agent instruction file).
  for (const h of matchRules(COMMAND_RULES, text)) {
    let sev = h.sev;
    if (isDoc && !agentFile && sev === 'HIGH') sev = 'LOW';
    const line = lineOf(text, h.index);
    report.add(sev, `cmd:${h.id}`, file, line, isDoc && !agentFile ? `${h.msg} (in documentation)` : h.msg, lineText(text, line, h.index));
  }

  if (isCode || ext === '' || ext === '.json' || ext === '.yml' || ext === '.yaml') {
    for (const h of matchRules(CODE_RULES, text, ext)) {
      const line = lineOf(text, h.index);
      report.add(h.sev, `code:${h.id}`, file, line, h.msg, lineText(text, line, h.index));
    }
  }

  for (const h of matchRules([NULLED_RULE], text)) {
    const line = lineOf(text, h.index);
    report.add(h.sev, `code:${h.id}`, file, line, h.msg, lineText(text, line, h.index));
  }

  // PHP: request input stored in a variable, then passed to a code/command execution function.
  if (PHP_EXT.has(ext)) {
    const tainted = new Set();
    for (const m of text.matchAll(/\$(\w{1,40})\s*=\s*[^;\n]{0,120}?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/g)) tainted.add(m[1]);
    for (const v of tainted) {
      const sink = new RegExp(`\\b(eval|assert|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec|call_user_func(_array)?|create_function|include|require)(_once)?\\s*\\(?[^;\\n]{0,120}?\\$${v}\\b`, 'i');
      const m = sink.exec(text);
      if (m) {
        const line = lineOf(text, m.index);
        report.add('HIGH', 'code:php-webshell', file, line, `PHP webshell: request input ($${v}) reaches ${m[1]}()`, lineText(text, line, m.index));
      }
    }
  }

  if (isCode) {
    for (const b of findBase64Blobs(text)) {
      report.add('MEDIUM', 'obfuscation', file, lineOf(text, b.index), `Long base64 blob (${b.length} chars) — decode as text to see what it is (never run it)`);
    }
    const net = SIGNALS.network.test(text);
    if (net && SIGNALS.credPaths.test(text)) {
      const idx = text.search(SIGNALS.credPaths);
      report.add('HIGH', 'exfil-combo', file, lineOf(text, idx), 'Reads credential files or browser/wallet stores AND makes network requests', lineText(text, lineOf(text, idx), idx));
    }
    if (net && SIGNALS.envDump.test(text)) {
      const idx = text.search(SIGNALS.envDump);
      report.add('HIGH', 'exfil-combo', file, lineOf(text, idx), 'Collects the whole environment AND makes network requests', lineText(text, lineOf(text, idx), idx));
    }
  }

  // Prompt injection: everywhere, since agents read docs, comments, and metadata.
  // "Don't tell the user" in ordinary source is usually a UX comment; in docs and agent files it is a red flag.
  for (const h of matchRules(INJECTION_RULES, text)) {
    if (h.id === 'zero-width' && h.index === 0) continue;
    const sev = h.id === 'hide-from-user' && isCode && !agentFile ? 'MEDIUM' : h.sev;
    const line = lineOf(text, h.index);
    report.add(sev, `injection:${h.id}`, file, line, h.msg, lineText(text, line, h.index));
  }
}

// Folders a web server typically serves to the public.
const WEBROOT = /[\\/](public|public_html|htdocs|www|wwwroot|web|html|httpdocs)[\\/]/i;

// Website production settings: debug left on, placeholder keys, secrets in the public folder.
function siteConfig(file, lower, text, report) {
  const at = re => { const i = text.search(re); return i < 0 ? null : lineOf(text, i); };
  if (lower === 'wp-config.php') {
    if (/put your unique phrase here/i.test(text)) report.add('HIGH', 'site-config', file, at(/put your unique phrase here/i), 'WordPress secret keys/salts are still the placeholder — anyone can forge login cookies. Generate new ones');
    if (/define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true/i.test(text)) report.add('MEDIUM', 'site-config', file, at(/WP_DEBUG['"]\s*,\s*true/i), 'WP_DEBUG is on — errors can reveal paths and data in production');
    if (/define\s*\(\s*['"]WP_DEBUG_LOG['"]\s*,\s*true/i.test(text) && !/WP_DEBUG_LOG['"]\s*,\s*['"]\//i.test(text)) report.add('MEDIUM', 'site-config', file, at(/WP_DEBUG_LOG/i), 'WP_DEBUG_LOG writes wp-content/debug.log, which is publicly downloadable by default');
    if (!/DISALLOW_FILE_EDIT['"]\s*,\s*true/i.test(text)) report.add('LOW', 'site-config', file, null, 'DISALLOW_FILE_EDIT is not set — a stolen admin login can edit PHP files from the dashboard');
  }
  if (/^\.env(\.(production|prod|live))?$/.test(lower)) {
    const prod = /^\s*APP_ENV\s*=\s*["']?prod/im.test(text) || /\.(production|prod|live)$/.test(lower);
    if (/^\s*APP_DEBUG\s*=\s*["']?true/im.test(text)) report.add(prod ? 'MEDIUM' : 'LOW', 'site-config', file, at(/^\s*APP_DEBUG\s*=/im), `APP_DEBUG=true${prod ? ' in production' : ''} — Laravel and similar frameworks show secrets and stack traces on errors`);
  }
  if (lower === 'settings.py' && /^\s*DEBUG\s*=\s*True\b/m.test(text)) {
    const exposed = /ALLOWED_HOSTS\s*=\s*\[[^\]]*['"](\*|[\w-]+\.[\w.-]+)['"]/.test(text);
    report.add(exposed ? 'MEDIUM' : 'LOW', 'site-config', file, at(/^\s*DEBUG\s*=\s*True/m), `Django DEBUG = True${exposed ? ' with public ALLOWED_HOSTS' : ''} — error pages expose settings and code`);
  }
  if ((lower === '.htaccess' && /^\s*Options\s+[^\n]*\+Indexes/im.test(text)) || (/\.conf$|^nginx\.conf$/.test(lower) && /^\s*autoindex\s+on\s*;/m.test(text))) {
    report.add('LOW', 'site-config', file, at(/\+Indexes|autoindex\s+on/i), 'Directory listing is enabled — visitors can browse folders and download backups');
  }
  if (WEBROOT.test(file) && (/^\.env(\..+)?$/.test(lower) && !/\.(example|sample|template|dist)$/.test(lower) || /\.(sql|sql\.gz|bak|old|orig|swp)$/.test(lower) || /^(phpinfo|info)\.php$/.test(lower) || /^debug\.log$/.test(lower))) {
    report.add(/^\.env|\.sql/.test(lower) ? 'HIGH' : 'MEDIUM', 'site-config', file, null, `${path.basename(file)} sits in a public web folder — it may be downloadable by anyone. Move it outside the web root`);
  }
}

function scanPackageJson(file, report) {
  const pkg = readJson(file);
  if (!pkg || typeof pkg !== 'object') return;
  const scripts = pkg.scripts || {};
  for (const name of LIFECYCLE) {
    if (!scripts[name]) continue;
    const cmd = String(scripts[name]);
    const bad = matchRules(COMMAND_RULES, cmd).filter(h => h.sev === 'HIGH');
    report.add(bad.length ? 'HIGH' : 'MEDIUM', 'install-hook', file, null,
      `npm "${name}" script runs automatically at install${bad.length ? `: ${bad[0].msg}` : ' — check what it runs'}`, cmd);
  }
  const events = pkg.activationEvents;
  if (pkg.engines && pkg.engines.vscode && Array.isArray(events) && events.includes('*')) {
    report.add('LOW', 'editor-extension', file, null, 'VS Code extension activates on every startup ("*")');
  }
}

function scanComposerJson(file, report) {
  const c = readJson(file);
  if (!c || typeof c !== 'object') return;
  if (c.type === 'composer-plugin') {
    report.add('MEDIUM', 'install-hook', file, null, 'Composer plugin: runs code inside Composer at install/update (intercom-php 2026 technique)');
  }
  for (const [ev, val] of Object.entries(c.scripts || {})) {
    if (!COMPOSER_EVENTS.test(ev)) continue;
    const cmd = [].concat(val).join(' && ');
    const bad = matchRules(COMMAND_RULES, cmd).filter(h => h.sev === 'HIGH');
    report.add(bad.length ? 'HIGH' : 'LOW', 'install-hook', file, null, `Composer "${ev}" script runs automatically${bad.length ? `: ${bad[0].msg}` : ''}`, cmd);
  }
}

export function scanTree(root, report, opts = {}) {
  const skip = new Set(opts.deep ? ['.git'] : ['.git', 'node_modules', '__pycache__', '.venv', 'venv', '.tox', '.mypy_cache']);
  let n = 0;
  const { skipPaths, note } = selfSkip(root);
  if (note) report.note(note);
  const stats = {};
  // A .git folder inside a public web folder lets anyone download the full source and history.
  for (const w of ['', 'public', 'public_html', 'htdocs', 'www', 'wwwroot', 'web', 'html', 'httpdocs']) {
    const dir = path.join(root, w);
    const servedRoot = w ? true : /^(public|public_html|htdocs|www|wwwroot|web|html|httpdocs)$/i.test(path.basename(root));
    if (servedRoot && fs.existsSync(path.join(dir, '.git', 'HEAD'))) report.add('HIGH', 'site-config', path.join(dir, '.git'), null, '.git folder inside the public web root — your source code, history and any committed secrets may be downloadable');
  }
  for (const file of walk(root, { skipDirs: skip, maxFiles: opts.maxFiles || 50000, skipPaths, skipVenvs: !opts.deep, stats })) {
    scanFile(file, report, opts);
    n++;
  }
  if (report.meta.ownFilesSkipped) report.note(`${report.meta.ownFilesSkipped} file(s) identical to safeguard's own files were skipped (another copy of this skill).`);
  if (stats.truncated) report.add('INFO', 'coverage', root, null, `Stopped after ${opts.maxFiles || 50000} files — scan sub-folders separately for full coverage`);
  if (stats.unreadable) report.note(`${stats.unreadable} folder(s) could not be read (permissions).`);
  report.bump('files', n);
  return n;
}

// Skip this skill's own folder (its rules contain the patterns it hunts) unless it is the target.
export function selfSkip(root) {
  if (samePath(root) === samePath(SKILL_ROOT) || !isInside(SKILL_ROOT, root)) return { skipPaths: [], note: null };
  return { skipPaths: [SKILL_ROOT], note: `Skipped safeguard's own folder (${SKILL_ROOT}): its rule files contain the patterns it looks for.` };
}
