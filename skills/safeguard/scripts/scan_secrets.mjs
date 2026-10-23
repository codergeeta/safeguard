#!/usr/bin/env node
// Finds plaintext secrets in a folder. Values are always redacted in output.
// Usage: node scan_secrets.mjs <dir> [--home] [--json]
//   --home  also check well-known credential files in your home directory
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs, exists, isDir, readText, walk, redact, lineOf, Report, homeDir, isOwnFile } from './lib/common.mjs';
import { selfSkip } from './lib/scanner.mjs';

const USAGE = 'Usage: node scan_secrets.mjs <dir> [--home] [--json]\n  --home  also check credential files in your home directory (~/.ssh, ~/.aws, ~/.npmrc, ...)';
const args = parseArgs(process.argv.slice(2), { flags: ['json', 'home', 'help'] }, USAGE);
if (args.help || (!args._[0] && !args.home)) {
  console.log(USAGE);
  process.exit(args.help ? 0 : 1);
}

const RULES = [
  { id: 'private-key', sev: 'HIGH', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g, label: 'Private key' },
  { id: 'aws-access-key', sev: 'HIGH', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, label: 'AWS access key ID' },
  { id: 'aws-secret', sev: 'HIGH', re: /aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})/gi, label: 'AWS secret access key', group: 1 },
  { id: 'github-token', sev: 'HIGH', re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g, label: 'GitHub token' },
  { id: 'gitlab-token', sev: 'HIGH', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, label: 'GitLab token' },
  { id: 'npm-token', sev: 'HIGH', re: /\bnpm_[A-Za-z0-9]{36}\b/g, label: 'npm token (can publish packages)' },
  { id: 'npmrc-auth', sev: 'HIGH', re: /_authToken\s*=\s*([^\s$][^\s]{10,})/g, label: 'npm registry auth token', group: 1 },
  { id: 'pypi-token', sev: 'HIGH', re: /\bpypi-AgE[A-Za-z0-9_-]{50,}\b/g, label: 'PyPI token (can publish packages)' },
  { id: 'anthropic-key', sev: 'HIGH', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, label: 'Anthropic API key' },
  { id: 'openai-key', sev: 'HIGH', re: /\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g, label: 'OpenAI-style API key' },
  { id: 'google-api-key', sev: 'HIGH', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, label: 'Google API key' },
  { id: 'gcp-service-account', sev: 'HIGH', re: /"type"\s*:\s*"service_account"/g, label: 'Google Cloud service account key file' },
  { id: 'slack-token', sev: 'HIGH', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, label: 'Slack token' },
  { id: 'slack-webhook', sev: 'MEDIUM', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g, label: 'Slack webhook URL' },
  { id: 'discord-webhook', sev: 'MEDIUM', re: /https:\/\/discord(app)?\.com\/api\/webhooks\/\d+\/[\w-]{20,}/g, label: 'Discord webhook URL' },
  { id: 'stripe-key', sev: 'HIGH', re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/g, label: 'Stripe live secret key' },
  { id: 'twilio', sev: 'MEDIUM', re: /\bSK[0-9a-fA-F]{32}\b/g, label: 'Twilio API key' },
  { id: 'sendgrid', sev: 'HIGH', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, label: 'SendGrid API key' },
  { id: 'vercel-token', sev: 'MEDIUM', re: /VERCEL_TOKEN\s*[=:]\s*["']?([A-Za-z0-9]{24,})/g, label: 'Vercel token', group: 1 },
  { id: 'supabase-service', sev: 'HIGH', re: /SUPABASE_SERVICE_ROLE(_KEY)?\s*[=:]\s*["']?(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|sb_secret_[A-Za-z0-9_-]{20,})/g, label: 'Supabase service-role key (bypasses row-level security)', group: 2 },
  { id: 'db-url', sev: 'HIGH', re: /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^\s:/@"']+:([^\s@"'$]{4,})@[^\s"']+/g, label: 'Database URL with password', group: 4 },
  { id: 'jwt', sev: 'LOW', re: /\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\b/g, label: 'JWT (may be a long-lived token)' },
  { id: 'generic-assign', sev: 'MEDIUM', re: /\b([A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*)\s*[=:]\s*["']?([^\s"'#$<>{}]{12,})/g, label: 'Secret-looking assignment', group: 3, nameGroup: 1 },
  { id: 'wp-config', sev: 'MEDIUM', re: /define\s*\(\s*['"]DB_PASSWORD['"]\s*,\s*['"]([^'"]{4,})['"]/g, label: 'WordPress DB password', group: 1 },
];
// Whole-value placeholders, plus values that are clearly references rather than secrets.
const PLACEHOLDER = /^(x{3,}|\*{3,}|\.{3,}|changeme|change_me|change-me|your[_-][\w-]*|example[\w-]*|placeholder|dummy|test|testing|sample|redacted|none|null|undefined|true|false|todo|tbd)$|^(<|\$\{|\$\(|\{\{|process\.env|os\.environ|getenv|env\()/i;
const SKIP_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.pdf', '.zip', '.gz', '.tgz', '.woff', '.woff2', '.ttf', '.mp4', '.mp3', '.lock', '.map']);
const LOCKFILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'composer.lock', 'Cargo.lock', 'Gemfile.lock', 'go.sum', 'uv.lock', 'bun.lock']);

function gitIgnored(root) {
  // Rough .gitignore check for .env-style files only; enough to grade severity.
  const gi = readText(path.join(root, '.gitignore')) || '';
  return name => gi.split(/\r?\n/).some(l => {
    l = l.trim();
    if (!l || l.startsWith('#') || l.startsWith('!')) return false;
    const pat = l.replace(/^\//, '').replace(/\/$/, '');
    const re = new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
    return re.test(name);
  });
}

function scanText(file, text, report, ignored) {
  const base = path.basename(file);
  const envFile = /^\.env(\..+)?$/.test(base) && !/\.(example|sample|template|dist)$/.test(base);
  let found = 0;
  const reported = new Set();
  for (const r of RULES) {
    r.re.lastIndex = 0;
    let m, n = 0;
    while ((m = r.re.exec(text)) && n < 10) {
      const value = r.group ? m[r.group] : m[0];
      if (!value || PLACEHOLDER.test(value)) continue;
      if ([...reported].some(v => v.includes(value) || value.includes(v))) continue;
      reported.add(value);
      if (r.id === 'generic-assign' && (/^[a-z]+(\.[a-z]+)+$/i.test(value) || /^[A-Z_]+$/.test(value))) continue;
      n++; found++;
      let sev = r.sev;
      let extra = '';
      if (envFile && ignored(base)) { sev = sev === 'HIGH' ? 'LOW' : 'INFO'; extra = ' (file is git-ignored; still readable by any malware or agent on this machine)'; }
      const name = r.nameGroup ? ` ${m[r.nameGroup]}` : '';
      report.add(sev, `secret:${r.id}`, file, lineOf(text, m.index), `${r.label}${name}: ${redact(value)}${extra}`);
    }
  }
  return found;
}

// Cipher name of an OpenSSH-format key ("none" = no passphrase); PEM keys return 'none' unless marked ENCRYPTED.
function opensshCipher(text) {
  const m = text.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END/);
  if (!m) return 'none';
  try {
    const buf = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
    const len = buf.readUInt32BE(15);
    return buf.subarray(19, 19 + len).toString('latin1');
  } catch {
    return 'unknown';
  }
}

const report = new Report('safeguard: secrets scan', args._[0] ? path.resolve(args._[0]) : null);

if (args._[0]) {
  const root = path.resolve(args._[0]);
  if (!isDir(root)) { console.error(`Not a folder: ${root}`); process.exit(1); }
  const ignored = gitIgnored(root);
  let n = 0;
  const { skipPaths, note } = selfSkip(root);
  if (note) report.note(note);
  const stats = {};
  for (const file of walk(root, { skipPaths, stats })) {
    const base = path.basename(file);
    const ext = path.extname(base).toLowerCase();
    if (LOCKFILES.has(base) || SKIP_EXT.has(ext) || isOwnFile(file)) continue;
    // Bundles can be large and often contain baked-in keys; the rules are linear, so read up to 8 MB.
    const text = readText(file, 8 * 1024 * 1024);
    if (text == null) continue;
    n++;
    scanText(file, text, report, ignored);
  }
  if (exists(path.join(root, '.git'))) {
    report.note('Only the current files were scanned. Secrets deleted from files can still be in git history: check with `git log -p -S <prefix>` or a tool like gitleaks, and rotate anything that was ever committed.');
  }
  report.meta.files = n;
  if (stats.truncated) report.note('File limit reached — scan sub-folders separately for full coverage.');
  report.note(`${n} text files scanned (node_modules, vendor, and virtualenvs skipped).`);
}

if (args.home) {
  const h = homeDir();
  const checks = [
    ['.ssh', 'SSH keys — check each private key has a passphrase'],
    [path.join('.aws', 'credentials'), 'AWS long-lived credentials — prefer SSO / short-lived'],
    ['.npmrc', 'npm config (may hold a publish token)'],
    ['.pypirc', 'PyPI config (may hold an upload token)'],
    [path.join('.composer', 'auth.json'), 'Composer auth (private repo / GitHub tokens)'],
    [path.join('.config', 'composer', 'auth.json'), 'Composer auth'],
    [path.join('.docker', 'config.json'), 'Docker registry credentials'],
    [path.join('.kube', 'config'), 'Kubernetes credentials'],
    ['.git-credentials', 'Git credentials stored in plaintext'],
    [path.join('.config', 'gh', 'hosts.yml'), 'GitHub CLI token'],
    [path.join('.gem', 'credentials'), 'RubyGems API key'],
    [path.join('.cargo', 'credentials.toml'), 'crates.io token'],
    [path.join('.nuget', 'NuGet', 'NuGet.Config'), 'NuGet feed credentials'],
    ['.netrc', 'netrc credentials'],
  ];
  const ignoredNone = () => false;
  for (const [rel, desc] of checks) {
    const p = path.join(h, rel);
    if (!exists(p)) continue;
    if (isDir(p)) {
      let names = [];
      try { names = fs.readdirSync(p); } catch { report.note(`Could not read ${p}`); }
      for (const f of names) {
        const fp = path.join(p, f);
        const t = readText(fp, 256 * 1024);
        if (!t) continue;
        if (/PRIVATE KEY-----/.test(t)) {
          const encrypted = /ENCRYPTED/.test(t) || opensshCipher(t) !== 'none';
          report.add(encrypted ? 'INFO' : 'MEDIUM', 'secret:ssh-key', fp, null, encrypted ? 'SSH private key (passphrase-protected)' : 'SSH private key WITHOUT a passphrase — infostealers take these first');
        }
      }
      continue;
    }
    const t = readText(p, 1024 * 1024) || '';
    const found = scanText(p, t, report, ignoredNone);
    if (!found) report.add('INFO', 'secret:credential-file', p, null, `${desc} — present`);
  }
  report.note('Home-directory credential files are normal, but every one is a target for infostealers. Prefer short-lived tokens, OS keychains, and passphrase-protected keys.');
}

report.finish(args.json);
