#!/usr/bin/env node
// Finds plaintext secrets in a folder. Values are always redacted in output.
// Usage: node scan_secrets.mjs <dir> [--home] [--json]
//   --home  also check well-known credential files in your home directory
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs, exists, isDir, readText, walk, redact, lineOf, Report, homeDir, isOwnFile } from './lib/common.mjs';
import { selfSkip } from './lib/scanner.mjs';
import { scanText } from './lib/secrets.mjs';

const USAGE = 'Usage: node scan_secrets.mjs <dir> [--home] [--json]\n  --home  also check credential files in your home directory (~/.ssh, ~/.aws, ~/.npmrc, ...)';
const args = parseArgs(process.argv.slice(2), { flags: ['json', 'home', 'help'] }, USAGE);
if (args.help || (!args._[0] && !args.home)) {
  console.log(USAGE);
  process.exit(args.help ? 0 : 1);
}

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
