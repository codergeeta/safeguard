#!/usr/bin/env node
// Git pre-commit guard: blocks commits that add secrets (keys, tokens, private keys, .env files).
//   run (from the hook):  node precommit.mjs
//   install in a repo:    node precommit.mjs --install [--repo <dir>] [--dry-run]
//   remove:               node precommit.mjs --uninstall [--repo <dir>]
// Bypass once, deliberately: git commit --no-verify
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs, exists, Report, readText } from './lib/common.mjs';
import { scanText } from './lib/secrets.mjs';

const USAGE = 'Usage: node precommit.mjs [--install | --uninstall] [--repo <dir>] [--dry-run]';
const args = parseArgs(process.argv.slice(2), { flags: ['install', 'uninstall', 'dry-run', 'help'], options: ['repo'] }, USAGE);
if (args.help) { console.log(USAGE); process.exit(0); }
const repo = path.resolve(args.repo || process.cwd());
const git = (...a) => spawnSync('git', ['-C', repo, ...a], { encoding: 'buffer', maxBuffer: 256 * 1024 * 1024 });
const MARK = '# safeguard pre-commit hook';

if (args.install || args.uninstall) {
  const r = git('rev-parse', '--git-path', 'hooks');
  if (r.status !== 0) { console.error(`Not a git repository: ${repo}`); process.exit(1); }
  const hooksDir = path.resolve(repo, r.stdout.toString().trim());
  const hook = path.join(hooksDir, 'pre-commit');
  const current = readText(hook);
  const ours = current != null && current.includes(MARK);
  if (args.uninstall) {
    if (!ours) { console.log(current == null ? 'No pre-commit hook installed.' : 'The existing pre-commit hook is not Safeguard\'s; left untouched.'); process.exit(0); }
    if (!args['dry-run']) fs.rmSync(hook);
    console.log(`✓ removed ${hook}`);
    process.exit(0);
  }
  if (current != null && !ours) {
    console.error(`A different pre-commit hook already exists at ${hook}; left untouched.\nTo chain it, add this line to that hook:\n  node "${fileURLToPath(import.meta.url)}" || exit 1`);
    process.exit(1);
  }
  const script = `#!/bin/sh\n${MARK} (github.com/codergeeta/safeguard)\n# Blocks commits that add secrets. Bypass once on purpose with: git commit --no-verify\n"${process.execPath.replace(/\\/g, '/')}" "${fileURLToPath(import.meta.url).replace(/\\/g, '/')}" --repo "$(git rev-parse --show-toplevel)" || exit 1\n`;
  if (!args['dry-run']) { fs.mkdirSync(hooksDir, { recursive: true }); fs.writeFileSync(hook, script, { mode: 0o755 }); }
  console.log(`✓ ${args['dry-run'] ? 'would install' : 'installed'} ${hook}\nCommits that add keys, tokens, private keys or .env files will now be blocked.`);
  process.exit(0);
}

// ---------- hook run ----------
const staged = git('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z');
if (staged.status !== 0) { console.error('safeguard pre-commit: not a git repository (skipping)'); process.exit(0); }
const files = staged.stdout.toString().split('\0').filter(Boolean);
const report = new Report('safeguard pre-commit', repo);
const RISKY_NAME = /(^|\/)(\.env(\.(?!example$|sample$|template$|dist$)[\w.-]+)?|id_rsa|id_ed25519|id_ecdsa|[^/]+\.(pem|p12|pfx|key|keystore|jks)|\.npmrc|\.pypirc|\.git-credentials|credentials\.json|service[-_]account[^/]*\.json)$/i;
const BINARY = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|woff2?|ttf|mp[34]|lock)$/i;
for (const f of files) {
  if (RISKY_NAME.test(f) && !/\.pub$/.test(f)) report.add('HIGH', 'secret:file', path.join(repo, f), null, 'Commits a file that normally holds secrets — add it to .gitignore instead');
  if (BINARY.test(f)) continue;
  const blob = git('show', `:${f}`);
  if (blob.status !== 0 || blob.stdout.length > 4 * 1024 * 1024 || blob.stdout.subarray(0, 8192).includes(0)) continue;
  scanText(path.join(repo, f), blob.stdout.toString('utf8'), report);
}
const block = report.findings.filter(f => f.severity === 'HIGH' || f.severity === 'MEDIUM');
if (!block.length) process.exit(0);
console.error('\n✋ Safeguard blocked this commit: it would add secrets to git history (they stay there even if deleted later).\n');
for (const f of block) console.error(`  ${f.severity.padEnd(6)} ${f.file}${f.line ? ':' + f.line : ''} — ${f.message}`);
console.error('\nFix: remove the secret (use environment variables or a secret manager), unstage the file, and add it to .gitignore.\nIf a real key was already pushed anywhere, rotate it.\nFalse alarm? Commit once with: git commit --no-verify\n');
process.exit(1);
