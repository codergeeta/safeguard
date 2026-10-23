#!/usr/bin/env node
// Offline dependency and build-pipeline check across ecosystems:
// npm/pnpm/yarn/bun, Python (pip/uv/poetry/pipenv + local venvs), PHP Composer, RubyGems,
// Go, Rust/Cargo, Maven/Gradle, NuGet, Dockerfiles, GitHub Actions, VS Code workspace files.
// Usage: node check_deps.mjs <project-dir> [--json]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, exists, isDir, readText, readJson, walk, lineOf, lineText, Report, redact } from './lib/common.mjs';
import { COMMAND_RULES, matchRules, judgePth } from './lib/patterns.mjs';
import { scanFile, selfSkip } from './lib/scanner.mjs';

const USAGE = 'Usage: node check_deps.mjs <project-dir> [--json]';
const args = parseArgs(process.argv.slice(2), { flags: ['json', 'help'] }, USAGE);
if (args.help || !args._[0]) {
  console.log(USAGE);
  process.exit(args.help ? 0 : 1);
}
const root = path.resolve(args._[0]);
if (!isDir(root)) { console.error(`Not a folder: ${root}`); process.exit(1); }

const here = path.dirname(fileURLToPath(import.meta.url));
const KB = readJson(path.join(here, '..', 'references', 'known-bad.json')) || {};
const report = new Report('safeguard: dependency & pipeline check', root);
const seenEco = new Set();

// ---------- helpers ----------
const norm = (eco, n) => (eco === 'pypi' ? n.toLowerCase().replace(/[-_.]+/g, '-') : n.toLowerCase());

function knownBad(eco, name, version) {
  const list = KB[eco] || [];
  const n = norm(eco, name);
  const hit = list.find(e => norm(eco, e.name) === n);
  if (!hit) return null;
  const v = version ? String(version).replace(/^[=v^~]+/, '') : null;
  if (hit.versions.includes('*')) return { exact: true, note: hit.note, versions: hit.versions };
  if (v && hit.versions.includes(v)) return { exact: true, note: hit.note, versions: hit.versions };
  return { exact: false, note: hit.note, versions: hit.versions };
}

function lev(a, b) {
  if (Math.abs(a.length - b.length) > 1) return 2;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

// Real, well-known packages that happen to sit one edit away from another popular name.
const LEGIT_NEIGHBOURS = new Set(['preact', 'tslint', 'scapy', 'boto', 'vuex', 'requests', 'request', 'chalk', 'clap', 'rand', 'yaml', 'pyyaml', 'axios', 'moment', 'express', 'cors', 'debug', 'jest', 'next', 'react', 'torch', 'flask', 'django', 'rails', 'rack', 'serde', 'tokio', 'uuid', 'nanoid', 'redux', 'webpack', 'esbuild', 'rollup', 'pytest', 'numpy', 'scipy', 'pandas']);

function typosquatOf(eco, name) {
  const popular = (KB.popular && KB.popular[eco]) || [];
  const n = norm(eco, name);
  if (n.length < 5 || LEGIT_NEIGHBOURS.has(n) || popular.some(p => norm(eco, p) === n)) return null;
  return popular.find(p => lev(norm(eco, p), n) === 1) || null;
}

const reportedNames = new Set();
function checkName(eco, name, version, file, line, where = '') {
  if (!name) return;
  const kb = knownBad(eco, name, version);
  if (kb?.exact) report.add('HIGH', `deps:${eco}`, file, line, `${name}${version ? `@${version}` : ''} is a known-malicious release: ${kb.note}. Remove it, rebuild the environment, rotate secrets on machines that installed it`);
  else if (kb) report.add('MEDIUM', `deps:${eco}`, file, line, `${name} had malicious releases (${kb.versions.join(', ')}): ${kb.note}. Confirm the installed version is not one of them${where}`);
  const squat = !kb?.exact && typosquatOf(eco, name);
  const key = `${eco}|${norm(eco, name)}|${file}`;
  if (squat && !reportedNames.has(key)) {
    reportedNames.add(key);
    report.add('MEDIUM', `deps:${eco}`, file, line, `"${name}" is one letter away from popular "${squat}" — possible typosquat`);
  }
}

function hostOf(url) {
  try { return new URL(url).host || url.slice(0, 60); } catch { return String(url).slice(0, 60); }
}

// ---------- npm family ----------
const OK_NPM_HOSTS = /^https:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com|npm\.pkg\.github\.com)\//;

function npmManifest(file) {
  seenEco.add('npm');
  scanFile(file, report); // lifecycle scripts, injection text
  const pkg = readJson(file);
  if (!pkg || typeof pkg !== 'object') return;
  const text = readText(file) || '';
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, spec] of Object.entries(pkg[field] || {})) {
      const s = String(spec);
      const line = lineOf(text, text.indexOf(`"${name}"`));
      if (/^(git\+|git:|github:|gitlab:|bitbucket:|https?:|[\w-]+\/[\w.-]+(#.*)?$)/.test(s)) report.add('MEDIUM', 'deps:npm', file, line, `${name} comes from a git/URL source, bypassing registry checks`, s);
      else if (/^(\*|latest|x|)$/.test(s.trim())) report.add('LOW', 'deps:npm', file, line, `${name} accepts any version ("${s}")`);
      checkName('npm', name, /^\d/.test(s) ? s : null, file, line);
    }
  }
  const dir = path.dirname(file);
  const locks = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'];
  const hasDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).length > 0;
  if (hasDeps && !locks.some(l => exists(path.join(dir, l)))) {
    report.add('LOW', 'deps:npm', file, null, 'No lockfile — every install can pull new (possibly malicious) versions');
  }
  if (pkg.pnpm?.onlyBuiltDependencies) report.add('INFO', 'deps:npm', file, null, `pnpm build scripts allowed only for: ${[].concat(pkg.pnpm.onlyBuiltDependencies).join(', ')}`);
}

function npmLock(file) {
  seenEco.add('npm');
  const lock = readJson(file);
  if (!lock || typeof lock !== 'object') return;
  const scripts = [];
  const entries = [];
  if (lock.packages && typeof lock.packages === 'object') {
    for (const [p, info] of Object.entries(lock.packages)) {
      if (p && info && typeof info === 'object') entries.push([info.name || p.replace(/^.*node_modules\//, ''), info]);
    }
  } else if (lock.dependencies) {
    // lockfileVersion 1: nested `dependencies` tree.
    const stack = [lock.dependencies];
    while (stack.length) {
      for (const [name, info] of Object.entries(stack.pop() || {})) {
        if (!info || typeof info !== 'object') continue;
        entries.push([name, info]);
        if (info.dependencies) stack.push(info.dependencies);
      }
    }
  }
  for (const [name, info] of entries) {
    const resolved = typeof info.resolved === 'string' ? info.resolved : '';
    if (info.hasInstallScript) scripts.push(`${name}@${info.version}`);
    if (/^http:\/\//.test(resolved)) report.add('MEDIUM', 'deps:npm', file, null, `${name} downloaded over plain http (can be swapped in transit)`, resolved.slice(0, 100));
    else if (/^https:/.test(resolved) && !OK_NPM_HOSTS.test(resolved)) {
      report.add('MEDIUM', 'deps:npm', file, null, `${name} resolved from ${hostOf(resolved)} (not the public registry — fine only if it is your private registry)`);
    }
    if (/^git/.test(resolved)) report.add('LOW', 'deps:npm', file, null, `${name} installed from git: ${resolved.slice(0, 80)}`);
    checkName('npm', name, info.version, file, null);
  }
  if (scripts.length) {
    report.add('MEDIUM', 'deps:npm-install-scripts', file, null,
      `${scripts.length} dependencies run install scripts (the npm worm entry point). Consider ignore-scripts with an allow-list`,
      scripts.slice(0, 15).join(', ') + (scripts.length > 15 ? ', …' : ''));
  }
}

function yarnOrPnpmLock(file) {
  seenEco.add('npm');
  const text = readText(file, 30 * 1024 * 1024) || '';
  const base = path.basename(file);
  const re = base === 'pnpm-lock.yaml'
    ? /^\s{2}'?\/?(@?[^@\s'(]+)@(\d[^:'(\s]*)/gm
    : /^"?(@?[^@\s",]+)@[^\n]*\n\s+version:?\s+"?([^"\s]+)/gm;
  let m;
  while ((m = re.exec(text))) checkName('npm', m[1], m[2], file, lineOf(text, m.index));
  if (base === 'pnpm-lock.yaml') {
    const n = (text.match(/requiresBuild: true/g) || []).length;
    if (n) report.add('MEDIUM', 'deps:npm-install-scripts', file, null, `${n} dependencies need build scripts — make sure pnpm onlyBuiltDependencies is an explicit allow-list`);
    else if (/^lockfileVersion:\s*'?9/m.test(text)) report.note('pnpm v9+ lockfile: pnpm 10 blocks dependency build scripts unless listed in onlyBuiltDependencies — keep that list short.');
  }
}

function bunLock(file) {
  seenEco.add('npm');
  const text = readText(file, 30 * 1024 * 1024) || '';
  // bun.lock (text) lists packages as "name": ["name@version", ...]
  for (const m of text.matchAll(/"(@?[^"@\s]+)@(\d[^"\s]*)"/g)) checkName('npm', m[1], m[2], file, lineOf(text, m.index));
  for (const m of text.matchAll(/"(@?[^"@\s]+)@(https?:|git\+|github:)[^"]*"/g)) report.add('LOW', 'deps:npm', file, lineOf(text, m.index), `${m[1]} from a git/URL source`);
}

// ---------- Python ----------
function pyRequirements(file) {
  seenEco.add('pypi');
  const text = readText(file) || '';
  let unpinned = 0;
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) return;
    if (/^(-i|--index-url)\b/.test(line)) { report.add('INFO', 'deps:pypi', file, i + 1, 'Custom package index', line.replace(/\/\/[^@/]+@/, '//***@')); return; }
    if (/^--extra-index-url\b/.test(line)) { report.add('MEDIUM', 'deps:pypi', file, i + 1, '--extra-index-url mixes indexes: an attacker can publish your internal package name on public PyPI (dependency confusion)', line.replace(/\/\/[^@/]+@/, '//***@')); return; }
    if (/^--trusted-host\b/.test(line)) { report.add('MEDIUM', 'deps:pypi', file, i + 1, '--trusted-host disables TLS verification for that host', line); return; }
    if (/^-(r|c)\s/.test(line) || /^--/.test(line)) return;
    if (/^(git\+|hg\+|svn\+|https?:\/\/|file:)/.test(line) || /@\s*(git\+|https?:)/.test(line)) { report.add('MEDIUM', 'deps:pypi', file, i + 1, 'Requirement from a VCS/URL source, bypassing PyPI checks and pinning', line); return; }
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===?|~=|>=|<=|!=|>|<)?\s*([^\s;,]*)/);
    if (!m) return;
    if (m[3] !== '==' && m[3] !== '===') unpinned++;
    checkName('pypi', m[1], m[3]?.startsWith('==') ? m[4] : null, file, i + 1);
  });
  if (unpinned) report.add('LOW', 'deps:pypi', file, null, `${unpinned} requirement(s) not pinned with == — use a lock (uv/poetry/pip-tools) with hashes`);
  if (!/--hash=/.test(text) && text.trim()) report.add('INFO', 'deps:pypi', file, null, 'No --hash pins; pip --require-hashes blocks swapped files');
}

function pyProject(file) {
  seenEco.add('pypi');
  const text = readText(file) || '';
  scanFile(file, report);
  // PEP 621 / PEP 735 arrays, single- or multi-line: dependencies = ["a==1", "b>=2"], optional groups too.
  const headers = [...text.matchAll(/^\[([^\]\n]+)\]\s*$/gm)].map(h => ({ at: h.index, name: h[1].trim() }));
  const sectionAt = i => (headers.filter(h => h.at < i).pop() || { name: '' }).name;
  for (const arr of text.matchAll(/^\s*([\w.-]+)\s*=\s*\[([\s\S]{0,20000}?)\]\s*(#[^\n]*)?$/gm)) {
    const sec = sectionAt(arr.index);
    const isDeps = /dependencies|requires/.test(arr[1]) || /^(project\.optional-dependencies|dependency-groups|tool\.uv)$/.test(sec);
    if (!isDeps) continue;
    for (const q of arr[2].matchAll(/["']([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===?|~=|>=|<=|!=|>|<)?\s*([0-9][^"';,\s]*)?[^"']*["']/g)) {
      const line = lineOf(text, arr.index + q.index);
      if (/@\s*(git\+|https?:|file:)/.test(q[0])) report.add('MEDIUM', 'deps:pypi', file, line, `${q[1]} from a VCS/URL source`, q[0]);
      checkName('pypi', q[1], q[3]?.startsWith('==') ? q[4] : null, file, line);
    }
  }
  const poetry = text.match(/\[tool\.poetry\.(group\.[\w-]+\.)?(dev-)?dependencies\]([\s\S]*?)(\n\[|$)/g) || [];
  for (const block of poetry) {
    for (const mm of block.matchAll(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$/gm)) {
      if (mm[1] === 'python') continue;
      if (/git\s*=|url\s*=|path\s*=/.test(mm[2])) report.add('MEDIUM', 'deps:pypi', file, lineOf(text, text.indexOf(mm[0])), `${mm[1]} from git/URL/path source`, mm[0]);
      checkName('pypi', mm[1], (mm[2].match(/^"=?=?(\d[^"]*)"/) || [])[1], file, lineOf(text, text.indexOf(mm[0])));
    }
  }
  if (/\[\[tool\.(uv\.index|poetry\.source)\]\]/.test(text)) report.add('INFO', 'deps:pypi', file, null, 'Extra package index configured — make sure internal names cannot be resolved from public PyPI');
}

function pyLock(file) {
  seenEco.add('pypi');
  const text = readText(file, 30 * 1024 * 1024) || '';
  if (path.basename(file) === 'Pipfile.lock') {
    const j = readJson(file);
    for (const sec of ['default', 'develop']) for (const [n, v] of Object.entries(j?.[sec] || {})) checkName('pypi', n, String(v?.version || '').replace(/^==/, '') || null, file, null);
    return;
  }
  for (const m of text.matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g)) {
    checkName('pypi', m[1], m[2], file, lineOf(text, m.index));
  }
}

function sitePackages(dir) {
  seenEco.add('pypi');
  let entries = [];
  try { entries = fs.readdirSync(dir); } catch { return; }
  let pth = 0;
  for (const e of entries) {
    const full = path.join(dir, e);
    if (e.endsWith('.pth')) {
      pth++;
      const v = judgePth(e, readText(full) || '');
      if (v && v.sev !== 'INFO') report.add(v.sev, 'python-startup', full, v.line, v.msg, v.evidence);
    } else if (/^(site|user)customize\.py$/.test(e)) {
      scanFile(full, report);
    } else {
      const m = e.match(/^(.+?)-(\d[^-]*)\.(dist-info|egg-info)$/);
      if (m) {
        const kb = knownBad('pypi', m[1], m[2]);
        if (kb?.exact) report.add('HIGH', 'deps:pypi', full, null, `INSTALLED known-malicious ${m[1]} ${m[2]}: ${kb.note}. Treat this machine as compromised (see incident-response.md)`);
        const squat = typosquatOf('pypi', m[1]);
        if (squat) report.add('MEDIUM', 'deps:pypi', full, null, `Installed "${m[1]}" is one letter away from "${squat}" — possible typosquat`);
      }
    }
  }
  report.add('INFO', 'deps:pypi', dir, null, `Virtualenv checked: ${pth} .pth file(s)`);
}

function findSitePackages(venv) {
  const out = [];
  const win = path.join(venv, 'Lib', 'site-packages');
  if (isDir(win)) out.push(win);
  const lib = path.join(venv, 'lib');
  let names = [];
  try { names = isDir(lib) ? fs.readdirSync(lib) : []; } catch { /* unreadable */ }
  for (const d of names) {
    const sp = path.join(lib, d, 'site-packages');
    if (/^python/.test(d) && isDir(sp)) out.push(sp);
  }
  return out;
}

// ---------- PHP Composer ----------
function composerManifest(file) {
  seenEco.add('composer');
  scanFile(file, report); // plugin type, event scripts
  const c = readJson(file);
  if (!c || typeof c !== 'object') return;
  const ap = c.config?.['allow-plugins'];
  if (ap === true) report.add('HIGH', 'deps:composer', file, null, 'allow-plugins: true lets EVERY dependency run a Composer plugin at install (intercom-php 2026 attack path) — use an explicit allow-list');
  else if (ap && typeof ap === 'object') {
    for (const [k, v] of Object.entries(ap)) if (v === true && /\*/.test(k)) report.add('MEDIUM', 'deps:composer', file, null, `allow-plugins wildcard "${k}"`);
  }
  const repos = Array.isArray(c.repositories) ? c.repositories : Object.values(c.repositories || {});
  for (const r of repos) {
    if (!r || typeof r !== 'object') continue;
    if (r.packagist === false || r['packagist.org'] === false) continue;
    if (['vcs', 'git', 'github', 'path', 'artifact', 'package'].includes(r.type)) {
      report.add(r.type === 'package' ? 'MEDIUM' : 'LOW', 'deps:composer', file, null, `Composer "${r.type}" repository${r.url ? ` ${r.url}` : ''} — packages from here skip Packagist malware checks`);
    }
    if (r.url && /^http:\/\//.test(r.url)) report.add('MEDIUM', 'deps:composer', file, null, `Repository over plain http: ${r.url}`);
  }
  if (c['minimum-stability'] === 'dev' && !c['prefer-stable']) report.add('LOW', 'deps:composer', file, null, 'minimum-stability "dev" without prefer-stable pulls development branches');
  for (const sec of ['require', 'require-dev']) for (const [n, v] of Object.entries(c[sec] || {})) {
    if (/^(dev-|\*$)/.test(String(v))) report.add('LOW', 'deps:composer', file, null, `${n}: "${v}" is not a fixed release`);
    if (n.includes('/')) checkName('composer', n, /^v?\d+(\.\d+)*$/.test(String(v)) ? String(v).replace(/^v/, '') : null, file, null);
  }
  if (!exists(path.join(path.dirname(file), 'composer.lock')) && Object.keys(c.require || {}).length > 1) {
    report.add('LOW', 'deps:composer', file, null, 'No composer.lock — commit it so deploys install exactly what you reviewed');
  }
  report.note('Composer: make sure you run Composer 2.10+ (default-on Packagist malware protection) and `composer audit`.');
}

function composerLock(file) {
  seenEco.add('composer');
  const lock = readJson(file);
  if (!lock) return;
  const manifest = readJson(path.join(path.dirname(file), 'composer.json')) || {};
  const allow = manifest.config?.['allow-plugins'];
  for (const p of [...(lock.packages || []), ...(lock['packages-dev'] || [])]) {
    checkName('composer', p.name, p.version, file, null);
    if (p.type === 'composer-plugin') {
      const allowed = allow === true || (allow && allow[p.name] === true);
      report.add(allowed ? 'MEDIUM' : 'INFO', 'deps:composer', file, null, `${p.name} ${p.version} is a Composer plugin${allowed ? ' and is ALLOWED to run code at install' : ' (blocked unless allow-plugins permits it)'}`);
    }
    const url = p.dist?.url || p.source?.url || '';
    if (url && !/^https:\/\/(api\.github\.com|github\.com|codeload\.github\.com|gitlab\.com|bitbucket\.org|repo\.packagist\.org)\//.test(url)) {
      report.add('INFO', 'deps:composer', file, null, `${p.name} downloads from ${url.replace(/^(https?:\/\/[^/]+).*/, '$1')}`);
    }
  }
}

// ---------- Ruby ----------
function gemfile(file) {
  seenEco.add('rubygems');
  const text = readText(file) || '';
  const isLock = path.basename(file) === 'Gemfile.lock';
  if (isLock) {
    for (const m of text.matchAll(/^\s+remote:\s+(\S+)/gm)) {
      if (!/^https:\/\/(rubygems\.org|gems\.rubygems\.org)\/?$/.test(m[1]) && !/^(\.|\/)/.test(m[1])) report.add('LOW', 'deps:rubygems', file, lineOf(text, m.index), `Gems from non-rubygems.org source: ${m[1]}`);
    }
    for (const m of text.matchAll(/^ {4}([a-z0-9][\w.-]*) \(([^)]+)\)$/gim)) {
      checkName('rubygems', m[1], m[2], file, lineOf(text, m.index));
      if (/^knot-/.test(m[1])) report.add('MEDIUM', 'deps:rubygems', file, lineOf(text, m.index), `"${m[1]}" matches the knot- prefix used by the 2026 BufferZoneCorp malicious gems — verify it`);
    }
  } else {
    for (const m of text.matchAll(/^\s*gem\s+['"]([^'"]+)['"][^\n]*(git:|github:|path:)/gm)) report.add('LOW', 'deps:rubygems', file, lineOf(text, m.index), `${m[1]} from git/path source`, m[0]);
    for (const m of text.matchAll(/^\s*source\s+['"]([^'"]+)['"]/gm)) if (!/rubygems\.org/.test(m[1])) report.add('LOW', 'deps:rubygems', file, lineOf(text, m.index), `Gem source ${m[1]}`);
  }
}

// ---------- Go ----------
function gomod(file) {
  seenEco.add('go');
  const text = readText(file) || '';
  for (const m of text.matchAll(/^\s*(replace\s+)?(\S+)(\s+\S+)?\s+=>\s+(\S+)(\s+\S+)?/gm)) {
    const local = /^(\.|\/|[A-Za-z]:\\)/.test(m[4]);
    report.add(local ? 'INFO' : 'MEDIUM', 'deps:go', file, lineOf(text, m.index), local ? `replace ${m[2]} => local path` : `replace ${m[2]} => ${m[4]} (different source than the real module — verify the fork)`);
  }
  if (/^require/m.test(text) && !exists(path.join(path.dirname(file), 'go.sum'))) report.add('LOW', 'deps:go', file, null, 'No go.sum — module checksums are not being verified');
  report.note('Go: keep GOSUMDB on, avoid GOFLAGS=-insecure, and run `govulncheck ./...`.');
}

// ---------- Rust ----------
function cargo(file) {
  seenEco.add('cargo');
  const text = readText(file, 30 * 1024 * 1024) || '';
  if (path.basename(file) === 'Cargo.lock') {
    for (const m of text.matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"(\s*\nsource\s*=\s*"([^"]+)")?/g)) {
      checkName('cargo', m[1], m[2], file, lineOf(text, m.index));
      if (m[4] && !/^registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index|^sparse\+https:\/\/index\.crates\.io\//.test(m[4])) {
        report.add('LOW', 'deps:cargo', file, lineOf(text, m.index), `${m[1]} from ${m[4].slice(0, 80)}`);
      }
    }
  } else {
    for (const m of text.matchAll(/^([\w-]+)\s*=\s*\{[^}\n]*\b(git|path)\s*=\s*"([^"]+)"/gm)) report.add('LOW', 'deps:cargo', file, lineOf(text, m.index), `${m[1]} from ${m[2]} ${m[3]}`);
    if (/^\[patch\./m.test(text)) report.add('MEDIUM', 'deps:cargo', file, lineOf(text, text.search(/^\[patch\./m)), '[patch] overrides a crate with another source — verify it');
    for (const m of text.matchAll(/^([\w-]+)\s*=/gm)) if (typosquatOf('cargo', m[1])) checkName('cargo', m[1], null, file, lineOf(text, m.index));
  }
}

// ---------- Java ----------
function jvm(file) {
  seenEco.add('jvm');
  const text = readText(file) || '';
  const base = path.basename(file);
  if (base === 'gradle-wrapper.properties') {
    const m = text.match(/distributionUrl\s*=\s*(\S+)/);
    if (m && !/^https\\?:\/\/services\.gradle\.org\//.test(m[1])) report.add('HIGH', 'deps:jvm', file, lineOf(text, m.index), 'Gradle wrapper downloads Gradle from an unofficial URL', m[1]);
    return;
  }
  for (const m of text.matchAll(/(url\s*[=(]?\s*['"]|<url>)\s*(http:\/\/[^'"<\s]+)/g)) report.add('MEDIUM', 'deps:jvm', file, lineOf(text, m.index), 'Repository over plain http (can be tampered with in transit)', m[2]);
  for (const m of text.matchAll(/<version>\s*(LATEST|RELEASE|\[[^<]*)\s*<\/version>|['"][\w.-]+:[\w.-]+:([\w.]*\+|latest\.\w+)['"]/g)) report.add('LOW', 'deps:jvm', file, lineOf(text, m.index), 'Dynamic dependency version — use exact versions and dependency locking', m[0]);
  if (/mavenLocal\(\)/.test(text)) report.add('LOW', 'deps:jvm', file, lineOf(text, text.indexOf('mavenLocal()')), 'mavenLocal() lets anything in ~/.m2 override real dependencies');
}

// ---------- .NET ----------
function dotnet(file) {
  seenEco.add('nuget');
  const text = readText(file) || '';
  const base = path.basename(file).toLowerCase();
  if (base === 'nuget.config') {
    for (const m of text.matchAll(/<add\s+key="([^"]+)"\s+value="(https?:\/\/[^"]+)"/gi)) {
      if (/^http:/.test(m[2])) report.add('MEDIUM', 'deps:nuget', file, lineOf(text, m.index), `NuGet source over plain http: ${m[2]}`);
      else if (!/api\.nuget\.org/.test(m[2])) report.add('INFO', 'deps:nuget', file, lineOf(text, m.index), `Extra NuGet source "${m[1]}" — use <packageSourceMapping> to stop dependency confusion`);
    }
    return;
  }
  for (const m of text.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]*\*[^"]*)"/g)) report.add('LOW', 'deps:nuget', file, lineOf(text, m.index), `${m[1]} uses a floating version "${m[2]}"`);
  if (/<PackageReference/.test(text) && !exists(path.join(path.dirname(file), 'packages.lock.json'))) report.add('INFO', 'deps:nuget', file, null, 'No packages.lock.json — set RestorePackagesWithLockFile=true');
}

// ---------- Docker ----------
function dockerfile(file) {
  seenEco.add('docker');
  const text = readText(file) || '';
  let hasUser = false;
  const stages = new Set();
  // Join "\"-continued lines so a multi-line RUN is checked as one command.
  const logical = [];
  text.split(/\r?\n/).forEach((l, i) => {
    const prev = logical[logical.length - 1];
    if (prev && prev.cont) { prev.text += ' ' + l.trim().replace(/\\$/, ''); prev.cont = /\\\s*$/.test(l); }
    else logical.push({ text: l.trim().replace(/\\$/, ''), line: i + 1, cont: /\\\s*$/.test(l) });
  });
  logical.forEach(({ text: line, line: ln }) => {
    const i = ln - 1;
    const from = line.match(/^FROM\s+(--platform=\S+\s+)?(\S+)(\s+AS\s+(\S+))?/i);
    if (from) {
      const img = from[2];
      const last = img.split('/').pop();
      if (!/^(scratch$|\$)/.test(img) && !stages.has(img.toLowerCase()) && !/@sha256:/.test(img) && (!last.includes(':') || /:latest$/.test(last))) {
        report.add('LOW', 'deps:docker', file, i + 1, `Base image "${img}" is not pinned (no tag or :latest) — pin a version or @sha256 digest`);
      }
      if (from[4]) stages.add(from[4].toLowerCase());
    }
    if (/^USER\s+/i.test(line)) hasUser = true;
    if (/^ADD\s+https?:/i.test(line)) report.add('MEDIUM', 'deps:docker', file, i + 1, 'ADD from a URL — downloaded content is not verified', line);
    if (/^(ENV|ARG)\s+\w*(TOKEN|SECRET|PASSWORD|API_?KEY|ACCESS_?KEY)\w*[\s=]+\S{6,}/i.test(line)) {
      report.add('MEDIUM', 'deps:docker', file, i + 1, `Secret baked into the image layer (${redact(line.split(/[\s=]+/).pop())}) — use BuildKit secrets`);
    }
    if (/^RUN\b/i.test(line)) {
      for (const h of matchRules(COMMAND_RULES, line)) report.add(h.sev === 'HIGH' ? 'MEDIUM' : h.sev, `deps:docker`, file, i + 1, `RUN: ${h.msg}`, line);
    }
  });
  if (!hasUser) report.add('LOW', 'deps:docker', file, null, 'No USER instruction — the container runs as root');
}

// ---------- GitHub Actions ----------
// Any ${{ ... }} expression that mentions attacker-controlled event text (also inside toJSON(), ||, format()).
const UNTRUSTED_EXPR = /\$\{\{[^}\n]{0,200}?(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|head_commit\.(message|author\.(name|email))|commits\b[^}\n]{0,40}\.(message|author)|pages\b[^}\n]{0,40}\.page_name|workflow_run\.(head_branch|head_commit\.message|display_title))|github\.head_ref)\b[^}\n]{0,200}\}\}/;
const AI_ACTIONS = /uses:\s*['"]?(anthropics\/claude-code-action|anthropics\/claude-code-base-action|openai\/codex-action|cline\/|google-github-actions\/run-gemini-cli|github\/copilot|paul-gauthier\/aider|aider-ai\/|coderabbitai\/)/i;

function workflow(file) {
  seenEco.add('github-actions');
  const text = readText(file) || '';
  const lines = text.split(/\r?\n/);
  // `on:` may be quoted ("on":) or written as `true:` by some YAML emitters.
  const onLine = text.search(/^["']?(on|true)["']?\s*:/m);
  const triggers = onLine < 0 ? '' : (text.slice(onLine).match(/^[^\n]*\n?(?:[ \t-][^\n]*\n?|\n)*/) || [''])[0];
  const prTarget = /pull_request_target|workflow_run/.test(triggers);
  const untrustedTrigger = /issues|issue_comment|pull_request_target|pull_request_review|discussion/.test(triggers);
  let runIndent = -1;

  lines.forEach((l, i) => {
    const indent = l.search(/\S/);
    if (runIndent >= 0 && indent >= 0 && indent <= runIndent) runIndent = -1;
    // run: (shell) and actions/github-script's script: (JavaScript) both execute inline text.
    const runStart = l.match(/^(\s*)(-\s+)?(run|script):\s*(.*)$/);
    if (runStart) runIndent = runStart[1].length + (runStart[2] ? runStart[2].length : 0);
    const inRun = runStart || runIndent >= 0;

    const uses = l.match(/uses:\s*['"]?([^@\s'"]+)@([^\s'"#]+)/);
    if (uses && !uses[1].startsWith('./') && !uses[1].startsWith('docker://')) {
      if (!/^[0-9a-f]{40}$/.test(uses[2])) {
        const firstParty = /^(actions|github)\//.test(uses[1]);
        report.add(firstParty ? 'LOW' : 'MEDIUM', 'ci:unpinned-action', file, i + 1, `${uses[1]}@${uses[2]} is pinned to a movable tag — attackers re-pointed tags in 2026 (TeamPCP, Checkmarx, Trivy). Pin the full commit SHA`);
      }
    }
    if (UNTRUSTED_EXPR.test(l)) {
      report.add(inRun ? 'HIGH' : 'MEDIUM', 'ci:untrusted-input', file, i + 1,
        inRun ? 'Untrusted issue/PR text is pasted straight into an inline script (script injection) — pass it via env: instead'
          : 'Untrusted issue/PR text is passed to a step — if that step is an AI agent this is a prompt-injection path (Clinejection 2026)', l.trim());
    }
    if (inRun) for (const h of matchRules(COMMAND_RULES, l)) report.add(h.sev === 'HIGH' ? 'MEDIUM' : h.sev, 'ci:run', file, i + 1, h.msg, l.trim());
    if (/secrets:\s*inherit/.test(l)) report.add('LOW', 'ci:secrets', file, i + 1, 'secrets: inherit passes every secret to the called workflow');
    if (/permissions:\s*write-all/.test(l)) report.add('MEDIUM', 'ci:permissions', file, i + 1, 'permissions: write-all gives the token full write access');
  });

  if (prTarget) {
    const checksOutHead = /ref:\s*\$\{\{\s*github\.event\.(pull_request\.head\.(sha|ref)|workflow_run\.head_(sha|branch))|github\.head_ref|refs\/pull\/|pull_request\.merge_commit_sha|repository:\s*\$\{\{\s*github\.event\.pull_request\.head\.repo/.test(text);
    report.add(checksOutHead ? 'HIGH' : 'MEDIUM', 'ci:pr-target', file, lineOf(text, text.search(/pull_request_target|workflow_run/)),
      checksOutHead ? 'pull_request_target/workflow_run checks out PR code and runs it with repository secrets ("pwn request")'
        : 'pull_request_target/workflow_run runs with secrets on events from forks — never check out or run PR code here');
  }
  if (AI_ACTIONS.test(text) && untrustedTrigger) {
    report.add('MEDIUM', 'ci:ai-agent', file, lineOf(text, text.search(AI_ACTIONS)), 'AI agent action triggered by issues/comments/PRs that anyone can write — restrict to trusted actors and give it no publish/cloud secrets');
  }
  if (!/^permissions:/m.test(text)) report.add('LOW', 'ci:permissions', file, null, 'No top-level permissions: block — set `permissions: contents: read` and widen per job');
}

// ---------- dispatch ----------
const VENV_NAMES = new Set(['.venv', 'venv', 'env', '.env']);
const handlers = [
  [b => b === 'package.json', npmManifest],
  [b => b === 'package-lock.json' || b === 'npm-shrinkwrap.json', npmLock],
  [b => b === 'yarn.lock' || b === 'pnpm-lock.yaml', yarnOrPnpmLock],
  [b => b === 'bun.lock', bunLock],
  [b => /^requirements.*\.(txt|in)$/i.test(b) || b === 'constraints.txt', pyRequirements],
  [b => b === 'pyproject.toml', pyProject],
  [b => b === 'poetry.lock' || b === 'uv.lock' || b === 'Pipfile.lock' || b === 'pdm.lock', pyLock],
  [b => b === 'setup.py', f => { seenEco.add('pypi'); scanFile(f, report); }],
  [b => b === 'composer.json', composerManifest],
  [b => b === 'composer.lock', composerLock],
  [b => b === 'Gemfile' || b === 'Gemfile.lock' || b.endsWith('.gemspec'), gemfile],
  [b => b === 'go.mod', gomod],
  [b => b === 'Cargo.toml' || b === 'Cargo.lock', cargo],
  [b => b === 'pom.xml' || /^build\.gradle(\.kts)?$/.test(b) || /^settings\.gradle(\.kts)?$/.test(b) || b === 'gradle-wrapper.properties', jvm],
  [b => /\.(cs|fs|vb)proj$/i.test(b) || b.toLowerCase() === 'nuget.config' || b === 'Directory.Packages.props', dotnet],
  [b => /^Dockerfile(\..+)?$|\.Dockerfile$|^Containerfile$/i.test(b), dockerfile],
];

let files = 0;
const { skipPaths, note: selfNote } = selfSkip(root);
if (selfNote) report.note(selfNote);
for (const file of walk(root, { skipPaths })) {
  const b = path.basename(file);
  const d = path.dirname(file);
  if (/[\\/]\.github[\\/]workflows$/.test(d) && /\.ya?ml$/.test(b)) { workflow(file); files++; continue; }
  if (/[\\/]\.vscode$/.test(d) && (b === 'tasks.json' || b === 'extensions.json')) {
    if (b === 'extensions.json') {
      const recs = readJson(file)?.recommendations || [];
      if (recs.length) report.add('INFO', 'editor-extension', file, null, `Workspace recommends ${recs.length} VS Code extension(s): ${recs.join(', ')} — install only ones you know`);
    } else scanFile(file, report);
    files++;
    continue;
  }
  const h = handlers.find(([test]) => test(b));
  if (h) { h[1](file); files++; }
}

// Python virtualenvs in the project (skipped by the walk).
let topLevel = [];
try { topLevel = fs.readdirSync(root); } catch { /* unreadable */ }
for (const name of topLevel) {
  const full = path.join(root, name);
  if (!isDir(full)) continue;
  if (VENV_NAMES.has(name) || exists(path.join(full, 'pyvenv.cfg'))) for (const sp of findSitePackages(full)) sitePackages(sp);
}

report.meta.ecosystems = [...seenEco];
report.meta.manifests = files;
report.note(`Ecosystems found: ${[...seenEco].join(', ') || 'none'}; ${files} manifest/lock/pipeline files checked.`);
report.note(`Known-bad list is a small offline sample (updated ${KB.updated || 'unknown'}). For full advisory coverage, run the ecosystem audit tool with the user's consent: npm audit, pip-audit, composer audit, bundle audit, govulncheck, cargo audit, dotnet list package --vulnerable, or osv-scanner.`);
report.finish(args.json);
