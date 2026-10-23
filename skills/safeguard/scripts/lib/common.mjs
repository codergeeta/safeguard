// Shared helpers for safeguard scanners. Read-only, offline, no dependencies.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

// Folders that are dependencies, caches, or VCS internals. Virtualenvs with any name are
// skipped by their pyvenv.cfg marker instead (see walk), so `env/` or `build/` folders
// holding real config and code are still scanned.
const DEFAULT_SKIP_DIRS = new Set([
  '.git', '.hg', '.svn', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__', '.tox',
  '.next', '.nuxt', '.cache', '.parcel-cache', '.turbo', 'coverage', '.gradle', '.idea', '.mypy_cache', '.pytest_cache',
]);

export const MAX_TEXT_BYTES = 2 * 1024 * 1024;

export function parseArgs(argv, { flags = [], options = [] } = {}, usage = '') {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      if (options.includes(key) && i + 1 < argv.length) out[key] = argv[++i];
      else if (flags.includes(key)) out[key] = true;
      else {
        console.error(`Unknown or incomplete option: ${a}`);
        if (usage) console.error(usage);
        process.exit(1);
      }
    } else out._.push(a);
  }
  return out;
}

export function exists(p) {
  try { fs.accessSync(p); return true; } catch { return false; }
}

export function isDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}

// Returns file text, or null for missing, oversized, or binary files.
export function readText(file, maxBytes = MAX_TEXT_BYTES) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > maxBytes) return null;
    const buf = fs.readFileSync(file);
    const probe = buf.subarray(0, 8192);
    if (probe.includes(0)) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

// For files over the size limit: the first and last `part` bytes, where droppers and
// appended payloads usually sit. Returns { text, size } or null for binary/unreadable.
export function readHeadTail(file, part = 1024 * 1024) {
  let fd;
  try {
    const size = fs.statSync(file).size;
    fd = fs.openSync(file, 'r');
    const head = Buffer.alloc(Math.min(part, size));
    fs.readSync(fd, head, 0, head.length, 0);
    if (head.subarray(0, 8192).includes(0)) return null;
    const tail = Buffer.alloc(Math.min(part, Math.max(0, size - part)));
    if (tail.length) fs.readSync(fd, tail, 0, tail.length, size - tail.length);
    return { text: `${head.toString('utf8')}\n${tail.toString('utf8')}`, size };
  } catch {
    return null;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* ignore */ }
  }
}

export function fileSize(file) {
  try { return fs.statSync(file).size; } catch { return 0; }
}

export function readJson(file) {
  const text = readText(file, 20 * 1024 * 1024);
  if (text == null) return null;
  try {
    return JSON.parse(text.replace(/^﻿/, ''));
  } catch {
    return undefined; // present but unparseable
  }
}

// Depth-first walk yielding file paths. Never follows symlinks. Pass `stats` ({}) to learn
// whether the file limit cut the walk short (stats.truncated) and how many dirs were unreadable.
export function* walk(root, { skipDirs = DEFAULT_SKIP_DIRS, maxFiles = 50000, skipPaths = [], skipVenvs = true, stats = {} } = {}) {
  let count = 0;
  const skipSet = new Set(skipPaths.map(samePath));
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { stats.unreadable = (stats.unreadable || 0) + 1; continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (skipDirs.has(e.name) || skipSet.has(samePath(full))) continue;
        if (skipVenvs && exists(path.join(full, 'pyvenv.cfg'))) continue;
        stack.push(full);
      } else if (e.isFile()) {
        if (++count > maxFiles) { stats.truncated = true; return; }
        yield full;
      }
    }
  }
}

// True when `child` is `parent` or inside it.
export function isInside(child, parent) {
  const rel = path.relative(samePath(parent), samePath(child));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export { DEFAULT_SKIP_DIRS };

// Canonical form for comparing paths (case-insensitive on Windows, symlinks resolved).
export function samePath(p) {
  let r = path.resolve(p);
  try { r = fs.realpathSync.native(r); } catch { /* keep resolved */ }
  return process.platform === 'win32' ? r.toLowerCase() : r;
}

// This skill's own folder. Its rule files contain every pattern it hunts for, so
// scans of other folders skip it by exact location (never by name, which attackers could copy).
export const SKILL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// Files byte-identical to this skill's own files (e.g. another checkout of safeguard) are
// skipped: identical content cannot hide anything new. Matching is by SHA-256, never by name.
let ownFiles = null;
export function isOwnFile(file) {
  if (!ownFiles) {
    ownFiles = new Map();
    for (const f of walk(SKILL_ROOT, { skipDirs: new Set(), skipVenvs: false })) {
      try {
        const buf = fs.readFileSync(f);
        const set = ownFiles.get(buf.length) || new Set();
        set.add(crypto.createHash('sha256').update(buf).digest('hex'));
        ownFiles.set(buf.length, set);
      } catch { /* unreadable */ }
    }
  }
  try {
    const size = fs.statSync(file).size;
    const set = ownFiles.get(size);
    return !!set && set.has(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'));
  } catch {
    return false;
  }
}

// Show only the first 4 characters of a secret.
export function redact(value) {
  if (!value) return '';
  const v = String(value);
  return v.length <= 4 ? '****' : `${v.slice(0, 4)}…[redacted ${v.length} chars]`;
}

// Line-start offsets for the most recent text, so repeated lookups on one file stay cheap.
let lastText = null, lastStarts = null;
function lineStarts(text) {
  if (text !== lastText) {
    lastStarts = [0];
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) lastStarts.push(i + 1);
    lastText = text;
  }
  return lastStarts;
}

// 1-based line number of a character offset.
export function lineOf(text, index) {
  const s = lineStarts(text);
  let lo = 0, hi = s.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (s[mid] <= index) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

// Text of a 1-based line (a window around `index` for very long lines).
export function lineText(text, line, index) {
  const s = lineStarts(text);
  const start = s[line - 1] ?? 0;
  const end = (s[line] ?? text.length + 1) - 1;
  if (end - start > 400 && index != null) return text.slice(Math.max(start, index - 60), Math.min(end, index + 200)).trim();
  return text.slice(start, Math.min(end, start + 400)).replace(/\r$/, '').trim();
}

export function clip(s, n = 160) {
  s = String(s).replace(/\s+/g, ' ').trim();
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

export class Report {
  constructor(title, root) {
    this.title = title;
    this.root = root;
    this.findings = [];
    this.notes = [];
    this.meta = {};
    this.seen = new Set();
  }

  // Counters and facts for the visual report (files scanned, ecosystems found, ...).
  bump(key, n = 1) { this.meta[key] = (this.meta[key] || 0) + n; }

  add(severity, category, file, line, message, evidence) {
    const rel = file ? (this.root ? path.relative(this.root, file) || file : file) : '';
    // Evidence is part of the key: two different hooks in one settings file are two findings.
    const key = `${severity}|${category}|${rel}|${line}|${message}|${evidence || ''}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.findings.push({ severity, category, file: rel, line: line || null, message, evidence: evidence ? clip(evidence) : undefined });
  }

  note(msg) { this.notes.push(msg); }

  counts() {
    const c = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
    for (const f of this.findings) c[f.severity]++;
    return c;
  }

  print(json = false) {
    const order = s => SEVERITIES.indexOf(s);
    this.findings.sort((a, b) => order(a.severity) - order(b.severity) || a.file.localeCompare(b.file) || (a.line || 0) - (b.line || 0));
    if (json) {
      console.log(JSON.stringify({ title: this.title, root: this.root, counts: this.counts(), meta: this.meta, findings: this.findings, notes: this.notes }, null, 2));
    } else {
      const c = this.counts();
      console.log(`== ${this.title} ==`);
      if (this.root) console.log(`Scanned: ${this.root}`);
      console.log(`Findings: ${c.HIGH} HIGH, ${c.MEDIUM} MEDIUM, ${c.LOW} LOW, ${c.INFO} INFO\n`);
      for (const sev of SEVERITIES) {
        const group = this.findings.filter(f => f.severity === sev);
        if (!group.length) continue;
        console.log(`-- ${sev} --`);
        for (const f of group) {
          const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '';
          console.log(`[${f.category}] ${loc}${loc ? ' — ' : ''}${f.message}`);
          if (f.evidence) console.log(`    > ${f.evidence}`);
        }
        console.log('');
      }
      if (!this.findings.length) console.log('No findings. (A clean scan is not a guarantee.)\n');
      for (const n of this.notes) console.log(`note: ${n}`);
    }
    return this.counts().HIGH > 0 ? 2 : 0;
  }

  // Print, then let Node exit on its own so piped --json output is never cut off.
  finish(json = false) {
    process.exitCode = this.print(json);
  }
}

export function homeDir() {
  return process.env.USERPROFILE || process.env.HOME || '';
}
