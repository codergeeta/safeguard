// Minimal TOML reader for agent config files (Codex config.toml): tables, dotted/quoted
// table names, strings, numbers, booleans, and single- or multi-line arrays of those,
// plus inline tables of strings. Not a full TOML implementation; unknown syntax is skipped.

export function parseToml(text) {
  const root = {};
  let cur = root;
  const lines = String(text).replace(/^﻿/, '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = stripComment(lines[i]).trim();
    if (!line) continue;
    const table = line.match(/^\[\[?\s*([^\]]+?)\s*\]\]?$/);
    if (table) {
      cur = root;
      for (const k of splitKey(table[1])) cur = cur[k] = cur[k] && typeof cur[k] === 'object' ? cur[k] : {};
      continue;
    }
    const kv = line.match(/^((?:"[^"]*"|'[^']*'|[\w.-]+)(?:\s*\.\s*(?:"[^"]*"|'[^']*'|[\w-]+))*)\s*=\s*(.*)$/);
    if (!kv) continue;
    let raw = kv[2];
    // Multi-line arrays: keep reading until brackets balance.
    while (raw.startsWith('[') && depth(raw) > 0 && i + 1 < lines.length) raw += ' ' + stripComment(lines[++i]).trim();
    const keys = splitKey(kv[1]);
    let target = cur;
    for (const k of keys.slice(0, -1)) target = target[k] = target[k] && typeof target[k] === 'object' ? target[k] : {};
    target[keys[keys.length - 1]] = value(raw.trim());
  }
  return root;
}

function stripComment(line) {
  let q = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '\\' && q === '"') i++; else if (c === q) q = null; }
    else if (c === '"' || c === "'") q = c;
    else if (c === '#') return line.slice(0, i);
  }
  return line;
}

function depth(s) {
  let d = 0, q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\' && q === '"') i++; else if (c === q) q = null; }
    else if (c === '"' || c === "'") q = c;
    else if (c === '[') d++;
    else if (c === ']') d--;
  }
  return d;
}

function splitKey(k) {
  return (k.match(/"[^"]*"|'[^']*'|[^.\s]+/g) || []).map(p => p.replace(/^["']|["']$/g, ''));
}

function value(v) {
  if (/^"""/.test(v) || /^'''/.test(v)) return v.slice(3, v.lastIndexOf(v.slice(0, 3)));
  if (v.startsWith('"')) return JSON.parse(v.slice(0, closing(v, '"') + 1).replace(/\\'/g, "'"));
  if (v.startsWith("'")) return v.slice(1, v.indexOf("'", 1));
  if (v === 'true' || v === 'false') return v === 'true';
  if (/^[+-]?\d[\d_]*(\.\d+)?$/.test(v)) return Number(v.replace(/_/g, ''));
  if (v.startsWith('[')) return splitTop(v.slice(1, v.lastIndexOf(']'))).map(value);
  if (v.startsWith('{')) {
    const o = {};
    for (const part of splitTop(v.slice(1, v.lastIndexOf('}')))) {
      const m = part.match(/^\s*("[^"]*"|'[^']*'|[\w.-]+)\s*=\s*(.*)$/);
      if (m) o[splitKey(m[1]).join('.')] = value(m[2].trim());
    }
    return o;
  }
  return v;
}

function closing(s, q) {
  for (let i = 1; i < s.length; i++) { if (s[i] === '\\') i++; else if (s[i] === q) return i; }
  return s.length - 1;
}

// Split on top-level commas (not inside strings, arrays, or inline tables).
function splitTop(s) {
  const out = [];
  let d = 0, q = null, start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\' && q === '"') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '[' || c === '{') d++;
    else if (c === ']' || c === '}') d--;
    else if (c === ',' && d === 0) { out.push(s.slice(start, i)); start = i + 1; }
  }
  out.push(s.slice(start));
  return out.map(x => x.trim()).filter(Boolean);
}
