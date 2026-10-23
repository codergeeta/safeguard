// Renders self-contained, offline HTML: the audit dashboard and the scam explainer card.
// Every value from scanned files is untrusted, so everything is escaped and the page
// carries a CSP that blocks all network access.
// Colors follow a validated status palette (critical / serious / warning / good); severity
// is always shown with an icon and a label, never by color alone.
import { explain, SCAM_TYPES } from './explain.mjs';

export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const CSP = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`;

const SEV = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_LABEL = { HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info' };
const SEV_ICON = { HIGH: '!', MEDIUM: '▲', LOW: '●', INFO: 'i' };

const TOKENS = `
:root{color-scheme:light;--plane:#f4f4f1;--surface:#fcfcfb;--raised:#ffffff;--ink:#0b0b0b;--ink2:#52514e;--muted:#6f6d68;--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);
--crit:#d03b3b;--serious:#ec835a;--warn:#fab219;--good:#0ca30c;--good-text:#006300;--info:#898781;--s1:#2a78d6;
--crit-bg:rgba(208,59,59,.09);--serious-bg:rgba(236,131,90,.12);--warn-bg:rgba(250,178,25,.14);--good-bg:rgba(12,163,12,.09);--info-bg:rgba(137,135,129,.12);--s1-bg:rgba(42,120,214,.09);
--shadow:0 1px 2px rgba(11,11,11,.04),0 4px 16px rgba(11,11,11,.05);--mono:ui-monospace,SFMono-Regular,Consolas,monospace;
--high:var(--crit);--med:var(--serious);--low:var(--warn);--ok:var(--good);--high-bg:var(--crit-bg);--med-bg:var(--serious-bg);--low-bg:var(--warn-bg);--ok-bg:var(--good-bg);--bg:var(--plane);--panel:var(--surface);--line:var(--grid);--accent:var(--s1)}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--plane:#0d0d0d;--surface:#1a1a19;--raised:#202020;--ink:#f0efec;--ink2:#c3c2b7;--muted:#9a988f;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--good-text:#0ca30c;--s1:#3987e5;
--crit-bg:rgba(208,59,59,.18);--serious-bg:rgba(236,131,90,.16);--warn-bg:rgba(250,178,25,.14);--good-bg:rgba(12,163,12,.16);--info-bg:rgba(137,135,129,.18);--s1-bg:rgba(57,135,229,.16);--shadow:none}}
:root[data-theme="dark"]{color-scheme:dark;--plane:#0d0d0d;--surface:#1a1a19;--raised:#202020;--ink:#f0efec;--ink2:#c3c2b7;--muted:#9a988f;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--good-text:#0ca30c;--s1:#3987e5;
--crit-bg:rgba(208,59,59,.18);--serious-bg:rgba(236,131,90,.16);--warn-bg:rgba(250,178,25,.14);--good-bg:rgba(12,163,12,.16);--info-bg:rgba(137,135,129,.18);--s1-bg:rgba(57,135,229,.16);--shadow:none}`;

const BASE_CSS = `${TOKENS}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:72px}
body{margin:0;background:var(--plane);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1120px;margin:0 auto;padding:24px 16px 72px}
h1{font-size:30px;line-height:1.15;margin:0;letter-spacing:-.01em}h2{font-size:20px;margin:0;letter-spacing:-.005em}h3{font-size:15px;margin:0}
p{margin:.4em 0}.muted{color:var(--muted)}.ink2{color:var(--ink2)}.small{font-size:13px}.mono{font-family:var(--mono);font-size:12.5px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--shadow)}
.grid{display:grid;gap:12px}.g4{grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}.g2{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}.g3{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:2px 9px 2px 3px;border-radius:999px;background:var(--info-bg);color:var(--ink);white-space:nowrap}
.chip i{display:inline-grid;place-items:center;width:17px;height:17px;border-radius:50%;font-style:normal;font-size:10px;font-weight:800;color:#fff;background:var(--info)}
.chip.HIGH{background:var(--crit-bg)}.chip.HIGH i{background:var(--crit)}.chip.MEDIUM{background:var(--serious-bg)}.chip.MEDIUM i{background:var(--serious)}
.chip.LOW{background:var(--warn-bg)}.chip.LOW i{background:var(--warn);color:#3a2a00}.chip.OK{background:var(--good-bg)}.chip.OK i{background:var(--good)}.chip.NA i{background:var(--axis)}
.chain{display:flex;align-items:stretch;gap:6px;margin:12px 0}
.step{flex:1 1 0;min-width:0;border:1px solid var(--border);border-radius:10px;padding:9px 11px;font-size:13px;background:var(--plane)}
.step.hit{border-color:var(--crit);background:var(--crit-bg);font-weight:600;box-shadow:0 0 0 2px var(--crit-bg)}
.step .n{display:block;font-size:11px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.04em;margin-bottom:2px}
.step.hit .n{color:var(--crit)}
.arrow{align-self:center;color:var(--axis);font-size:18px}
pre.ev{white-space:pre-wrap;word-break:break-all;background:var(--plane);border:1px solid var(--border);border-radius:8px;padding:9px 11px;margin:10px 0;font-family:var(--mono);font-size:12.5px}
footer{margin-top:48px;font-size:13px;color:var(--muted);border-top:1px solid var(--grid);padding-top:16px}
button,select,input{font:inherit;color:inherit}
@media (max-width:720px){.chain{flex-direction:column}.arrow{transform:rotate(90deg);line-height:1}h1{font-size:24px}}
`;

export function page(title, body, extraCss = '', script = '', bodyAttrs = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${CSP}<title>${esc(title)}</title><style>${BASE_CSS}${extraCss}</style></head><body${bodyAttrs}>${body}${script ? `<script>${script}</script>` : ''}</body></html>`;
}

const chip = (sev, text = SEV_LABEL[sev] || sev) => `<span class="chip ${sev}"><i aria-hidden="true">${SEV_ICON[sev] || (sev === 'OK' ? '✓' : '–')}</i>${esc(text)}</span>`;

function chainHtml(chain, at, hit = true, label = 'this finding') {
  if (!chain?.length) return '';
  return `<div class="chain" role="list">${chain.map((s, i) => `${i ? '<span class="arrow" aria-hidden="true">→</span>' : ''}<div role="listitem" class="step${hit && i === at ? ' hit' : ''}"><span class="n">Step ${i + 1}${hit && i === at ? ` · ${label}` : ''}</span>${esc(s)}</div>`).join('')}</div>`;
}

// ---------- scoring & analysis ----------

const WEIGHT = { HIGH: 15, MEDIUM: 4, LOW: 1, INFO: 0 };

export function score(findings) {
  // Repeats of the same issue type count less each time, so one noisy area cannot zero the score.
  const seen = {};
  let penalty = 0;
  for (const f of findings) {
    const k = `${f.severity}|${explain(f).key}`;
    seen[k] = (seen[k] || 0) + 1;
    penalty += WEIGHT[f.severity] / Math.sqrt(seen[k]);
  }
  return Math.max(0, Math.round(100 - penalty));
}

function grade(s, counts) {
  // Any HIGH caps the grade at D: a single open attack path matters more than many tidy settings.
  const g = s >= 90 ? 'A' : s >= 75 ? 'B' : s >= 55 ? 'C' : s >= 35 ? 'D' : 'F';
  return counts.HIGH && g < 'D' ? 'D' : g;
}
const GRADE_COLOR = { A: 'var(--good)', B: 'var(--good)', C: 'var(--warn)', D: 'var(--serious)', F: 'var(--crit)' };

const AREAS = [
  { id: 'agent', label: 'AI agent setup', short: 'Agent', icon: '<path d="M12 2a2 2 0 0 1 2 2v1h3a3 3 0 0 1 3 3v9a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3V8a3 3 0 0 1 3-3h3V4a2 2 0 0 1 2-2Zm-3 9.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3Zm6 0a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3Z"/>' },
  { id: 'deps', label: 'Dependencies & CI', short: 'Dependencies', icon: '<path d="M12 2 3 6.5v11L12 22l9-4.5v-11L12 2Zm0 2.2 6.6 3.3L12 10.8 5.4 7.5 12 4.2ZM5 9.2l6 3v7.6l-6-3V9.2Zm8 10.6v-7.6l6-3v7.6l-6 3Z"/>' },
  { id: 'code', label: 'Code & website files', short: 'Code', icon: '<path d="M8.7 7.3 4 12l4.7 4.7-1.4 1.4L1.2 12l6.1-6.1 1.4 1.4Zm6.6 0 1.4-1.4 6.1 6.1-6.1 6.1-1.4-1.4L20 12l-4.7-4.7Z"/>' },
  { id: 'secrets', label: 'Secrets', short: 'Secrets', icon: '<path d="M14.5 2a7.5 7.5 0 0 0-7.1 9.9L2 17.3V22h4.7v-2.2h2.2v-2.2h2.2l1.4-1.4A7.5 7.5 0 1 0 14.5 2Zm2 3.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4Z"/>' },
  { id: 'site', label: 'Website (live check)', short: 'Website', icon: '<path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.9 6h-3a15.7 15.7 0 0 0-1.4-3.6A8 8 0 0 1 18.9 8ZM12 4c.8 1.2 1.5 2.5 1.9 4h-3.8c.4-1.5 1.1-2.8 1.9-4ZM4.3 14a8 8 0 0 1 0-4h3.4a16.5 16.5 0 0 0 0 4H4.3Zm.8 2h3a15.7 15.7 0 0 0 1.4 3.6A8 8 0 0 1 5.1 16Zm3-8h-3a8 8 0 0 1 4.4-3.6C8.1 5.5 7.6 6.7 8.1 8ZM12 20c-.8-1.2-1.5-2.5-1.9-4h3.8c-.4 1.5-1.1 2.8-1.9 4Zm2.3-6H9.7a14.7 14.7 0 0 1 0-4h4.6a14.7 14.7 0 0 1 0 4Zm.3 5.6c.6-1.1 1.1-2.4 1.4-3.6h3a8 8 0 0 1-4.4 3.6Zm1.7-5.6a16.5 16.5 0 0 0 0-4h3.4a8 8 0 0 1 0 4h-3.4Z"/>' },
];
const icon = (path, size = 20) => `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="currentColor" aria-hidden="true">${path}</svg>`;

// Effort, timing and copy-paste commands per kind of issue, used by the action plan.
const PLAN = {
  hook: { effort: '5 min', cmds: [] },
  permissions: { effort: '5 min', cmds: [] },
  mcp: { effort: '10 min', cmds: ['claude mcp list'] },
  injection: { effort: '5 min', cmds: [] },
  download: { effort: '15 min', cmds: [] },
  exfil: { effort: '1–3 h', cmds: [] },
  webshell: { effort: '2–4 h', cmds: [] },
  obfuscation: { effort: '30 min', cmds: [] },
  pth: { effort: '30 min', cmds: ['python -m venv --clear .venv'] },
  installHook: { effort: '15 min', cmds: ['npm config set ignore-scripts true'] },
  knownBad: { effort: '1–2 h', cmds: [] },
  typosquat: { effort: '10 min', cmds: [] },
  source: { effort: '20 min', cmds: [] },
  installScripts: { effort: '20 min', cmds: ['npm config set ignore-scripts true'] },
  composerPlugin: { effort: '10 min', cmds: ['composer self-update', 'composer audit'] },
  actionsPin: { effort: '15 min', cmds: [] },
  actionsInjection: { effort: '20 min', cmds: [] },
  prTarget: { effort: '20 min', cmds: [] },
  ciPerms: { effort: '5 min', cmds: [] },
  secret: { effort: '15 min each', cmds: [] },
  docker: { effort: '20 min', cmds: [] },
  editorAutorun: { effort: '5 min', cmds: [] },
  binary: { effort: '15 min', cmds: [] },
  siteConfig: { effort: '15 min', cmds: [] },
  siteExposed: { effort: '30 min + rotate keys', cmds: [] },
  siteEmail: { effort: '30 min', cmds: [] },
  siteOrigin: { effort: '1 h', cmds: [] },
  siteTls: { effort: '15 min', cmds: [] },
  siteHeaders: { effort: '30 min', cmds: [] },
  siteDomain: { effort: '15 min', cmds: [] },
  generic: { effort: '10 min', cmds: [] },
};

// Security controls scorecard. `eco` limits a control to projects using that ecosystem.
const CONTROLS = [
  { label: 'No agent hooks that download code or leak data', area: 'agent', test: f => /^agent:.*hook/i.test(f.category) },
  { label: 'Agent asks before running commands', area: 'agent', test: f => f.category === 'agent:permissions' },
  { label: 'MCP servers pinned and from safe locations', area: 'agent', test: f => f.category === 'agent:mcp', applies: c => c.mcp > 0 },
  { label: 'No hidden instructions aimed at AI', area: 'code', test: f => f.category.startsWith('injection:') },
  { label: 'No known-malicious packages', area: 'deps', test: f => /known-malicious/.test(f.message), applies: c => c.ecos.size > 0 },
  { label: 'No look-alike (typosquat) packages', area: 'deps', test: f => /typosquat|knot- prefix/.test(f.message), applies: c => c.ecos.size > 0 },
  { label: 'Install-time code is controlled', area: 'deps', test: f => ['installHook', 'installScripts', 'composerPlugin'].includes(explain(f).key), applies: c => ['npm', 'composer', 'pypi', 'rubygems', 'cargo'].some(e => c.ecos.has(e)) },
  { label: 'Dependencies come from trusted sources', area: 'deps', test: f => explain(f).key === 'source', applies: c => c.ecos.size > 0 },
  { label: 'Versions locked (lockfiles, exact pins)', area: 'deps', test: f => /No lockfile|No composer\.lock|No go\.sum|not pinned|accepts any version|not a fixed release|floating version|Dynamic dependency/.test(f.message), applies: c => c.ecos.size > 0 },
  { label: 'GitHub Actions pinned to commit SHAs', area: 'deps', test: f => f.category === 'ci:unpinned-action', applies: c => c.ecos.has('github-actions') },
  { label: 'CI safe from untrusted PR / issue text', area: 'deps', test: f => ['ci:untrusted-input', 'ci:pr-target', 'ci:ai-agent'].includes(f.category), applies: c => c.ecos.has('github-actions') },
  { label: 'CI token is least-privilege', area: 'deps', test: f => ['ci:permissions', 'ci:secrets'].includes(f.category), applies: c => c.ecos.has('github-actions') },
  { label: 'No plaintext secrets', area: 'secrets', test: f => f.category.startsWith('secret') },
  { label: 'No webshells, stealers or hidden payloads', area: 'code', test: f => ['webshell', 'exfil', 'obfuscation', 'download'].includes(explain(f).key) && !f.category.startsWith('agent:') },
  { label: 'No Python startup hooks', area: 'deps', test: f => f.category === 'python-startup', applies: c => c.ecos.has('pypi') },
  { label: 'Container builds hardened', area: 'deps', test: f => f.category === 'deps:docker', applies: c => c.ecos.has('docker') },
  { label: 'Editor won\'t auto-run code', area: 'code', test: f => f.category === 'editor-autorun' },
  { label: 'Production config safe (debug off, real keys, no secrets in web root)', area: 'code', test: f => f.category === 'site-config' },
  { label: 'No secrets, source or backups publicly downloadable', area: 'site', test: f => f.category === 'site:exposed', applies: c => !c.siteChallenged },
  { label: 'Email can\'t be spoofed (SPF + enforced DMARC)', area: 'site', test: f => f.category === 'site:email' },
  { label: 'Origin server hidden behind the proxy', area: 'site', test: f => f.category === 'site:origin' },
  { label: 'HTTPS enforced with a healthy certificate', area: 'site', test: f => f.category === 'site:tls' },
  { label: 'Browser security headers set', area: 'site', test: f => f.category === 'site:headers', applies: c => !c.siteChallenged },
  { label: 'Domain locked, renewing, DNS hardened', area: 'site', test: f => f.category === 'site:domain' || f.category === 'site:dns' },
];

function worst(items) {
  for (const s of SEV) if (items.some(f => f.severity === s)) return s;
  return null;
}

// ---------- dashboard ----------

function gauge(value, g) {
  const r = 58, c = 2 * Math.PI * r, off = c * (1 - value / 100);
  const color = GRADE_COLOR[g];
  return `<svg class="gauge" viewBox="0 0 150 150" width="150" height="150" role="img" aria-label="Health score ${value} out of 100, grade ${g}">
<circle cx="75" cy="75" r="${r}" fill="none" stroke="var(--grid)" stroke-width="12"/>
<circle cx="75" cy="75" r="${r}" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${value === 0 ? c.toFixed(1) : off.toFixed(1)}" transform="rotate(-90 75 75)"/>
<text x="75" y="72" text-anchor="middle" font-size="40" font-weight="700" fill="var(--ink)">${value}</text>
<text x="75" y="96" text-anchor="middle" font-size="12" fill="var(--muted)">health / 100</text></svg>`;
}

function stackedBars(rows) {
  // rows: [{label, icon, c:{HIGH,MEDIUM,LOW}}] — horizontal stacked bars on one shared scale.
  const max = Math.max(1, ...rows.map(r => r.c.HIGH + r.c.MEDIUM + r.c.LOW));
  const ticks = niceTicks(max);
  const top = ticks[ticks.length - 1];
  return `<div class="hbars" role="img" aria-label="Issues by area and severity">
${rows.map(r => {
    const total = r.c.HIGH + r.c.MEDIUM + r.c.LOW;
    const segs = ['HIGH', 'MEDIUM', 'LOW'].filter(s => r.c[s]).map(s => `<span class="seg ${s}" style="width:${(r.c[s] / top * 100).toFixed(2)}%" tabindex="0" data-tip="${esc(`${r.label}: ${r.c[s]} ${SEV_LABEL[s].toLowerCase()}`)}"></span>`).join('');
    return `<div class="hrow"><div class="hlabel">${r.icon ? icon(r.icon, 16) : ''}<span>${esc(r.label)}</span></div><div class="htrack">${ticks.map(t => `<span class="gl" style="left:${(t / top * 100).toFixed(2)}%"></span>`).join('')}<div class="hfill">${segs}${r.skipped ? '<span class="na">not run</span>' : ''}</div></div><div class="hval">${r.skipped ? '–' : total}</div></div>`;
  }).join('')}
<div class="hrow axis"><div></div><div class="htrack ticks">${ticks.map(t => `<span style="left:${(t / top * 100).toFixed(2)}%">${t}</span>`).join('')}</div><div></div></div></div>`;
}

function rankBars(items) {
  // items: [{label, n, sev}] — single-series bars in one color, sorted, value at the end.
  const max = Math.max(1, ...items.map(i => i.n));
  return `<div class="rbars">${items.map(i => `<div class="rrow" tabindex="0" data-tip="${esc(`${i.label}: ${i.n} finding${i.n > 1 ? 's' : ''}, worst ${SEV_LABEL[i.sev].toLowerCase()}`)}"><div class="rlabel">${esc(i.label)}</div><div class="rtrack"><span class="rfill" style="width:${(i.n / max * 100).toFixed(2)}%"></span></div><div class="rval">${i.n}<span class="chip ${i.sev} dot" title="Worst: ${SEV_LABEL[i.sev]}"><i aria-hidden="true">${SEV_ICON[i.sev]}</i></span></div></div>`).join('')}</div>`;
}

function niceTicks(max) {
  const step = [1, 2, 5, 10, 20, 25, 50, 100, 200, 500].find(s => max / s <= 5) || Math.ceil(max / 5);
  const out = [];
  for (let t = 0; t <= max + step - 1; t += step) { out.push(t); if (t >= max) break; }
  return out;
}

function tableView(headers, rows) {
  return `<details class="tview"><summary>Show as table</summary><table><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map((c, i) => `<td${i ? ' class="num"' : ''}>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></details>`;
}

export function renderDashboard({ generated, target, areas, notes = [] }) {
  const all = [];
  for (const a of AREAS) for (const f of areas[a.id]?.findings || []) all.push({ ...f, area: a.id });
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of all) counts[f.severity]++;
  const s = score(all);
  const g = grade(s, counts);
  const actionable = all.filter(f => f.severity !== 'INFO');

  const meta = k => AREAS.reduce((n, a) => n + (Number(areas[a.id]?.meta?.[k]) || 0), 0);
  const ecos = new Set(areas.deps?.meta?.ecosystems || []);
  const ctx = { ecos, mcp: Number(areas.agent?.meta?.mcpServers) || 0, siteChallenged: !!areas.site?.meta?.challenged };
  const filesScanned = Math.max(Number(areas.code?.meta?.files) || 0, Number(areas.secrets?.meta?.files) || 0);

  // Group findings by kind of issue.
  const groups = new Map();
  for (const f of actionable) {
    const ex = explain(f);
    if (!groups.has(ex.key)) groups.set(ex.key, { ex, items: [] });
    groups.get(ex.key).items.push(f);
  }
  for (const gr of groups.values()) gr.worst = worst(gr.items);
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  const sorted = [...groups.values()].sort((a, b) => order[a.worst] - order[b.worst] || b.items.length - a.items.length);

  // Controls.
  // Controls for areas that were not part of this run are left out entirely.
  const controls = CONTROLS.filter(c => areas[c.area]).map(c => {
    if (c.applies && !c.applies(ctx)) return { ...c, status: 'NA' };
    const hits = actionable.filter(c.test);
    return { ...c, status: hits.length ? worst(hits) : 'OK', hits };
  });
  const applicable = controls.filter(c => c.status !== 'NA');
  const passing = applicable.filter(c => c.status === 'OK');

  const siteOnly = !!areas.site && !AREAS.some(a => a.id !== 'site' && areas[a.id]);
  const verdict = counts.HIGH ? { title: 'Action needed', tone: 'HIGH', line: siteOnly ? 'Your domain or website can be abused right now. Fix the "Now" items first — most take minutes in your DNS, email or hosting dashboard.' : 'Open attack paths were found. Fix the "Now" items before installing dependencies, opening this project with an AI agent, or deploying.' }
    : counts.MEDIUM ? { title: 'Review recommended', tone: 'MEDIUM', line: siteOnly ? 'Nothing is openly exposed, but these gaps make an attack on your site or domain easier — tighten them this week.' : 'No sign of an active compromise. Several weak spots would make an attack easier — tighten them this week.' }
      : { title: 'No red flags found', tone: 'OK', line: siteOnly ? 'Nothing risky was visible from the outside. Keep 2FA on your registrar and DNS, and re-check after changes.' : 'Nothing risky matched. Keep dependencies locked, actions pinned and secrets out of files.' };
  const compromiseHint = actionable.some(f => /INSTALLED known-malicious/.test(f.message) || (f.category === 'python-startup' && f.severity === 'HIGH') || f.category === 'webshell');

  // ----- executive summary (plain-language analysis) -----
  const areaRan = AREAS.filter(a => areas[a.id]);
  const ecoNames = { npm: 'npm', pypi: 'Python', composer: 'PHP / Composer', rubygems: 'Ruby', go: 'Go', cargo: 'Rust', jvm: 'Java', nuget: '.NET', docker: 'Docker', 'github-actions': 'GitHub Actions' };
  const summary = [];
  const site = areas.site?.meta;
  const checked = [];
  if (areaRan.some(a => a.id !== 'site')) checked.push(`<b>${filesScanned.toLocaleString()} files</b>${ecos.size ? ` across <b>${[...ecos].map(e => esc(ecoNames[e] || e)).join(', ')}</b>` : ''}${ctx.mcp ? `, <b>${ctx.mcp} MCP server${ctx.mcp > 1 ? 's' : ''}</b>` : ''}`);
  if (site) checked.push(`the live site <b>${esc(site.domain)}</b> from the outside (DNS, email authentication, domain and TLS${site.challenged ? '; header and exposed-file checks were blocked by the site\'s bot protection' : `, headers and ${site.pathsChecked} sensitive paths`})`);
  summary.push(`Safeguard checked ${checked.join(' and ')}, and found <b>${counts.HIGH} high</b>, <b>${counts.MEDIUM} medium</b> and <b>${counts.LOW} low</b>-severity issues. <b>${passing.length} of ${applicable.length}</b> security controls pass.`);
  const urgent = sorted.filter(x => x.worst === 'HIGH');
  if (urgent.length) {
    const u = urgent[0];
    summary.push(`The most serious problem: <b>${esc(u.ex.title)}</b> (${u.items.length} place${u.items.length > 1 ? 's' : ''}, starting with <span class="mono">${esc(u.items[0].file || '')}</span>). ${esc(u.ex.meaning)}`);
    if (urgent.length > 1) summary.push(`Also urgent: ${urgent.slice(1, 4).map(x => `<b>${esc(x.ex.title)}</b> (${x.items.length})`).join(', ')}.`);
  } else if (sorted.length) {
    summary.push(`The main weak spot: <b>${esc(sorted[0].ex.title)}</b> (${sorted[0].items.length}). ${esc(sorted[0].ex.meaning)}`);
  }
  const clearAreas = areaRan.filter(a => !actionable.some(f => f.area === a.id));
  if (clearAreas.length) summary.push(`Clear: ${clearAreas.map(a => esc(a.label)).join(', ')}.`);

  // ----- stat tiles -----
  const tiles = [
    { sev: 'HIGH', n: counts.HIGH, sub: 'fix now' },
    { sev: 'MEDIUM', n: counts.MEDIUM, sub: 'fix this week' },
    { sev: 'LOW', n: counts.LOW, sub: 'when you can' },
    { sev: passing.length === applicable.length ? 'OK' : passing.length / Math.max(1, applicable.length) >= 0.6 ? 'LOW' : 'MEDIUM', n: `${passing.length}/${applicable.length}`, label: 'Controls passing', sub: 'security checks' },
  ];
  const tilesHtml = tiles.map(t => `<div class="tile"><div class="tl">${chip(t.sev, t.label || SEV_LABEL[t.sev])}</div><div class="tn">${t.n}</div><div class="muted small">${t.sub}</div></div>`).join('');

  const coverage = [];
  if (areaRan.some(a => a.id !== 'site')) coverage.push(
    ['Files scanned', filesScanned.toLocaleString()],
    ['Ecosystems', ecos.size ? [...ecos].map(e => ecoNames[e] || e).join(', ') : 'none detected'],
    ['Manifests & pipelines', String(areas.deps?.meta?.manifests ?? '–')],
    ['MCP servers', String(ctx.mcp)],
    ['Agent hooks', String(meta('hooks'))],
    ['Skills reviewed', String(meta('skills'))],
  );
  if (site) coverage.push(
    ['Website', site.domain],
    ['Hosting / CDN', site.platform || (site.proxied ? 'Cloudflare' : '–')],
    ['Mail provider', site.mailProvider || '–'],
    ['Certificate expires in', site.certDays != null ? `${site.certDays} days` : '–'],
    ['Domain expires in', site.domainExpiresDays != null ? `${site.domainExpiresDays} days` : '–'],
    ['Public paths probed', site.challenged ? 'blocked by bot protection' : `${site.pathsChecked} (${site.exposedPaths} exposed)`],
  );

  // ----- charts -----
  const areaRows = areaRan.map(a => {
    const c = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const f of areas[a.id]?.findings || []) if (c[f.severity] != null) c[f.severity]++;
    return { label: a.label, icon: a.icon, c, skipped: !areas[a.id] };
  });
  const areaTotal = areaRows.reduce((n, r) => n + r.c.HIGH + r.c.MEDIUM + r.c.LOW, 0);
  const topArea = [...areaRows].sort((a, b) => (b.c.HIGH * 100 + b.c.MEDIUM * 10 + b.c.LOW) - (a.c.HIGH * 100 + a.c.MEDIUM * 10 + a.c.LOW))[0];
  const areaInsight = !areaTotal ? 'No issues in any area.'
    : `<b>${esc(topArea.label)}</b> carries the most risk: ${topArea.c.HIGH} high of ${topArea.c.HIGH + topArea.c.MEDIUM + topArea.c.LOW} issues (${Math.round((topArea.c.HIGH + topArea.c.MEDIUM + topArea.c.LOW) / areaTotal * 100)}% of all issues).`;
  const typeItems = sorted.map(x => ({ label: x.ex.title, n: x.items.length, sev: x.worst })).sort((a, b) => b.n - a.n || order[a.sev] - order[b.sev]).slice(0, 8);

  // ----- controls -----
  const controlsHtml = controls.map(c => {
    const label = c.status === 'OK' ? 'Pass' : c.status === 'NA' ? 'N/A' : `${c.hits.length} ${SEV_LABEL[c.status].toLowerCase()}`;
    return `<li class="ctl ${c.status}">${chip(c.status === 'NA' ? 'NA' : c.status, label)}<span>${esc(c.label)}</span></li>`;
  }).join('');

  // ----- action plan -----
  const buckets = [
    { sev: 'HIGH', title: 'Now', sub: 'Open attack paths — do these before anything else' },
    { sev: 'MEDIUM', title: 'This week', sub: 'Weak spots that make an attack easier' },
    { sev: 'LOW', title: 'When you can', sub: 'Hygiene and hardening' },
  ];
  let stepNo = 0;
  const planHtml = buckets.map(b => {
    const items = sorted.filter(x => x.worst === b.sev);
    if (!items.length) return '';
    return `<div class="bucket"><div class="bh">${chip(b.sev, b.title)}<span class="muted small">${esc(b.sub)}</span></div>${items.map(x => {
      stepNo++;
      const p = PLAN[x.ex.key] || PLAN.generic;
      const files = [...new Set(x.items.map(f => `${f.file || ''}${f.line ? ':' + f.line : ''}`))];
      return `<div class="act panel"><div class="ah"><span class="num">${stepNo}</span><h3>${esc(x.ex.title)}</h3><span class="eff" title="Estimated effort">⏱ ${esc(p.effort)}</span></div>
<p class="ink2">${esc(x.ex.meaning)}</p>
<div class="do"><b>Do this:</b> ${esc(x.ex.fix)}</div>
${p.cmds.length ? `<div class="cmds">${p.cmds.map(c => `<div class="cmd"><code>${esc(c)}</code><button class="copy" data-copy="${esc(c)}" aria-label="Copy command">Copy</button></div>`).join('')}</div>` : ''}
<details class="where"><summary>${x.items.length} affected location${x.items.length > 1 ? 's' : ''}</summary><ul>${files.slice(0, 12).map(f => `<li class="mono">${esc(f)}</li>`).join('')}${files.length > 12 ? `<li class="muted">…and ${files.length - 12} more (see All findings)</li>` : ''}</ul></details></div>`;
    }).join('')}</div>`;
  }).join('');

  // ----- attack paths -----
  const chains = sorted.filter(x => x.ex.chain.length && x.worst !== 'LOW').slice(0, 6).map(x => `<div class="panel"><div class="ah"><h3>${esc(x.ex.title)}</h3>${chip(x.worst, `${x.items.length}`)}</div><p class="muted small">${esc(x.ex.meaning)}</p>${chainHtml(x.ex.chain, x.ex.at)}</div>`).join('');

  // ----- findings explorer -----
  const rows = all.map(f => {
    const ex = explain(f);
    return `<details class="finding" data-sev="${f.severity}" data-area="${f.area}" data-text="${esc(`${f.message} ${f.file} ${f.category}`.toLowerCase())}"><summary>${chip(f.severity)}<span class="msg">${esc(f.message)}</span><span class="loc mono">${esc(f.file || '')}${f.line ? ':' + f.line : ''}</span></summary><div class="body">${f.evidence ? `<pre class="ev">${esc(f.evidence)}</pre>` : ''}<p><b>What this means.</b> ${esc(ex.meaning)}</p>${f.severity !== 'INFO' ? chainHtml(ex.chain, ex.at) : ''}<p><b>Fix.</b> ${esc(ex.fix)}</p><label class="done"><input type="checkbox" data-id="${esc(`${f.category}|${f.file}|${f.line}|${f.message}`)}"> Mark as handled</label><span class="muted small mono" style="float:right">${esc(f.category)}</span></div></details>`;
  }).join('');

  const css = `
.top{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--plane) 88%,transparent);backdrop-filter:blur(8px);border-bottom:1px solid var(--grid)}
.top .in{max-width:1120px;margin:0 auto;padding:10px 16px;display:flex;gap:16px;align-items:center}
.brand{display:flex;gap:8px;align-items:center;font-weight:700}.brand svg{color:var(--s1)}
.top nav{display:flex;gap:4px;overflow-x:auto;flex:1;scrollbar-width:none}.top nav a{color:var(--ink2);text-decoration:none;font-size:13px;padding:4px 10px;border-radius:999px;white-space:nowrap}.top nav a:hover{background:var(--surface)}
.tbtn{border:1px solid var(--border);background:var(--surface);border-radius:8px;padding:4px 10px;cursor:pointer;font-size:13px}
section{margin-top:36px}.sh{display:flex;align-items:baseline;gap:10px;margin-bottom:12px;flex-wrap:wrap}.sh p{margin:0}
.hero{display:grid;grid-template-columns:auto 1fr;gap:24px;align-items:center;border-left:5px solid var(--vt)}
.hero .eyebrow{font-size:12px;font-weight:700;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}
.grade{display:inline-grid;place-items:center;width:34px;height:34px;border-radius:9px;font-weight:800;color:#fff;background:var(--gc);font-size:18px;vertical-align:middle;margin-left:10px}
.target{word-break:break-all;margin-top:8px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:12px}.tile{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px 16px;box-shadow:var(--shadow)}.tn{font-size:34px;font-weight:700;line-height:1.1;margin:6px 0 2px}
.summary p{margin:.55em 0}.bottom{margin-top:12px;padding:12px 14px;border-radius:10px;background:var(--vbg);font-weight:600}
.cov{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px 18px;margin:0}.cov dt{font-size:12px;color:var(--muted)}.cov dd{margin:0;font-weight:600}
.legend{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.hbars{display:grid;gap:10px}.hrow{display:grid;grid-template-columns:minmax(120px,170px) 1fr 36px;gap:10px;align-items:center}
.hlabel{display:flex;gap:7px;align-items:center;font-size:13px;color:var(--ink2)}.hlabel svg{color:var(--muted);flex:none}
.htrack{position:relative;height:22px}.gl{position:absolute;top:0;bottom:0;width:1px;background:var(--grid)}
.hfill{position:absolute;inset:3px 0;display:flex;gap:2px}.seg{display:block;height:100%;min-width:3px;outline:none}.seg:last-child{border-radius:0 4px 4px 0}
.seg.HIGH{background:var(--crit)}.seg.MEDIUM{background:var(--serious)}.seg.LOW{background:var(--warn)}.seg:hover,.seg:focus{filter:brightness(1.1);box-shadow:0 0 0 2px var(--surface),0 0 0 3px var(--ink2)}
.na{font-size:12px;color:var(--muted);align-self:center}
.hval{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
.axis .htrack{height:16px}.ticks span{position:absolute;transform:translateX(-50%);font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums}
.rbars{display:grid;gap:8px}.rrow{display:grid;grid-template-columns:minmax(140px,1.1fr) 1.4fr auto;gap:10px;align-items:center;font-size:13px;outline:none;border-radius:6px}
.rrow:hover .rfill,.rrow:focus .rfill{filter:brightness(1.12)}.rlabel{color:var(--ink2)}
.rtrack{height:14px;background:var(--plane);border-radius:0 4px 4px 0}.rfill{display:block;height:100%;background:var(--s1);border-radius:0 4px 4px 0;min-width:3px}
.rval{display:flex;gap:6px;align-items:center;font-weight:700;font-variant-numeric:tabular-nums;min-width:52px;justify-content:flex-end}
.chip.dot{padding:2px;gap:0}
.insight{margin:14px 0 0;padding:10px 12px;border-radius:8px;background:var(--plane);font-size:13.5px;color:var(--ink2)}
.tview{margin-top:12px;font-size:13px}.tview summary{cursor:pointer;color:var(--muted)}.tview table{border-collapse:collapse;width:100%;margin-top:8px}.tview th,.tview td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--grid)}.tview .num{text-align:right;font-variant-numeric:tabular-nums}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);font-size:12px;padding:5px 9px;border-radius:6px;opacity:0;transition:opacity .1s;z-index:10;max-width:260px}
.ctls{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:8px}
.ctl{display:flex;gap:10px;align-items:center;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:9px 12px;font-size:14px}.ctl .chip{min-width:96px}.ctl.NA{opacity:.6}
.bucket{margin-bottom:22px}.bh{display:flex;gap:10px;align-items:center;margin-bottom:10px}.bh .chip{font-size:13px}
.act{margin-bottom:10px}.ah{display:flex;gap:10px;align-items:center;margin-bottom:6px}.ah h3{flex:1;font-size:16px}
.num{display:inline-grid;place-items:center;width:28px;height:28px;border-radius:50%;background:var(--s1);color:#fff;font-weight:700;font-size:13px;flex:none}
.eff{font-size:12px;color:var(--muted);white-space:nowrap}
.do{background:var(--s1-bg);border-radius:8px;padding:9px 12px;margin:10px 0}
.cmds{display:grid;gap:6px;margin:8px 0}.cmd{display:flex;gap:8px;align-items:center;background:var(--plane);border:1px solid var(--border);border-radius:8px;padding:6px 6px 6px 12px}.cmd code{flex:1;font-family:var(--mono);font-size:12.5px;word-break:break-all}
.copy{border:1px solid var(--border);background:var(--surface);border-radius:6px;padding:2px 10px;cursor:pointer;font-size:12px}
.where summary{cursor:pointer;font-size:13px;color:var(--muted)}.where ul{margin:6px 0 0;padding-left:18px}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}.tools button{border:1px solid var(--border);background:var(--surface);border-radius:999px;padding:4px 12px;cursor:pointer;font-size:13px}.tools button[aria-pressed="true"]{border-color:var(--s1);color:var(--s1);font-weight:600}
.tools input,.tools select{border:1px solid var(--border);background:var(--surface);border-radius:8px;padding:5px 10px;flex:1 1 180px;min-width:0;font-size:13px}
details.finding{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:6px}
details.finding summary{display:flex;gap:10px;align-items:center;padding:10px 14px;cursor:pointer;list-style:none;flex-wrap:wrap}details.finding summary::-webkit-details-marker{display:none}
.msg{flex:1 1 300px}.loc{color:var(--muted);word-break:break-all}
details.finding .body{padding:4px 14px 14px;border-top:1px solid var(--grid)}details.finding.handled{opacity:.5}details.finding.handled .msg{text-decoration:line-through}
.done{display:inline-flex;gap:6px;align-items:center;margin-top:6px;cursor:pointer;font-size:13px}
.prog{height:6px;background:var(--grid);border-radius:999px;overflow:hidden;width:160px;display:inline-block;vertical-align:middle}.prog span{display:block;height:100%;background:var(--good);width:0}
.alert{border:1px solid var(--crit);background:var(--crit-bg);border-radius:12px;padding:12px 14px;margin-top:12px}
@media (max-width:820px){.tiles{grid-template-columns:repeat(2,1fr)}.hero{grid-template-columns:1fr;justify-items:start}.top nav{display:none}}
@media (max-width:520px){.hrow{grid-template-columns:96px 1fr 30px}.rrow{grid-template-columns:1fr 1fr auto}}
@media print{.top,.tools,.copy,#tip,.done{display:none!important}body{background:#fff}.panel,.tile,details.finding,.ctl{box-shadow:none}details>*{display:block}section{break-inside:avoid-page}}`;

  const js = `
const tip=document.getElementById('tip');
function showTip(el){const r=el.getBoundingClientRect();tip.textContent=el.dataset.tip;tip.style.opacity=1;const w=tip.offsetWidth;tip.style.left=Math.max(8,Math.min(innerWidth-w-8,r.left+r.width/2-w/2))+'px';tip.style.top=(r.top-34<8?r.bottom+8:r.top-34)+'px'}
document.querySelectorAll('[data-tip]').forEach(el=>{el.addEventListener('mouseenter',()=>showTip(el));el.addEventListener('focus',()=>showTip(el));el.addEventListener('mouseleave',()=>tip.style.opacity=0);el.addEventListener('blur',()=>tip.style.opacity=0)});
const KEY='safeguard-handled:'+document.body.dataset.target;let handled={};try{handled=JSON.parse(localStorage.getItem(KEY)||'{}')}catch(e){}
const save=()=>{try{localStorage.setItem(KEY,JSON.stringify(handled))}catch(e){}};
function count(){const all=document.querySelectorAll('.done input'),n=document.querySelectorAll('.done input:checked').length;document.getElementById('progress').textContent=n+' of '+all.length+' handled';document.querySelector('.prog span').style.width=(all.length?n/all.length*100:0)+'%'}
document.querySelectorAll('.done input').forEach(cb=>{const d=cb.closest('details');if(handled[cb.dataset.id]){cb.checked=true;d.classList.add('handled')}
cb.addEventListener('change',()=>{if(cb.checked)handled[cb.dataset.id]=1;else delete handled[cb.dataset.id];d.classList.toggle('handled',cb.checked);save();count()})});count();
let sev='ALL',area='ALL',q='';
function apply(){let n=0;document.querySelectorAll('details.finding').forEach(d=>{const ok=(sev==='ALL'||d.dataset.sev===sev)&&(area==='ALL'||d.dataset.area===area)&&(!q||d.dataset.text.includes(q));d.hidden=!ok;if(ok)n++});document.getElementById('shown').textContent=n+' shown'}
document.querySelectorAll('[data-sev-btn]').forEach(b=>b.addEventListener('click',()=>{sev=b.dataset.sevBtn;document.querySelectorAll('[data-sev-btn]').forEach(x=>x.setAttribute('aria-pressed',x===b));apply()}));
document.getElementById('area').addEventListener('change',e=>{area=e.target.value;apply()});
document.getElementById('q').addEventListener('input',e=>{q=e.target.value.toLowerCase();apply()});apply();
document.getElementById('expand').addEventListener('click',e=>{const open=e.target.dataset.open!=='1';document.querySelectorAll('details.finding:not([hidden])').forEach(d=>d.open=open);e.target.dataset.open=open?'1':'0';e.target.textContent=open?'Collapse all':'Expand all'});
document.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='Copied'}catch(e){b.textContent='Select & copy'}setTimeout(()=>b.textContent='Copy',1500)}));
document.getElementById('theme').addEventListener('click',()=>{const r=document.documentElement;const dark=r.dataset.theme?r.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;r.dataset.theme=dark?'light':'dark'});
document.getElementById('print').addEventListener('click',()=>{document.querySelectorAll('details').forEach(d=>d.open=true);print()});`;

  const vtone = verdict.tone === 'HIGH' ? 'var(--crit)' : verdict.tone === 'MEDIUM' ? 'var(--serious)' : 'var(--good)';
  const vbg = verdict.tone === 'HIGH' ? 'var(--crit-bg)' : verdict.tone === 'MEDIUM' ? 'var(--serious-bg)' : 'var(--good-bg)';
  const shield = '<path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm-1.2 13.6-3.5-3.5 1.4-1.4 2.1 2.1 4.9-4.9 1.4 1.4-6.3 6.3Z"/>';

  const body = `<div class="top"><div class="in"><span class="brand">${icon(shield, 22)}Safeguard</span><nav aria-label="Sections"><a href="#summary">Summary</a><a href="#controls">Controls</a><a href="#charts">Breakdown</a><a href="#plan">Action plan</a>${chains ? '<a href="#paths">Attack paths</a>' : ''}<a href="#findings">All findings</a></nav><button class="tbtn" id="print">Print / PDF</button><button class="tbtn" id="theme" aria-label="Toggle dark mode">◐</button></div></div>
<div class="wrap" style="--vt:${vtone};--vbg:${vbg};--gc:${GRADE_COLOR[g]}">
<section id="summary" style="margin-top:8px"><div class="panel hero"><div>${gauge(s, g)}</div><div><div class="eyebrow">Security report · ${esc(generated)}</div><h1>${esc(verdict.title)}<span class="grade" title="Grade">${g}</span></h1><p class="ink2" style="margin-top:8px">${esc(verdict.line)}</p><div class="mono muted target">${esc(target)}</div></div></div>
<div class="tiles">${tilesHtml}</div>
${compromiseHint ? '<div class="alert"><b>This machine or site may already be compromised.</b> A known-malicious package is installed, a Python startup hook runs hidden code, or a webshell is present. Do not just delete files: follow the incident-response steps (clean device first, then rotate credentials from a different device).</div>' : ''}
<div class="grid g2" style="margin-top:12px"><div class="panel summary"><h2>Analysis</h2>${summary.map(p => `<p>${p}</p>`).join('')}<div class="bottom">Bottom line: ${esc(verdict.line)}</div></div>
<div class="panel"><h2>What was checked</h2><dl class="cov" style="margin-top:12px">${coverage.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl><p class="muted small" style="margin-top:14px">Read-only and offline: nothing was executed from your files and nothing left this machine.</p></div></div></section>

<section id="controls"><div class="sh"><h2>Security controls</h2><p class="muted small">${passing.length} of ${applicable.length} passing · N/A = not used in this project, or could not be checked</p></div><ul class="ctls">${controlsHtml}</ul></section>

<section id="charts"><div class="grid g2">
<div class="panel"><div class="sh"><h2>Issues by area</h2></div><div class="legend">${['HIGH', 'MEDIUM', 'LOW'].map(x => chip(x)).join('')}</div>${stackedBars(areaRows)}<p class="insight">${areaInsight}</p>${tableView(['Area', 'High', 'Medium', 'Low'], areaRows.map(r => [r.label, r.skipped ? '–' : r.c.HIGH, r.skipped ? '–' : r.c.MEDIUM, r.skipped ? '–' : r.c.LOW]))}</div>
<div class="panel"><div class="sh"><h2>Top risk types</h2><p class="muted small">findings per kind of issue</p></div>${typeItems.length ? rankBars(typeItems) + `<p class="insight">Fixing the top ${Math.min(3, typeItems.length)} risk types resolves <b>${typeItems.slice(0, 3).reduce((n, i) => n + i.n, 0)} of ${actionable.length}</b> issues.</p>` + tableView(['Risk type', 'Findings', 'Worst'], typeItems.map(i => [i.label, i.n, SEV_LABEL[i.sev]])) : '<p class="muted">Nothing to chart: no issues found.</p>'}</div>
</div></section>

<section id="plan"><div class="sh"><h2>Your action plan</h2><p class="muted small">In order. Each step closes one kind of risk everywhere it appears.</p></div>${planHtml || '<div class="panel"><p>No actions needed. Re-run this check after adding dependencies, MCP servers, or skills.</p></div>'}</section>

${chains ? `<section id="paths"><div class="sh"><h2>How an attacker could use this</h2><p class="muted small">Real 2026 attack paths. The red step is the one your findings open; closing it breaks the chain.</p></div><div class="grid">${chains}</div></section>` : ''}

<section id="findings"><div class="sh"><h2>All findings</h2><span class="prog" aria-hidden="true"><span></span></span><span class="muted small" id="progress"></span></div>
<div class="tools" role="toolbar">${['ALL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(x => `<button data-sev-btn="${x}" aria-pressed="${x === 'ALL'}">${x === 'ALL' ? `All (${all.length})` : `${SEV_LABEL[x]} (${counts[x]})`}</button>`).join('')}<select id="area" aria-label="Area"><option value="ALL">All areas</option>${areaRan.map(a => `<option value="${a.id}">${esc(a.label)}</option>`).join('')}</select><input id="q" type="search" placeholder="Search findings or files" aria-label="Search findings"><button id="expand">Expand all</button><span class="muted small" id="shown" style="align-self:center"></span></div>
${rows || '<div class="panel">No findings.</div>'}</section>

${notes.length ? `<section><details class="tview"><summary>Scanner notes (${notes.length})</summary><ul class="muted small">${notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul></details></section>` : ''}
<footer>Generated offline by the safeguard skill. A clean result is not a guarantee: scanners find known patterns, not every attack. For full advisory coverage, run your ecosystem's audit tool (npm audit, pip-audit, composer audit, osv-scanner).</footer></div>
<div id="tip" role="tooltip"></div>`;
  return page(`Safeguard report — ${verdict.title}`, body, css, js, ` data-target="${esc(target)}"`);
}

// ---------- scam explainer card ----------

export function renderScamCard(card) {
  const v = String(card.verdict || 'Suspicious');
  const tone = /likely scam|scam|danger|do not/i.test(v) ? ['HIGH', 'var(--crit)', 'var(--crit-bg)'] : /suspicious|caution/i.test(v) ? ['MEDIUM', 'var(--serious)', 'var(--serious-bg)'] : ['OK', 'var(--good)', 'var(--good-bg)'];
  const flags = (card.flags || []).map((f, i) => ({ ...f, n: i + 1, severity: String(f.severity || 'strong').toLowerCase() }));
  const message = String(card.message || '');

  // Highlight each flag's quote inside the message (first occurrence, non-overlapping).
  const marks = [];
  for (const f of flags) {
    if (!f.quote) continue;
    const idx = message.toLowerCase().indexOf(String(f.quote).toLowerCase());
    if (idx >= 0 && !marks.some(m => idx < m.end && idx + f.quote.length > m.start)) marks.push({ start: idx, end: idx + f.quote.length, f });
  }
  marks.sort((a, b) => a.start - b.start);
  let html = '', pos = 0;
  for (const m of marks) {
    html += esc(message.slice(pos, m.start));
    html += `<mark class="${esc(m.f.severity)}" title="${esc(m.f.why)}">${esc(message.slice(m.start, m.end))}<sup>${m.f.n}</sup></mark>`;
    pos = m.end;
  }
  html += esc(message.slice(pos));

  const type = SCAM_TYPES[card.type] || SCAM_TYPES.other;
  const sevMap = { critical: 'HIGH', strong: 'MEDIUM', weak: 'LOW' };
  const nCrit = flags.filter(f => f.severity === 'critical').length;
  const nStrong = flags.filter(f => f.severity === 'strong').length;
  const risk = Math.min(100, nCrit * 45 + nStrong * 20 + flags.filter(f => f.severity === 'weak').length * 5 + (tone[0] === 'HIGH' ? 10 : 0));

  const css = `
.verdict{display:grid;grid-template-columns:auto 1fr auto;gap:18px;align-items:center;border-radius:16px;padding:20px;border:1px solid var(--border);border-left:6px solid ${tone[1]};background:var(--surface);box-shadow:var(--shadow)}
.verdict .big{width:56px;height:56px;border-radius:50%;display:grid;place-items:center;background:${tone[2]};color:${tone[1]};font-size:28px;font-weight:800}
.eyebrow{font-size:12px;font-weight:700;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}
.meter{min-width:170px}.meter .bar{height:10px;border-radius:999px;background:linear-gradient(90deg,var(--good),var(--warn),var(--serious),var(--crit));position:relative;margin:8px 0 4px}
.meter .pin{position:absolute;top:-5px;width:4px;height:20px;border-radius:2px;background:var(--ink);box-shadow:0 0 0 2px var(--surface)}
.meter .ends{display:flex;justify-content:space-between;font-size:11px;color:var(--muted)}
section{margin-top:28px}h2{margin-bottom:10px}
.msgbox{white-space:pre-wrap;word-break:break-word;font-size:15px;line-height:1.8;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--shadow)}
.meta{font-size:13px;color:var(--muted);margin-bottom:8px}
mark{border-radius:4px;padding:1px 3px;color:inherit}mark.critical{background:var(--crit-bg);box-shadow:inset 0 -2px 0 var(--crit)}mark.strong{background:var(--serious-bg);box-shadow:inset 0 -2px 0 var(--serious)}mark.weak{background:var(--warn-bg);box-shadow:inset 0 -2px 0 var(--warn)}
mark sup{font-weight:800;font-size:10px;margin-left:2px}
ol.flags{padding:0;list-style:none;margin:0;display:grid;gap:8px}ol.flags li{display:flex;gap:12px;align-items:flex-start;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.badge{display:inline-grid;place-items:center;min-width:26px;height:26px;border-radius:50%;background:var(--ink);color:var(--surface);font-weight:700;font-size:12px}
.steps{margin:0;padding-left:20px}.steps li{margin-bottom:8px}.safe{border-left:5px solid var(--good)}
@media (max-width:640px){.verdict{grid-template-columns:auto 1fr}.meter{grid-column:1/-1}}`;

  const body = `<div class="wrap" style="max-width:860px">
<div class="verdict"><span class="big" aria-hidden="true">${tone[0] === 'HIGH' ? '✕' : tone[0] === 'MEDIUM' ? '!' : '✓'}</span><div><div class="eyebrow">Safeguard scam check</div><h1 style="color:${tone[1]}">${esc(v)}</h1><div class="ink2">${esc(type.title)}${card.channel ? ` · via ${esc(card.channel)}` : ''}</div></div>
<div class="meter" aria-label="Risk ${risk} of 100"><div class="small muted">Risk level</div><div class="bar"><span class="pin" style="left:calc(${risk}% - 2px)"></span></div><div class="ends"><span>Safe</span><span>Scam</span></div></div></div>
${flags.length ? `<div class="grid g3" style="margin-top:12px">${[['HIGH', nCrit, 'critical red flags'], ['MEDIUM', nStrong, 'strong red flags'], ['LOW', flags.length - nCrit - nStrong, 'weak signals']].map(([s, n, l]) => `<div class="panel" style="padding:12px 16px">${chip(s, SEV_LABEL[s])}<div style="font-size:28px;font-weight:700;margin-top:4px">${n}</div><div class="muted small">${l}</div></div>`).join('')}</div>` : ''}
${message ? `<section><h2>The message, with the warning signs marked</h2>${card.from ? `<div class="meta">From: ${esc(card.from)}</div>` : ''}<div class="msgbox">${html}</div></section>` : ''}
${flags.length ? `<section><h2>Why</h2><ol class="flags">${flags.map(f => `<li><span class="badge">${f.n}</span><div>${chip(sevMap[f.severity] || 'MEDIUM', f.severity)} <b>${esc(f.title || '')}</b><div class="ink2" style="margin-top:4px">${esc(f.why || '')}</div>${f.quote && !marks.some(m => m.f === f) ? `<div class="mono muted small">“${esc(f.quote)}”</div>` : ''}</div></li>`).join('')}</ol></section>` : ''}
${type.chain.length ? `<section><h2>How this scam works</h2>${chainHtml(type.chain, card.step ?? -1, card.step != null, 'you are here')}${card.step != null ? '<p class="muted small">Highlighted: where you are now. Stopping here breaks the chain.</p>' : ''}</section>` : ''}
${(card.do_now || []).length ? `<section><h2>Do now</h2><div class="panel safe"><ol class="steps">${card.do_now.map(x => `<li>${esc(x)}</li>`).join('')}</ol></div></section>` : ''}
${card.safe_path ? `<section><h2>The safe way to check</h2><div class="panel">${esc(card.safe_path)}</div></section>` : ''}
${card.not_checked ? `<p class="muted small" style="margin-top:20px"><b>Not checked:</b> ${esc(card.not_checked)}</p>` : ''}
<footer>Made offline by the safeguard skill. No links in the message were opened. When in doubt, contact the company through its official app or a number you already know.</footer></div>`;
  return page(`Scam check: ${v}`, body, css);
}
