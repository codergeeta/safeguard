#!/usr/bin/env node
// Interactive, offline personal security checkup page (no AI needed): the checkup steps as a
// checklist with saved progress, plus the scam red-flag reference and "if you were hacked" steps.
// Usage: node checkup.mjs [--out checkup.html] [--open]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from './lib/common.mjs';
import { page, esc } from './lib/render.mjs';
import { openFile } from './lib/open.mjs';

const USAGE = 'Usage: node checkup.mjs [--out checkup.html] [--open]';
const args = parseArgs(process.argv.slice(2), { flags: ['open', 'help'], options: ['out'] }, USAGE);
if (args.help) { console.log(USAGE); process.exit(0); }

const refs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'references');
const read = f => fs.readFileSync(path.join(refs, f), 'utf8');

// Inline Markdown: escape first, then bold, code, and links shown as text (no navigation).
function inline(s) {
  return esc(s)
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 <span class="muted">($2)</span>');
}

// Splits a guide into ## sections, each with paragraphs, ### sub-headings, and list items.
function sections(md) {
  const out = [];
  let cur = null;
  for (const raw of md.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (/^#\s/.test(line)) continue;
    const h2 = line.match(/^##\s+(.*)/);
    if (h2) { cur = { title: h2[1], blocks: [] }; out.push(cur); continue; }
    if (!cur) continue;
    const h3 = line.match(/^###\s+(.*)/);
    const li = line.match(/^\s*(?:[-*]|\d+\.)\s+(.*)/);
    if (h3) cur.blocks.push({ t: 'h3', s: h3[1] });
    else if (li) cur.blocks.push({ t: 'li', s: li[1] });
    else if (line.trim()) {
      const last = cur.blocks[cur.blocks.length - 1];
      if (last && last.t === 'p') last.s += ' ' + line.trim(); else cur.blocks.push({ t: 'p', s: line.trim() });
    }
  }
  return out;
}

let itemId = 0;
function renderSection(sec, { checklist, prefix }) {
  const body = sec.blocks.map(b => {
    if (b.t === 'h3') return `<h4>${inline(b.s)}</h4>`;
    if (b.t === 'p') return `<p class="ink2">${inline(b.s)}</p>`;
    if (!checklist) return `<div class="ref">${inline(b.s)}</div>`;
    const id = `${prefix}-${++itemId}`;
    return `<label class="item"><input type="checkbox" data-id="${id}"><span>${inline(b.s)}</span></label>`;
  }).join('');
  return `<section class="panel sec" data-sec><div class="sh"><h3>${inline(sec.title)}</h3>${checklist ? '<span class="count muted small"></span>' : ''}</div>${checklist ? '<div class="bar"><span></span></div>' : ''}${body}</section>`;
}

const checkup = sections(read('checkup-personal.md')).filter(s => !/^wrap-up/i.test(s.title));
const triage = sections(read('scam-triage.md')).filter(s => /red flags|safe path|verdict/i.test(s.title));
const incident = sections(read('incident-response.md')).filter(s => /^[0-3]\./.test(s.title));
const website = sections(read('website-hardening.md')).filter(s => /^\d\./.test(s.title));

const css = `
.top{display:flex;gap:16px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:8px}
.hero{border-left:5px solid var(--s1)}.eyebrow{font-size:12px;font-weight:700;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}
.overall{display:flex;align-items:center;gap:14px;margin-top:12px}.overall .bar{flex:1;height:12px}
.tabs{display:flex;gap:6px;margin:22px 0 14px;flex-wrap:wrap}.tabs button{border:1px solid var(--border);background:var(--surface);border-radius:999px;padding:6px 14px;cursor:pointer;font-size:14px}.tabs button[aria-selected="true"]{border-color:var(--s1);color:var(--s1);font-weight:600}
.sec{margin-bottom:12px}.sh{display:flex;justify-content:space-between;gap:10px;align-items:baseline}.sh h3{font-size:17px}
.bar{height:6px;border-radius:999px;background:var(--grid);overflow:hidden;margin:8px 0 10px}.bar span{display:block;height:100%;width:0;background:var(--good);transition:width .2s}
.item{display:flex;gap:10px;align-items:flex-start;padding:8px 10px;border-radius:8px;cursor:pointer}.item:hover{background:var(--plane)}
.item input{margin-top:4px;width:18px;height:18px;flex:none;accent-color:var(--good)}.item.done span{color:var(--muted);text-decoration:line-through}
.ref{padding:6px 0 6px 14px;border-left:3px solid var(--grid);margin:6px 0}
h4{margin:14px 0 4px;font-size:14px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
code{font-family:var(--mono);font-size:12.5px;background:var(--plane);padding:1px 5px;border-radius:4px}
.tbtn{border:1px solid var(--border);background:var(--surface);border-radius:8px;padding:5px 12px;cursor:pointer;font-size:13px}
[hidden]{display:none!important}
@media print{.tabs,.tbtn{display:none}[data-pane]{display:block!important}}`;

const js = `
const KEY='safeguard-checkup';let done={};try{done=JSON.parse(localStorage.getItem(KEY)||'{}')}catch(e){}
const save=()=>{try{localStorage.setItem(KEY,JSON.stringify(done))}catch(e){}};
function refresh(){let all=0,n=0;document.querySelectorAll('[data-pane="website"] [data-sec]').forEach(s=>{const b=s.querySelectorAll('input'),c=s.querySelectorAll('input:checked').length;s.querySelector('.count').textContent=c+' / '+b.length;s.querySelector('.bar span').style.width=(b.length?c/b.length*100:0)+'%'});document.querySelectorAll('[data-pane="checkup"] [data-sec]').forEach(s=>{const b=s.querySelectorAll('input'),c=s.querySelectorAll('input:checked').length;all+=b.length;n+=c;s.querySelector('.count').textContent=c+' / '+b.length;s.querySelector('.bar span').style.width=(b.length?c/b.length*100:0)+'%'});
document.getElementById('overall').style.width=(all?n/all*100:0)+'%';document.getElementById('overallText').textContent=n+' of '+all+' steps done'}
document.querySelectorAll('.item input').forEach(cb=>{if(done[cb.dataset.id]){cb.checked=true;cb.closest('.item').classList.add('done')}
cb.addEventListener('change',()=>{if(cb.checked)done[cb.dataset.id]=1;else delete done[cb.dataset.id];cb.closest('.item').classList.toggle('done',cb.checked);save();refresh()})});refresh();
document.querySelectorAll('[data-tab]').forEach(t=>t.addEventListener('click',()=>{document.querySelectorAll('[data-tab]').forEach(x=>x.setAttribute('aria-selected',x===t));document.querySelectorAll('[data-pane]').forEach(p=>p.hidden=p.dataset.pane!==t.dataset.tab)}));
document.getElementById('reset').addEventListener('click',()=>{if(confirm('Clear all ticks?')){done={};save();document.querySelectorAll('.item input').forEach(c=>{c.checked=false;c.closest('.item').classList.remove('done')});refresh()}});
document.getElementById('print').addEventListener('click',()=>print());`;

const body = `<div class="wrap" style="max-width:900px">
<div class="panel hero"><div class="top"><div><div class="eyebrow">Safeguard · personal security</div><h1>Your security checkup</h1></div><div><button class="tbtn" id="print">Print</button> <button class="tbtn" id="reset">Reset</button></div></div>
<p class="ink2">Work through these at your own pace. Highest impact first: start with your email, the master key to everything else. Ticks are saved in this browser only; nothing is sent anywhere.</p>
<div class="overall"><div class="bar"><span id="overall"></span></div><b id="overallText" class="small"></b></div></div>
<div class="tabs" role="tablist"><button data-tab="checkup" aria-selected="true">✅ Checkup</button><button data-tab="scam" aria-selected="false">🚩 Spot a scam</button><button data-tab="website" aria-selected="false">🌐 My website</button><button data-tab="hacked" aria-selected="false">🆘 I think I've been hacked</button></div>
<div data-pane="checkup">${checkup.map(s => renderSection(s, { checklist: true, prefix: 'c' })).join('')}</div>
<div data-pane="scam" hidden><div class="panel" style="margin-bottom:12px;border-left:5px solid var(--crit)"><b>The one rule:</b> no real company, bank, CAPTCHA or support agent ever needs you to paste a command, read back a code, install remote-access software, or pay with gift cards or crypto.</div>${triage.map(s => renderSection(s, { checklist: false })).join('')}</div>
<div data-pane="website" hidden><div class="panel" style="margin-bottom:12px;border-left:5px solid var(--s1)"><b>For website and shop owners.</b> Start with section 1: whoever controls your domain registrar and DNS controls your site and your email. For an automatic outside-in check of a site you own, run <code>npx github:codergeeta/safeguard site yourdomain.com --i-own-this --open</code>.</div>${website.map(s => renderSection(s, { checklist: true, prefix: 'w' })).join('')}</div>
<div data-pane="hacked" hidden><div class="panel" style="margin-bottom:12px;border-left:5px solid var(--crit)"><b>Order matters:</b> money first, then disconnect the affected device, then change passwords and sign out of all sessions <i>from a different, clean device</i>.</div>${incident.map(s => renderSection(s, { checklist: false })).join('')}</div>
<footer>Made offline by Safeguard (github.com/codergeeta/safeguard). Not financial or legal advice; for money already lost, call your bank using the number on your card.</footer></div>`;

const out = path.resolve(args.out || path.join(os.tmpdir(), 'safeguard-checkup.html'));
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, page('Security checkup', body, css, js));
console.log(`Security checkup page: ${out}`);
if (args.open) openFile(out);
