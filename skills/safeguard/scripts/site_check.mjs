#!/usr/bin/env node
// Opt-in, outside-in exposure check of a website the user owns. This is the only Safeguard
// script that uses the network. It sends DNS lookups, one RDAP lookup (rdap.org), one DNSSEC
// query (Cloudflare DNS-over-HTTPS), and ~30 ordinary HTTPS requests to the site itself.
// It never prints the content of exposed files and never follows redirects to other sites.
// Usage: node site_check.mjs <domain> --i-own-this [--json] [--out report.html] [--open]
import dns from 'node:dns';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { parseArgs, Report } from './lib/common.mjs';
import { renderDashboard } from './lib/render.mjs';
import { openFile, stamp } from './lib/open.mjs';

const USAGE = `Usage: node site_check.mjs <domain> --i-own-this [--json] [--out report.html] [--open]
Checks a website YOU own or are authorised to test, from the outside: origin-IP leaks around the
CDN, email spoofing protection (SPF/DMARC), CAA, DNSSEC, registrar lock and expiry, HTTPS/TLS,
security headers, and publicly reachable secrets, source code, backups and debug pages.`;
// --test-base points the HTTP probes at a local fixture server and skips DNS/RDAP/TLS (tests only).
const args = parseArgs(process.argv.slice(2), { flags: ['i-own-this', 'json', 'open', 'help', 'no-report'], options: ['out', 'timeout', 'test-base'] }, USAGE);
if (args.help || !args._[0]) { console.log(USAGE); process.exit(args.help ? 0 : 1); }
if (!args['i-own-this']) {
  console.error(`${USAGE}\n\nRefusing to run: add --i-own-this to confirm you own this site or are authorised to test it.\nThis check contacts the site and public DNS services; only use it on your own domains.`);
  process.exit(1);
}

const domain = String(args._[0]).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/?#].*$/, '').replace(/\.$/, '');
if (!/^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) { console.error(`Not a valid domain name: ${domain}`); process.exit(1); }
const apex = domain.replace(/^www\./, '');
const TIMEOUT = Number(args.timeout) || 8000;
const TEST = args['test-base'] ? String(args['test-base']).replace(/\/$/, '') : null;
if (TEST && !/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(TEST)) { console.error('--test-base must be a localhost URL'); process.exit(1); }
const BASE = TEST || `https://${domain}`;
const UA = 'safeguard-site-check/1.2 (+https://github.com/codergeeta/safeguard; owner-requested scan)';

const report = new Report(`safeguard: website exposure check — ${domain}`, null);
let requests = 0;
const add = (sev, cat, where, msg, ev) => report.add(sev, `site:${cat}`, where, null, msg, ev);

// ---------- helpers ----------
const resolver = new dns.promises.Resolver({ timeout: TIMEOUT, tries: 2 });
async function q(fn, name) { try { return await resolver[fn](name); } catch { return null; } }

// Cloudflare's published ranges (cloudflare.com/ips). Used only to tell "proxied" from "direct".
const CF4 = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'];
const CF6 = ['2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'];
const toInt4 = ip => ip.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
function inV4(ip, cidr) { const [b, bits] = cidr.split('/'); const m = bits === '0' ? 0 : (~0 << (32 - bits)) >>> 0; return (toInt4(ip) & m) === (toInt4(b) & m); }
function expand6(ip) { const [h, t = ''] = ip.split('::'); const a = h ? h.split(':') : [], b = t ? t.split(':') : []; return [...a, ...Array(8 - a.length - b.length).fill('0'), ...b].map(x => parseInt(x || '0', 16)); }
function inV6(ip, cidr) { const [b, bits] = cidr.split('/'); const x = expand6(ip), y = expand6(b); let left = Number(bits); for (let i = 0; i < 8 && left > 0; i++, left -= 16) { const m = left >= 16 ? 0xffff : (0xffff << (16 - left)) & 0xffff; if ((x[i] & m) !== (y[i] & m)) return false; } return true; }
const isCF = ip => (ip.includes(':') ? CF6.some(c => inV6(ip, c)) : CF4.some(c => inV4(ip, c)));
const isPrivate = ip => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|f[cd])/i.test(ip);

async function http(url, { method = 'GET', max = 65536, accept = '*/*' } = {}) {
  requests++;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT);
  try {
    const res = await fetch(url, { method, redirect: 'manual', signal: ctl.signal, headers: { 'user-agent': UA, accept } });
    let body = Buffer.alloc(0);
    if (method !== 'HEAD' && res.body) {
      const reader = res.body.getReader();
      const parts = [];
      let size = 0;
      while (size < max) { const { done, value } = await reader.read(); if (done) break; parts.push(Buffer.from(value)); size += value.length; }
      try { await reader.cancel(); } catch { /* ignore */ }
      body = Buffer.concat(parts).subarray(0, max);
    }
    return { status: res.status, headers: res.headers, body, text: body.toString('utf8') };
  } catch (e) {
    return { status: 0, error: e.name === 'AbortError' ? 'timeout' : e.message, headers: new Headers(), body: Buffer.alloc(0), text: '' };
  } finally { clearTimeout(t); }
}

function certInfo(host) {
  return new Promise(resolve => {
    const s = tls.connect({ host, port: 443, servername: host, timeout: TIMEOUT, rejectUnauthorized: false }, () => {
      const c = s.getPeerCertificate();
      resolve({ authorized: s.authorized, error: s.authorizationError, validTo: c && c.valid_to ? new Date(c.valid_to) : null, issuer: c?.issuer?.O || c?.issuer?.CN, protocol: s.getProtocol() });
      s.end();
    });
    s.on('error', e => resolve({ error: e.message }));
    s.on('timeout', () => { s.destroy(); resolve({ error: 'timeout' }); });
  });
}

// ---------- 1. DNS, CDN and origin exposure ----------
// Set by the DNS section; stay at these defaults in --test-base mode.
let proxied = false;
let pendingOrigin = null;
if (!TEST) {
const a4 = (await q('resolve4', domain)) || [];
const a6 = (await q('resolve6', domain)) || [];
const ips = [...a4, ...a6];
if (!ips.length) { add('HIGH', 'dns', domain, 'Domain does not resolve — check the DNS records (or the domain may have expired)'); }
proxied = ips.length > 0 && ips.every(isCF);
const cnameHint = (await q('resolveCname', domain)) || [];
// Whether a non-Cloudflare site is on a CDN/hosting platform is decided after the homepage
// request, from its response headers (see "platform" below), because apex records rarely CNAME.
pendingOrigin = ips.length && !proxied ? { ip: ips[0], cname: cnameHint.find(c => /cloudfront|fastly|akamai|edgekey|azurefd|vercel-dns|netlify|pages\.dev|github\.io|herokudns|sucuri|stackpath|bunny|cdn/i.test(c)) } : null;
report.meta.proxied = proxied;

const SUBS = ['www', 'mail', 'webmail', 'smtp', 'ftp', 'cpanel', 'whm', 'direct', 'origin', 'dev', 'staging', 'test', 'admin', 'api', 'server', 'vpn', 'portal', 'old', 'beta'];
const leaks = [];
if (proxied) {
  await Promise.all(SUBS.map(async s => {
    const host = `${s}.${apex}`;
    if (host === domain) return;
    const r = [...((await q('resolve4', host)) || []), ...((await q('resolve6', host)) || [])].filter(ip => !isCF(ip) && !isPrivate(ip));
    if (r.length) leaks.push({ host, ip: r[0] });
  }));
  for (const l of leaks) add('MEDIUM', 'origin', l.host, `Unproxied subdomain ${l.host} resolves to ${l.ip} — if that is your web server, it reveals the origin the proxy is hiding`);
  if (!leaks.length) add('INFO', 'origin', domain, 'Site is behind Cloudflare and no common unproxied subdomains were found. Make sure the origin firewall only accepts Cloudflare IPs');
  else add('INFO', 'origin', domain, 'Also check: the origin firewall accepts only Cloudflare IP ranges (or use Cloudflare Tunnel), and change the server IP if it was ever public');
}

// ---------- 2. Email authentication ----------
const mx = (await q('resolveMx', apex)) || [];
const txt = ((await q('resolveTxt', apex)) || []).map(r => r.join(''));
const spf = txt.filter(t => /^v=spf1\b/i.test(t));
const dmarcTxt = (((await q('resolveTxt', `_dmarc.${apex}`)) || []).map(r => r.join(''))).filter(t => /^v=DMARC1/i.test(t));
const sendsMail = mx.length > 0;
// Spoofable = no SPF and no enforced DMARC: forged mail "from" the domain gets delivered.
const dmarcPolicy = ((dmarcTxt[0] || '').match(/\bp=(\w+)/i) || [])[1]?.toLowerCase();
const spoofable = !spf.length && (!dmarcTxt.length || dmarcPolicy === 'none' || !dmarcPolicy);
const googleMx = mx.some(m => /google\.com$|googlemail\.com$/i.test(m.exchange));
const microsoftMx = mx.some(m => /outlook\.com$|protection\.outlook\.com$/i.test(m.exchange));
const spfHint = googleMx ? ' For Google Workspace: v=spf1 include:_spf.google.com ~all' : microsoftMx ? ' For Microsoft 365: v=spf1 include:spf.protection.outlook.com ~all' : '';
if (!spf.length) add(spoofable ? 'HIGH' : 'MEDIUM', 'email', apex, sendsMail
  ? `No SPF record${spoofable ? ' and no enforced DMARC — anyone can send email that passes as your domain' : ' — receivers can\'t tell which servers may send mail as your domain'}.${spfHint}`
  : 'No SPF record. If this domain never sends email, publish "v=spf1 -all" so nobody can send as it');
else {
  if (spf.length > 1) add('MEDIUM', 'email', apex, `${spf.length} SPF records — only one is allowed; receivers treat this as an error`);
  const s = spf[0];
  if (/[+?]all\b/i.test(s) || !/[-~]all\b/i.test(s) && !/redirect=/i.test(s)) add('HIGH', 'email', apex, 'SPF allows any server to send as your domain (+all, ?all or no all)', s);
  else if (/~all\b/i.test(s)) add('LOW', 'email', apex, 'SPF ends in ~all (soft fail). Move to -all once all senders are listed', s);
  if (/\bip[46]:/i.test(s)) add('LOW', 'origin', apex, 'SPF lists raw IP addresses — make sure none of them is your web server, or it reveals the origin', s);
}
if (!dmarcTxt.length) add(spf.length ? 'MEDIUM' : 'HIGH', 'email', `_dmarc.${apex}`, 'No DMARC record — anyone can send phishing "from" your domain to your customers. Start with p=none reporting, then move to p=reject');
else {
  const p = (dmarcTxt[0].match(/\bp=(\w+)/i) || [])[1]?.toLowerCase();
  if (p === 'none') add('LOW', 'email', `_dmarc.${apex}`, 'DMARC is in monitor mode (p=none) — spoofed mail is still delivered. Move to quarantine, then reject', dmarcTxt[0]);
  else if (!p) add('MEDIUM', 'email', `_dmarc.${apex}`, 'DMARC record has no valid policy (p=)', dmarcTxt[0]);
}
for (const m of mx) {
  if (!m.exchange.toLowerCase().endsWith(apex)) continue;
  const mips = ((await q('resolve4', m.exchange)) || []).filter(ip => !isCF(ip) && !isPrivate(ip));
  if (mips.length && proxied) add('LOW', 'origin', m.exchange, `Mail server ${m.exchange} (${mips[0]}) is on your own domain — if it shares the web server, it reveals the origin. A separate mail provider avoids this`);
}
report.meta.mailProvider = mx.length ? mx.sort((x, y) => x.priority - y.priority)[0].exchange : 'none';

// ---------- 3. Domain: CAA, DNSSEC, registrar lock, expiry ----------
const caa = await q('resolveCaa', apex);
if (!caa || !caa.length) add('LOW', 'dns', apex, 'No CAA record — any certificate authority may issue certificates for your domain. Add CAA naming only the CAs you use');
const doh = await http(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(apex)}&type=DS`, { accept: 'application/dns-json' });
try {
  const j = JSON.parse(doh.text);
  if (!(j.Answer || []).some(a => a.type === 43)) add('LOW', 'dns', apex, 'DNSSEC is not enabled — DNS answers for your domain can be forged on some networks. Enable it at your DNS provider and registrar');
} catch { report.note('DNSSEC status could not be determined.'); }
const rdap = await http(`https://rdap.org/domain/${encodeURIComponent(apex)}`, { max: 262144 });
let rdapJson = null;
if (rdap.status >= 300 && rdap.status < 400 && rdap.headers.get('location')) {
  const loc = rdap.headers.get('location');
  if (/^https:\/\//.test(loc)) { const r2 = await http(loc, { max: 262144 }); try { rdapJson = JSON.parse(r2.text); } catch { /* ignore */ } }
} else { try { rdapJson = JSON.parse(rdap.text); } catch { /* ignore */ } }
if (rdapJson) {
  const status = (rdapJson.status || []).map(s => String(s).toLowerCase());
  if (!status.some(s => /transfer prohibited/.test(s))) add('MEDIUM', 'domain', apex, 'Registrar transfer lock is off — turn on "transfer lock" so the domain can\'t be moved to another registrar without you', status.join(', '));
  const exp = (rdapJson.events || []).find(e => /expiration/i.test(e.eventAction))?.eventDate;
  if (exp) {
    const days = Math.round((new Date(exp) - Date.now()) / 86400000);
    report.meta.domainExpiresDays = days;
    if (days < 30) add(days < 7 ? 'HIGH' : 'MEDIUM', 'domain', apex, `Domain expires in ${days} day(s) — renew now and turn on auto-renew; expired domains are snapped up by attackers`);
  }
} else report.note('Registrar lock and expiry could not be checked (RDAP unavailable for this domain/TLD).');

} // end DNS/domain checks

// ---------- 4. HTTPS, TLS, headers ----------
if (!TEST) {
const cert = await certInfo(domain);
if (cert.error && !cert.validTo) add('HIGH', 'tls', domain, `HTTPS is not reachable (${cert.error})`);
else {
  if (!cert.authorized) add('HIGH', 'tls', domain, `Certificate is not trusted by browsers (${cert.error || 'invalid'})`);
  if (cert.validTo) {
    const days = Math.round((cert.validTo - Date.now()) / 86400000);
    report.meta.certDays = days;
    if (days < 14) add(days < 3 ? 'HIGH' : 'MEDIUM', 'tls', domain, `TLS certificate expires in ${days} day(s) — check auto-renewal`);
  }
  if (cert.protocol && /TLSv1(\.[01])?$/.test(cert.protocol)) add('MEDIUM', 'tls', domain, `Server negotiated outdated ${cert.protocol}`);
}
const plain = await http(`http://${domain}/`, { max: 2048 });
if (plain.status && !(plain.status >= 300 && plain.status < 400 && /^https:\/\//i.test(plain.headers.get('location') || ''))) add('MEDIUM', 'tls', domain, `http://${domain}/ does not redirect to HTTPS (status ${plain.status})`);
}
const home = await http(`${BASE}/`, { max: 131072 });
const hh = n => home.headers.get(n) || '';
// Hosting platform / CDN, from response headers (apex DNS records rarely reveal it).
const platform = /vercel/i.test(hh('server')) || hh('x-vercel-id') ? 'Vercel'
  : hh('cf-ray') ? 'Cloudflare' : hh('x-nf-request-id') ? 'Netlify' : hh('x-amz-cf-id') ? 'Amazon CloudFront'
    : /fastly/i.test(hh('x-served-by') + hh('via')) ? 'Fastly' : /github\.com/i.test(hh('server')) ? 'GitHub Pages'
      : /akamai/i.test(hh('server')) ? 'Akamai' : null;
report.meta.platform = platform || (proxied ? 'Cloudflare' : 'none detected');
if (pendingOrigin) {
  const hosted = ['Vercel', 'Netlify', 'GitHub Pages'].includes(platform);
  if (hosted) add('INFO', 'origin', domain, `Hosted on ${platform}'s edge network — there is no separate origin server IP to hide`);
  else if (platform || pendingOrigin.cname) add('INFO', 'origin', domain, `Served through ${platform || pendingOrigin.cname} — make sure the origin behind it only accepts traffic from the CDN`);
  else add('LOW', 'origin', domain, `Not behind a proxy/CDN: the server IP (${pendingOrigin.ip}) is public. A proxy such as Cloudflare plus an origin firewall cuts bot and DDoS traffic`);
}
// Bot protection (Vercel/Cloudflare challenge) answers scanners with a challenge page. That is good
// protection, but header and exposed-file results would describe the challenge page, not the site.
const challenged = home.status >= 400 && (/challenge/i.test(hh('x-vercel-mitigated') + hh('cf-mitigated')) || /just a moment|cf-chl|challenge-platform|security checkpoint/i.test(home.text));
report.meta.challenged = challenged;
if (challenged) {
  add('INFO', 'coverage', domain, `Bot protection is on: ${platform || 'the CDN'} answered automated requests with a challenge (HTTP ${home.status}). That blocks scanners and scraping bots, which is good — but the security-header and exposed-file checks could not see your real site. To complete them, allowlist your own IP in the ${platform || 'CDN'} firewall or briefly pause the challenge, then re-run`);
} else if (home.status) {
  const h = n => home.headers.get(n);
  const csp = h('content-security-policy') || '';
  if (!h('strict-transport-security')) add('MEDIUM', 'headers', domain, 'Missing Strict-Transport-Security (HSTS) — browsers may still connect over plain HTTP first');
  if (!csp) add('LOW', 'headers', domain, 'Missing Content-Security-Policy — the main browser defence against injected scripts and card skimmers');
  if (!h('x-frame-options') && !/frame-ancestors/i.test(csp)) add('LOW', 'headers', domain, 'No clickjacking protection (X-Frame-Options or CSP frame-ancestors)');
  if (!/nosniff/i.test(h('x-content-type-options') || '')) add('LOW', 'headers', domain, 'Missing X-Content-Type-Options: nosniff');
  if (!h('referrer-policy')) add('INFO', 'headers', domain, 'No Referrer-Policy header (strict-origin-when-cross-origin is a good default)');
  for (const n of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
    const v = h(n);
    if (v && /\d+\.\d+/.test(v)) add('LOW', 'headers', domain, `${n} header reveals software versions (${v.slice(0, 60)}) — attackers match these to known exploits`);
  }
  const cookies = typeof home.headers.getSetCookie === 'function' ? home.headers.getSetCookie() : [h('set-cookie')].filter(Boolean);
  for (const c of cookies) {
    const name = c.split('=')[0];
    if (!/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c)) add('LOW', 'headers', domain, `Cookie "${name}" is missing Secure and/or HttpOnly`);
  }
  report.meta.wordpress = /wp-content|wp-includes/i.test(home.text);
  const gen = (home.text.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i) || [])[1];
  if (gen && /\d/.test(gen)) add('LOW', 'headers', domain, `Page advertises its exact software version (${gen.slice(0, 60)})`);
} else add('HIGH', 'tls', domain, `https://${domain}/ did not respond (${home.error})`);

// ---------- 5. Publicly reachable secrets, source, backups, debug pages ----------
// A random path tells us what this site returns for "not found" so soft-404 pages aren't reported.
const base = challenged ? { status: 0 } : await http(`${BASE}/safeguard-${crypto.randomBytes(6).toString('hex')}.txt`, { max: 65536 });
const baseHash = base.status === 200 ? crypto.createHash('sha1').update(base.body).digest('hex') : null;
const notHtml = r => !/^\s*<(!doctype|html)/i.test(r.text);
const PROBES = [
  ['/.git/HEAD', 'HIGH', 'Git repository is downloadable — full source code and history (including any committed secrets)', r => /^ref: refs\//.test(r.text)],
  ['/.git/config', 'HIGH', 'Git config is downloadable — the whole .git folder is likely exposed', r => /^\s*\[core\]/m.test(r.text)],
  ['/.env', 'HIGH', '.env file is downloadable — database passwords and API keys are exposed. Move it outside the web root and rotate every secret in it', r => notHtml(r) && /^[A-Z][A-Z0-9_]{1,40}=/m.test(r.text)],
  ['/.env.production', 'HIGH', '.env.production is downloadable — rotate every secret in it', r => notHtml(r) && /^[A-Z][A-Z0-9_]{1,40}=/m.test(r.text)],
  ['/.env.local', 'HIGH', '.env.local is downloadable — rotate every secret in it', r => notHtml(r) && /^[A-Z][A-Z0-9_]{1,40}=/m.test(r.text)],
  ['/wp-config.php.bak', 'HIGH', 'WordPress config backup is downloadable — database password exposed', r => /DB_PASSWORD/.test(r.text)],
  ['/wp-config.php~', 'HIGH', 'WordPress config editor backup is downloadable — database password exposed', r => /DB_PASSWORD/.test(r.text)],
  ['/wp-config.old', 'HIGH', 'Old WordPress config is downloadable — database password exposed', r => /DB_PASSWORD/.test(r.text)],
  ['/.htpasswd', 'HIGH', '.htpasswd is downloadable — password hashes exposed', r => notHtml(r) && /^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13}$)/m.test(r.text)],
  ['/backup.zip', 'HIGH', 'A site backup archive is downloadable', r => r.body.subarray(0, 2).toString() === 'PK'],
  ['/backup.sql', 'HIGH', 'A database dump is downloadable', r => notHtml(r) && /(CREATE TABLE|INSERT INTO)/i.test(r.text)],
  ['/db.sql', 'HIGH', 'A database dump is downloadable', r => notHtml(r) && /(CREATE TABLE|INSERT INTO)/i.test(r.text)],
  ['/dump.sql', 'HIGH', 'A database dump is downloadable', r => notHtml(r) && /(CREATE TABLE|INSERT INTO)/i.test(r.text)],
  ['/site.zip', 'HIGH', 'A site archive is downloadable', r => r.body.subarray(0, 2).toString() === 'PK'],
  ['/.svn/entries', 'MEDIUM', 'Subversion metadata is downloadable', r => notHtml(r) && /^\d+\s*$/m.test(r.text.slice(0, 20))],
  ['/phpinfo.php', 'MEDIUM', 'phpinfo() page is public — it reveals server paths, versions and sometimes environment secrets', r => /phpinfo\(\)|PHP Version/i.test(r.text)],
  ['/info.php', 'MEDIUM', 'phpinfo() page is public — it reveals server paths, versions and sometimes environment secrets', r => /phpinfo\(\)|PHP Version/i.test(r.text)],
  ['/server-status', 'MEDIUM', 'Apache server-status is public — it shows live requests and client IPs', r => /Apache Server Status/i.test(r.text)],
  ['/wp-content/debug.log', 'MEDIUM', 'WordPress debug.log is downloadable — it can contain paths, queries and user data', r => notHtml(r) && /PHP (Notice|Warning|Fatal|Deprecated)/.test(r.text)],
  ['/debug.log', 'MEDIUM', 'debug.log is downloadable', r => notHtml(r) && /(PHP (Notice|Warning|Fatal)|ERROR|Exception)/.test(r.text)],
  ['/wp-json/wp/v2/users', 'LOW', 'WordPress REST API lists usernames — attackers use them for password guessing. Restrict the users endpoint', r => /^\s*\[\s*\{[^]*"slug"\s*:/.test(r.text)],
  ['/xmlrpc.php', 'LOW', 'xmlrpc.php is enabled — used for brute-force and pingback attacks. Disable it if you don\'t use the mobile app or Jetpack', r => /XML-RPC server accepts POST requests only/i.test(r.text)],
  ['/readme.html', 'LOW', 'WordPress readme.html is public and can reveal the version', r => /WordPress/i.test(r.text) && /Version/i.test(r.text)],
  ['/.DS_Store', 'LOW', '.DS_Store is downloadable — it lists file names in the folder', r => r.body.subarray(4, 8).toString() === 'Bud1'],
];
let exposed = 0;
for (let i = 0; !challenged && i < PROBES.length; i += 4) {
  const batch = PROBES.slice(i, i + 4);
  const results = await Promise.all(batch.map(([p]) => http(`${BASE}${p}`)));
  batch.forEach(([p, sev, msg, ok], k) => {
    const r = results[k];
    if (r.status !== 200) return;
    if (baseHash && crypto.createHash('sha1').update(r.body).digest('hex') === baseHash) return;
    if (!ok(r)) return;
    exposed++;
    add(sev, 'exposed', `${BASE}${p}`, msg);
  });
}
if (!challenged) {
  const sec = await http(`${BASE}/.well-known/security.txt`, { max: 8192 });
  if (!(sec.status === 200 && /contact:/i.test(sec.text))) add('INFO', 'headers', domain, 'No /.well-known/security.txt — publishing one tells researchers how to report problems to you');
}
if (report.meta.wordpress) add('INFO', 'headers', domain, 'WordPress detected — see the WordPress items in the hardening guide (updates, unused plugins, DISALLOW_FILE_EDIT, PHP blocked in uploads)');

report.meta.domain = domain;
report.meta.requests = requests;
report.meta.exposedPaths = exposed;
report.meta.pathsChecked = challenged ? 0 : PROBES.length;
report.note(`${requests} HTTP request(s) made to ${domain}, rdap.org and cloudflare-dns.com, plus DNS lookups through your system resolver. No content from exposed files is shown.`);
report.note('Outside-in checks see only what the internet sees. Pair this with `safeguard scan <webroot>` for the files on the server.');

if (!args['no-report']) {
  const out = path.resolve(args.out || path.join(os.tmpdir(), `safeguard-site-${apex.replace(/[^a-z0-9.-]/g, '')}-${stamp()}.html`));
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, renderDashboard({ generated: new Date().toLocaleString(), target: `https://${domain}`, areas: { site: { findings: report.findings, meta: report.meta } }, notes: report.notes }));
  report.meta.report = out;
  if (!args.json) report.note(`Visual report: ${out}`);
  if (args.open) openFile(out);
}
report.finish(args.json);
