# Mode 6 — Harden my website

For anyone who owns a website: business site, shop, WordPress, Laravel, Django, Node, static site. Work through the sections in order: the first three stop the attacks that take whole businesses down (domain theft, email spoofing, server takeover). Offer `safeguard site <domain> --i-own-this` for an automatic outside-in check and `safeguard scan <webroot>` for the files.

## 1. Accounts that control the site (10 min, highest impact)
Whoever controls these controls your site, email, and customers.
- Turn on **2FA (passkey or authenticator app)** for: domain registrar, DNS provider (e.g. Cloudflare), hosting/VPS panel, CMS admin accounts, email provider, payment provider.
- **Registrar lock** ("transfer lock", status `clientTransferProhibited`) on. For valuable domains ask the registrar about **registry lock**.
- **Auto-renew on**, with a card that won't expire; an expired domain can be re-registered by anyone within weeks.
- Use a recovery email on a **different domain** than the website (if the domain is lost, its email is lost too).
- Remove ex-staff, agencies, and freelancers from all of the above. Use individual accounts, never shared logins.

## 2. Email: stop people spoofing your domain (20 min)
Without these, anyone can send email "from" your domain to your customers.
- **SPF**: one TXT record starting `v=spf1`, listing only the services that send your mail, ending in `-all` (or `~all` while testing). Never `+all`.
- **DKIM**: turn it on in your email provider and in every service that sends mail for you (shop, newsletter, contact form SMTP).
- **DMARC**: TXT at `_dmarc.yourdomain` → start with `v=DMARC1; p=none; rua=mailto:...`, then move to `p=quarantine` and **`p=reject`** once reports look clean.
- Domains that never send email: `v=spf1 -all` and `v=DMARC1; p=reject;`.
- Website mail (contact forms, order emails) should go through an authenticated **SMTP/email API**, not the server's built-in PHP `mail()`.

## 3. Hide and lock down the server (30–60 min)
A CDN/proxy (Cloudflare or similar) only hides your server if attackers can't find or reach it another way.
- Put the domain behind the proxy (orange cloud on) **before** the site goes live, or **change the server IP after** moving, because DNS-history sites keep the old IP forever.
- **Firewall the origin to accept web traffic only from the proxy's IP ranges** (Cloudflare publishes them), or use **Cloudflare Tunnel** so the server has no open web ports at all. Without this, scanners such as Censys find the origin by its certificate in hours.
- Don't leave **unproxied subdomains** (`mail.`, `cpanel.`, `ftp.`, `dev.`, `staging.`, `direct.`) pointing at the same server. Use a separate mail provider so MX/SPF records don't reveal it.
- Remember subdomains are public in certificate-transparency logs; don't rely on secret names.
- Turn on the proxy's **WAF managed rules, bot protection, and rate limiting** for login, checkout, and search pages. Protection comes from these settings, not from the proxy "learning" your traffic.
- Server: SSH keys only (no password login), no root login, automatic security updates, nothing listening that doesn't need to be (databases bound to localhost).

## 4. The application
- **Update** core, plugins, themes, and libraries promptly; turn on auto-updates for security releases.
- **Remove** plugins and themes you don't use; inactive code is still attackable.
- **Watch for ownership changes.** In 2026 WordPress plugins were bought and a backdoor shipped in a normal signed update (all closed by WordPress.org on April 7). Check the changelog and author when a plugin suddenly changes hands, and prefer vendors with a security track record.
- **Never install nulled/cracked plugins or themes.** The wp-vcd family and similar malware spread this way and create hidden admin users and spam pages.
- If you build your own plugin or theme, including with AI help: keep it in version control, have someone who knows security review it, run `safeguard package <folder>` and a static analyzer, and never paste secrets into the code. An AI assistant only knows about recent vulnerabilities if it can search for them.
- **Production settings**: debug off (`WP_DEBUG`, Laravel `APP_DEBUG`, Django `DEBUG`), error display off, unique secret keys/salts, `DISALLOW_FILE_EDIT` on WordPress.
- **Never in the web root**: `.env`, `.git/`, database dumps, backup zips, `phpinfo.php`, `debug.log`. Deploy from git to a folder outside the public one.
- **Block PHP execution in upload folders**, limit upload types, and rename/limit admin login URLs with rate limits and 2FA for admins.
- Least-privilege database user (no `GRANT ALL` for the web app); separate DB per site.

## 5. Security headers and HTTPS
- Redirect all HTTP to HTTPS; **HSTS** (`Strict-Transport-Security: max-age=31536000; includeSubDomains`).
- `Content-Security-Policy` (start in report-only), `X-Content-Type-Options: nosniff`, `frame-ancestors 'self'` (or `X-Frame-Options: SAMEORIGIN`), `Referrer-Policy: strict-origin-when-cross-origin`.
- Cookies: `Secure; HttpOnly; SameSite=Lax`.
- Hide version numbers (`Server`, `X-Powered-By`, WordPress `readme.html`).
- **CAA** DNS record naming only the certificate authorities you use; **DNSSEC** on if your registrar/DNS supports it.
- Publish `/.well-known/security.txt` so researchers can reach you.

## 6. Backups you can actually restore
- Keep **3-2-1**: three copies, two kinds of storage, one off-site — and at least one that is **offline or versioned/immutable** (ransomware and attackers delete reachable backups, including cloud folders synced to a hacked PC).
- Back up **files and database**, plus DNS records (export a zone file) and the list of plugins/versions.
- **Test a restore every quarter** onto a scratch server. An untested backup is a hope, not a backup.
- Last resort if everything is gone: archive.org snapshots can help rebuild content (not data).

## 7. Know quickly when something is wrong
- Uptime monitoring and **SSL/domain expiry alerts**.
- **File-integrity monitoring** (security plugin or host feature) alerting on new/changed PHP files.
- Alerts for new admin users, DNS changes (registrar/DNS provider notifications), and failed-login spikes.
- Google Search Console and Bing Webmaster Tools: they warn when your site is flagged for malware or spam.
- Re-run Safeguard weekly: `safeguard schedule <webroot> --apply`, or the GitHub Action on every push.

## 8. Tripwires (canary tokens)
Cheap traps that alert you the moment an attacker touches them, often before real damage:
- Free canary tokens (for example from canarytokens.org) for: a fake AWS key in a `credentials` file, a fake `.env` in a backup folder, a "passwords.docx" in a shared drive, a fake admin login URL, or a DNS token inside a database row. Use a dedicated email for alerts.
- Put them where only a thief would look; never where your own tools or backups will trigger them.
- When one fires, go straight to `incident-response.md`.

## If the site is already hacked
Follow section 5 of `incident-response.md`: take it offline, keep a copy for evidence, restore from a known-good backup or redeploy from git (don't just delete the files you found), rotate every password and key, update everything, then find the entry point in the access logs.
