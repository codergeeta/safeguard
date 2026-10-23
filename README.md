# Safeguard

**A security skill for every AI agent, and for people who don't use AI at all. It helps you avoid, spot, and recover from 2026-era attacks.** It checks scam messages, walks you through account security, audits AI-agent setups and dependencies in every major ecosystem, and explains everything with visual, offline reports.

Works with **Claude Code, OpenAI Codex, Cursor, GitHub Copilot, Gemini CLI, Windsurf, Cline, OpenCode, Goose, Roo, Kiro, Continue, Junie, Amp, Zed** and 60+ more agents (open Agent Skills format). It also works with **any MCP client** (Claude Desktop, ChatGPT desktop, VS Code…), with **chat apps** (ChatGPT, Gemini, Claude Projects), and as a **plain command-line tool**.

![Safeguard dashboard](docs/dashboard.png)

## Why

In 2026 most attacks go after **people and their sessions**, not software bugs:

- **AI-written phishing** on every channel: email, SMS, QR codes, cloned voices.
- **ClickFix**: a fake CAPTCHA that tells you to press Win+R and paste a command.
- **MFA-bypass kits, device-code and OAuth-consent phishing** that take over accounts without your password.
- **Infostealers** (Vidar, Lumma, Atomic) that grab browser sessions, SSH keys, `.env` files and API tokens.

Developers face **supply-chain worms** across every registry. Some 2026 examples:

- **npm:** Mini Shai-Hulud, the poisoned axios releases, and the Mastra takeover.
- **PyPI:** two LiteLLM compromises (March and October) and the Hades campaign.
- **Composer:** intercom-php and Laravel-Lang.
- **Others:** WordPress plugin backdoors, Ruby/Go sleeper packages, malicious Rust crates, re-pointed GitHub Action tags, a poisoned VS Code extension, malicious agent skills and MCP servers.

See [`threats-2026.md`](skills/safeguard/references/threats-2026.md) for the full catalogue with sources.

## What it does

| Mode | Ask your AI… | You get |
|---|---|---|
| **Scam check** | "Is this SMS / email / pop-up / call a scam?" | A verdict and a **visual card** with the red flags highlighted in the message, plus the safe way to check |
| **Security checkup** | "Help me secure my accounts" | A guided checklist: passkeys, sessions, OAuth apps, router, backups, family code word |
| **Dev & agent audit** | "Audit this repo / my Claude setup" | A **visual dashboard**: health score, risk by area, the attack chain each finding enables, and fixes |
| **Vet before install** | "Is this skill / MCP server / package safe?" | A static review of the code and manifest, plus identity checks |
| **Incident response** | "I think I've been hacked" | Steps in the right order: money, isolate, recover from a clean device, revoke sessions, rotate developer tokens, clean a hacked site |
| **Harden my website** | "Make my website / shop safer" | Registrar and DNS lockdown, email anti-spoofing, hiding the server behind the CDN properly, CMS and plugin hygiene, headers, backups, monitoring, tripwires, plus an optional **live check** of your own domain |
| **Prevention** | "Stop this happening again" | A **guard hook** that blocks dangerous agent actions before they run, a **pre-commit** secret block, a **GitHub Action**, and a **weekly re-check** |

## Visual reports

Every audit can produce a **self-contained, offline HTML dashboard** (`safeguard.mjs <project> --open`):

- **Health score and grade**, a verdict, and stat tiles for high, medium, and low issues and controls passing.
- **Plain-language analysis**: what was scanned, the most serious problem and where it starts, what else is urgent, what's clear, and a bottom line.
- **Security controls scorecard**: 17 controls, each marked pass, fail, or not applicable to this project.
- **Charts**: issues by area as stacked severity bars, and the top risk types, each with a one-line insight, a hover tooltip, and a table view.
- **Action plan** grouped into *Now*, *This week*, and *When you can*. Each step has an effort estimate, the reason, the exact fix, copyable commands, and the affected files.
- **Attack paths**: the real 2026 attack chain each kind of finding enables, with the step your findings open highlighted.
- **Findings explorer** with search, filters, and a "mark as handled" checkbox with a progress bar. It supports dark mode, print/PDF, and phone layout.

![Dark mode](docs/dashboard-dark.png)

For everyday users, the **scam check card** shows their own message with every red flag highlighted and numbered. It adds a risk meter, the plain reasons, the scam's step-by-step chain with *you are here*, what to do now, and the safe way to verify:

![Scam check card](docs/scam-card.png)

### What the scanners check

| Area | Checks |
|---|---|
| **AI agents** | Claude Code hooks and permission rules; Codex approval/sandbox policy; MCP servers in Claude Code/Desktop, Codex (TOML), Cursor, VS Code, Gemini CLI, Windsurf, Cline, Zed; installed skills for ~20 agents; prompt injection in `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules`, `.windsurf/rules`, `.clinerules`, Copilot instructions |
| **npm / pnpm / yarn** | Install scripts, git/URL deps, odd registries, typosquats, known-bad versions, missing lockfile |
| **Python** | Known-bad versions, typosquats, `--extra-index-url` dependency confusion, VCS deps, unpinned/unhashed requirements, **`.pth` / `sitecustomize.py` startup hooks in local venvs** |
| **PHP** | Composer `allow-plugins: true`, plugin packages, install scripts, VCS repos, **webshells** (`eval($_POST…)`, decoded eval, PHP in `uploads/`) |
| **Ruby, Go, Rust, Java, .NET** | Non-standard sources, `replace`/`[patch]` overrides, missing checksums, Gradle wrapper URL, plain-http repos, floating versions |
| **Docker** | Unpinned base images, `curl \| sh`, secrets in `ENV`, running as root |
| **GitHub Actions** | Unpinned actions, `pull_request_target` "pwn requests", `${{ github.event… }}` script injection, AI-agent workflows exposed to untrusted issues, missing `permissions:` |
| **Code** | Download-and-execute, credential theft plus network calls, exfil hosts (Discord/Telegram webhooks, webhook.site…), obfuscation, reverse shells, persistence, hidden Unicode, text aimed at AI reviewers |
| **Secrets** | 25+ token types (GitHub, npm, PyPI, AWS, Anthropic, OpenAI, Stripe, Supabase service keys, DB URLs, private keys…) with values always redacted; `--home` reviews the credential files infostealers target |

## Install — pick what you use

| You use | How | Command |
|---|---|---|
| **Any coding agent that reads skills** (Codex, Cursor, Copilot, Gemini CLI, Windsurf, Cline, OpenCode, Goose, Roo, Kiro, Continue, Junie, Amp, Claude Code, 60+ more) | Agent Skills installer | `npx skills add codergeeta/safeguard` |
| …or our own installer (Node 18+, detects your agents) | Copies the skill into every detected agent | `npx github:codergeeta/safeguard install` |
| **Claude Code** | Plugin (auto-updates) | `/plugin marketplace add codergeeta/safeguard` then `/plugin install safeguard@codergeeta` |
| **Gemini CLI** | Native extension (skill + MCP) | `gemini extensions install https://github.com/codergeeta/safeguard` |
| **Any MCP client** (Claude Desktop, ChatGPT desktop, VS Code, Cursor, Codex, Windsurf, Zed, Cline, Continue…) | MCP server with 7 tools, 7 guides, 4 prompts | `npx github:codergeeta/safeguard mcp-config` prints the exact config for each app |
| **ChatGPT, Gemini, Claude.ai, Copilot chat** (no code) | Custom GPT / Gem / Project instructions | Paste [`chat/INSTRUCTIONS.md`](skills/safeguard/chat/INSTRUCTIONS.md) and upload [`references/`](skills/safeguard/references) as knowledge |
| **No AI at all** | Command-line tool + offline pages | `npx github:codergeeta/safeguard checkup --open` or `… scan <folder> --open` |

Installer options: `--list` shows the supported agents and which are detected, `--agent codex,cursor` picks agents, `--all` installs for every agent, `--project <dir>` installs into a repo instead of your profile, `--dry-run` previews, and `--uninstall` removes it. It never overwrites a different skill that happens to be called "safeguard".

**MCP setup example.** This works for Claude Desktop, Cursor, Windsurf, Gemini CLI and Cline. VS Code uses a `"servers"` key with `"type": "stdio"`, and Codex uses TOML; `mcp-config` prints those too.

```json
{ "mcpServers": { "safeguard": { "command": "npx", "args": ["-y", "github:codergeeta/safeguard", "mcp"] } } }
```

The scanners need Node.js 18 or later. Without Node, agents fall back to the manual checks in the guides, and chat apps use the instruction pack.

## Use

Just ask your agent or chat app:

- *"Is this message a scam?"* and paste it
- *"Help me secure my accounts"*
- *"Audit this project for supply-chain risks"*
- *"Check my AI agent setup for anything dangerous"*
- *"Is the MCP server in ./downloads/foo safe to install?"*
- *"I pasted a command from a CAPTCHA page, what do I do?"*

Or use the command line. `npx github:codergeeta/safeguard <command>` works with nothing installed, and `npm i -g github:codergeeta/safeguard` gives you a `safeguard` command:

```bash
safeguard scan <folder> --open          # full checkup + visual dashboard
safeguard deps <folder>                 # dependencies & CI, all ecosystems
safeguard agent --project <folder>      # AI-agent config across all major agents
safeguard package <folder>              # vet a package / skill / MCP server / website root
safeguard secrets <folder> --home       # plaintext secrets (values redacted)
safeguard checkup --open                # interactive personal + website security checklist
safeguard site example.com --i-own-this --open   # live check of YOUR website (online, opt-in)
safeguard mcp                           # run the MCP server
```

Every scanner supports `--json` and exits with code `2` when HIGH findings exist, so you can use them in CI.

![Personal checkup page](docs/checkup.png)

## For website owners

`safeguard site yourdomain.com --i-own-this --open` checks your site **from the outside**, the way an attacker sees it, and produces the same visual report. It flags:

- **Origin leaks around Cloudflare:** unproxied subdomains, or mail and SPF records that point at your real server.
- **Email spoofing:** a missing or weak SPF record, or a missing or `p=none` DMARC policy.
- **Domain takeover risks:** registrar transfer lock off, the domain about to expire, no CAA record, no DNSSEC.
- **HTTPS problems:** an expiring or untrusted certificate, or HTTP not redirecting to HTTPS.
- **Missing protections:** no HSTS, CSP, clickjacking protection or `nosniff`; software versions leaked in headers; cookies without Secure or HttpOnly.
- **Files anyone can download:** `.git`, `.env`, config backups, SQL dumps, site archives, `phpinfo`, `server-status`, `debug.log`, WordPress user lists, `xmlrpc.php`. It confirms each by its content, so ordinary "not found" pages aren't reported, and it **never shows what was inside**.

This is the only Safeguard feature that uses the network. It refuses to run without `--i-own-this`, sends about 30 ordinary requests to your site plus DNS, RDAP and DNSSEC lookups, and never follows redirects to other sites. Only run it on domains you own.

Pair it with `safeguard scan <webroot>` for the server files: it finds `.git`, `.env` and dumps in the public folder, debug mode in production, placeholder WordPress keys, directory listing, **wp-vcd malware** and **nulled plugins**. The checkup page has a **My website** tab with a 43-step checklist. The full guide is [`website-hardening.md`](skills/safeguard/references/website-hardening.md).

## Prevention: stop problems before they happen

| Tool | What it does | Set up |
|---|---|---|
| **Agent guard** | A hook that checks every command, file read and web fetch an AI agent is about to make. It **blocks** download-and-run, credential theft, env-variable exfiltration, reverse shells, webhook/paste-site exfiltration, deleting your home folder or a drive, and force-pushing to main. It **asks first** before secret files are read (Claude Code). It fails open, so a guard bug never locks you out. | `safeguard guard --install` (Claude Code, Cursor, Gemini CLI; backs up your settings first). Test any command: `safeguard guard --check "<command>"` |
| **Pre-commit secret block** | Stops commits that add API keys, tokens, private keys or `.env` files. Values are redacted in the message | `safeguard precommit --install` in a repo |
| **GitHub Action** | Runs the full checkup on every push or PR, writes a job summary, annotates the files, uploads the visual report, and fails on HIGH (configurable) | See below |
| **Weekly re-check** | Uses your OS scheduler (Task Scheduler, launchd or cron). Writes a fresh report every Monday and opens it only when something needs attention. `--site yourdomain.com` adds the live check | `safeguard schedule <folder> --apply` (prints the plan first without `--apply`) |
| **Tripwires** | Canary tokens: fake keys and files that alert you the moment a thief touches them | Guide: [`website-hardening.md` §8](skills/safeguard/references/website-hardening.md) |

```yaml
# .github/workflows/safeguard.yml
name: safeguard
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: codergeeta/safeguard@336d3114bc8ea9261fec1c609f5849767fc63f1b # v1.2.2
        with:
          fail-on: high        # high | medium | low | never
```

## Safety design

- **Read-only and offline.** Scanners never execute, install, or upload anything. Reports are self-contained HTML with a Content-Security-Policy that blocks all network access. The one exception is the opt-in website check (`--i-own-this`).
- **Changes only when you ask.** The guard, pre-commit, scheduler and installer all preview first (`--dry-run`, or no `--apply`), back up what they edit, never overwrite things that aren't theirs, and uninstall cleanly.
- **Secrets are redacted** everywhere, in the terminal and in reports.
- **Prompt-injection aware.** Scanned content is treated as data. Text that tries to steer an AI reviewer is itself reported as a HIGH finding.
- **No self-exemption by name.** Scans skip only this skill's own folder, matched by exact location, so a malicious skill can't hide by calling itself "safeguard".
- **Calibrated.** The skill says what it did not check. A clean scan is not a guarantee.

## Limits

- Pattern-based static analysis catches known techniques, not every attack.
- `known-bad.json` is a small offline sample of 2026 incidents, not an advisory database. With your consent the skill offers `npm audit`, `pip-audit`, `composer audit`, `osv-scanner` and similar tools for full coverage.
- It is not a replacement for antivirus, EDR, or your bank's fraud team.

## Development

```bash
node skills/safeguard/tests/run_tests.mjs
```

The 171 tests build throwaway malicious and clean fixtures in your temp folder: hooks, MCP configs, webshells, `.pth` stealers, poisoned lockfiles for every ecosystem, workflow injections, and XSS payloads. They then check every scanner and both HTML reports against them. The suite also includes:

- **Regression tests from an independent review:** realistic false positives (UI comments, `$curl`/`$apiKey`, ngrok dev origins, WordPress stubs, apps that read `OPENAI_API_KEY`), malformed lockfiles, and a performance test on a 2 MB minified bundle.
- **Speed:** every regex is bounded, so a scan never stalls on huge single-line files.

To add a newly reported malicious package, add it to [`known-bad.json`](skills/safeguard/references/known-bad.json) with a source in the PR description.

## License

MIT
