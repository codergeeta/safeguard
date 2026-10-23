# Safeguard

**A Claude skill that helps people and developers avoid, spot, and recover from 2026-era attacks.** It checks scam messages, walks you through account security, audits AI-agent setups and dependencies in every major ecosystem, and explains everything with visual, offline reports.

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

| Mode | Ask Claude… | You get |
|---|---|---|
| **Scam check** | "Is this SMS / email / pop-up / call a scam?" | A verdict and a **visual card** with the red flags highlighted in the message, plus the safe way to check |
| **Security checkup** | "Help me secure my accounts" | A guided checklist: passkeys, sessions, OAuth apps, router, backups, family code word |
| **Dev & agent audit** | "Audit this repo / my Claude setup" | A **visual dashboard**: health score, risk by area, the attack chain each finding enables, and fixes |
| **Vet before install** | "Is this skill / MCP server / package safe?" | A static review of the code and manifest, plus identity checks |
| **Incident response** | "I think I've been hacked" | Steps in the right order: money, isolate, recover from a clean device, revoke sessions, rotate developer tokens, clean a hacked site |

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
| **AI agents** | Claude Code hooks, permission rules, `bypassPermissions`, MCP servers (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf), skills, commands, plugins, `CLAUDE.md`/`AGENTS.md` prompt injection |
| **npm / pnpm / yarn** | Install scripts, git/URL deps, odd registries, typosquats, known-bad versions, missing lockfile |
| **Python** | Known-bad versions, typosquats, `--extra-index-url` dependency confusion, VCS deps, unpinned/unhashed requirements, **`.pth` / `sitecustomize.py` startup hooks in local venvs** |
| **PHP** | Composer `allow-plugins: true`, plugin packages, install scripts, VCS repos, **webshells** (`eval($_POST…)`, decoded eval, PHP in `uploads/`) |
| **Ruby, Go, Rust, Java, .NET** | Non-standard sources, `replace`/`[patch]` overrides, missing checksums, Gradle wrapper URL, plain-http repos, floating versions |
| **Docker** | Unpinned base images, `curl \| sh`, secrets in `ENV`, running as root |
| **GitHub Actions** | Unpinned actions, `pull_request_target` "pwn requests", `${{ github.event… }}` script injection, AI-agent workflows exposed to untrusted issues, missing `permissions:` |
| **Code** | Download-and-execute, credential theft plus network calls, exfil hosts (Discord/Telegram webhooks, webhook.site…), obfuscation, reverse shells, persistence, hidden Unicode, text aimed at AI reviewers |
| **Secrets** | 25+ token types (GitHub, npm, PyPI, AWS, Anthropic, OpenAI, Stripe, Supabase service keys, DB URLs, private keys…) with values always redacted; `--home` reviews the credential files infostealers target |

## Install

**As a plugin** (recommended; updates with the repo):

```text
/plugin marketplace add codergeeta/safeguard
/plugin install safeguard@codergeeta
```

Then ask Claude anything from the table above, or invoke it directly with `/safeguard:safeguard`.

**Or as a personal skill:** copy `skills/safeguard` into `~/.claude/skills/safeguard` (invoke with `/safeguard`):

```bash
git clone https://github.com/codergeeta/safeguard
cp -r safeguard/skills/safeguard ~/.claude/skills/safeguard
```

Requires Node.js 18 or later for the scanners. Without Node, the skill falls back to manual checks.

## Use

Just ask:

- *"Is this message a scam?"* and paste it
- *"Audit this project for supply-chain risks"*
- *"Check my Claude Code setup for anything dangerous"*
- *"Is the MCP server in ./downloads/foo safe to install?"*
- *"I pasted a command from a CAPTCHA page, what do I do?"*

Or run the scanners yourself:

```bash
node skills/safeguard/scripts/safeguard.mjs <project> --open        # full checkup + visual dashboard
node skills/safeguard/scripts/check_deps.mjs <project>              # dependencies & CI, all ecosystems
node skills/safeguard/scripts/audit_agent_config.mjs --project <p>  # AI-agent config
node skills/safeguard/scripts/scan_package.mjs <dir>                # vet a package / skill / website root
node skills/safeguard/scripts/scan_secrets.mjs <dir> --home         # plaintext secrets
```

Every scanner supports `--json` and exits with code `2` when HIGH findings exist, so you can use them in CI.

## Safety design

- **Read-only and offline.** Scanners never execute, install, or upload anything. Reports are self-contained HTML with a Content-Security-Policy that blocks all network access.
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

The 91 tests build throwaway malicious and clean fixtures in your temp folder: hooks, MCP configs, webshells, `.pth` stealers, poisoned lockfiles for every ecosystem, workflow injections, and XSS payloads. They then check every scanner and both HTML reports against them. The suite also includes:

- **Regression tests from an independent review:** realistic false positives (UI comments, `$curl`/`$apiKey`, ngrok dev origins, WordPress stubs, apps that read `OPENAI_API_KEY`), malformed lockfiles, and a performance test on a 2 MB minified bundle.
- **Speed:** every regex is bounded, so a scan never stalls on huge single-line files.

To add a newly reported malicious package, add it to [`known-bad.json`](skills/safeguard/references/known-bad.json) with a source in the PR description.

## License

MIT
