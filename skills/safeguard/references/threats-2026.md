# Threat catalogue — 2026

Last researched: 2026-10-23. Figures are mostly from vendor reports; treat them as direction, not precision. Use this file to explain *why* something is a red flag.

## 1. People-targeted attacks (everyday users)

### AI-written phishing on every channel
- Phishing text is now fluent, personalised, and free of the spelling mistakes people were taught to look for. Several 2026 reports put AI-generated content in roughly 40–80% of phishing.
- Channels have spread: QR-code phishing ("quishing") rose ~146% in one quarter (Microsoft, Q1 2026); voice phishing ("vishing") rose ~134% year over year (CrowdStrike 2026).
- **Deepfake voice/video**: a few seconds of public audio is enough to clone a boss, child, or parent. Typical script: emergency + secrecy + money/gift cards/crypto/wire.
- **Red flags that still work**: urgency, secrecy, unusual payment method, a request to move to another app, a link/QR/number you did not look up yourself, a sender address or domain that is close-but-not-exact.

### ClickFix and "paste this command"
- A web page shows a fake CAPTCHA, "verify you are human", browser-update, or "fix this error" dialog and tells you to press **Win+R** (or open Terminal / PowerShell), paste, and press Enter. The clipboard was already filled with a malware download command.
- Variants: "press Win+X then I", "paste into the address bar", macOS Terminal "install the fix", fake GitHub issue "run this to reproduce".
- **Rule**: no real website, CAPTCHA, or support agent ever needs you to paste a command into Run, Terminal, or PowerShell.

### MFA-bypass account takeover
- **Adversary-in-the-middle phishing kits** (rented, not built) proxy the real login page. The password and MFA code are real, the login succeeds, and the attacker keeps the session cookie.
- **Device-code phishing**: the victim is told to enter a code at a genuine Microsoft/Google page. That approves the attacker's device.
- **OAuth consent phishing ("ConsentFix")**: the victim clicks "Allow" for an app that gets mailbox/drive access without a password.
- **MFA fatigue**: repeated push prompts until the victim taps Approve.
- Defences: passkeys/security keys for important accounts; never enter a code or approve a prompt you did not start; review connected apps; "sign out of all sessions" after any suspicion.

### Infostealers
- Malware such as Vidar, Lumma (revived after its 2025 takedown), StealC, and Atomic Stealer (macOS) grab browser cookies, saved passwords, crypto wallets, SSH keys, `.env` files, cloud and AI-tool tokens, and Discord/Telegram sessions in seconds.
- Common sources: game cheats and cracked software, fake installers from search ads, ClickFix pages, malicious extensions, poisoned packages.
- A stolen session cookie **bypasses passwords, MFA, and even passkeys** until the session is revoked. That is why recovery = clean device first, then rotate and revoke from a clean device.
- Documented case: in April 2026 a Lumma infection on one employee machine (from a Roblox-cheats download) reportedly led to stolen Google Workspace credentials and cloud keys used in the Vercel-related incident.

### Breaches you cannot prevent
- Large breaches this month alone include ASOS, Oracle Health (~20M people), Quest Diagnostics, and SBI customer records found on the dark web. Breach data fuels targeted phishing ("we noticed a problem with your recent lab order").
- Defences: unique passwords per site, credit freeze, distrust "follow-up" messages after a breach is in the news.

### Home network and edge devices
- Consumer routers are ~56% of exploited edge-device vulnerabilities (VulnCheck 2026). End-of-life routers never get fixes.
- Business VPNs (Check Point CVE-2026-50751, Palo Alto PAN-OS, Ivanti EPMM, Cisco FMC) were exploited for ransomware in 2026.

## 2. Developer and AI-agent attacks

### Package-registry supply chain — every ecosystem
2026 attacks were no longer npm-only. The same groups (notably **TeamPCP**, behind the Shai-Hulud / Mini Shai-Hulud worms) moved across registries. See `ecosystems.md` for per-ecosystem detail and hardening.

| Ecosystem | 2026 examples | How code ran |
|---|---|---|
| npm | Mini Shai-Hulud worm (from Apr 29) republished itself into every package its victims could publish; poisoned axios releases (Mar 31, ~3 h); Mastra takeover republished 140+ packages in ~88 min (Jun 17); Cline package compromised via prompt injection (Feb) | `preinstall` / `postinstall` scripts |
| PyPI | LiteLLM 1.82.7/1.82.8 (Mar 24) and 1.107.0 (Oct 21); Hades campaign (26 packages, Jun); typosquats `rlask`, `tlask`, `rsquests`, `nhmpy` (Jun 7) | `.pth` file / `sitecustomize.py` that runs on **every Python start**, `setup.py` |
| Composer / Packagist (PHP) | intercom/intercom-php 5.0.2 turned into a Composer plugin (Apr 30); Laravel-Lang: hundreds of malicious versions under old tags (May 22–23); 8-package campaign hiding code in the bundled `package.json` (May) | Composer plugins run at install; overwritten Git tags; JS tooling inside PHP packages |
| WordPress | Plugins bought on Flippa, then a backdoor shipped in a signed update; all closed Apr 7 | Normal auto-update |
| RubyGems / Go | BufferZoneCorp "sleeper" packages (`knot-` prefixes) (May) | Native-extension build at install; Go `init()` |
| crates.io (Rust) | `chrono_anchor`, `time_calibrator` (Feb–Mar) | `build.rs` / proc macros |
| GitHub Actions | TeamPCP compromised Actions (Feb–May); two Checkmarx Actions (Mar); Trivy compromise used to steal LiteLLM's PyPI token | Mutable tags (`@v1`) re-pointed to malicious commits |
| VS Code / Open VSX | Malicious Nx Console release (2.2M installs) led to ~3,800 GitHub internal repos exfiltrated (May) | Extension auto-update |
| Agent skills | ClawHavoc: 1,184 poisoned skills delivering Atomic Stealer; Snyk ToxicSkills: 76 confirmed malicious skills | Skill scripts/instructions run by the agent |

Common payload: steal npm/PyPI/GitHub tokens, cloud keys, SSH keys, `.env`, CI secrets, AI API keys, then use stolen publish tokens to spread.

### Attacks on AI coding agents
- **Prompt injection from repo content**: an issue title, PR description, README, code comment, or web page tells the agent to run commands or leak secrets ("Clinejection", Feb 2026, started from an issue title read by an agent holding CI credentials).
- **Malicious MCP servers**: tool descriptions carry hidden instructions; "instruction fragmentation" splits theft into innocent-looking steps the agent assembles itself. About 40% of internet-reachable MCP servers expose tools with no auth.
- **Malicious hooks**: a repo's `.claude/settings.json` hook (e.g. `SessionStart`) runs a shell command with your privileges whenever the agent starts.
- **LLM bait packages**: e.g. PromptMink (North Korea-linked) used "LLM optimisation" so agents would choose malicious packages; Hades embedded prompt injection telling AI analysers its code was safe.
- **Hallucinated package names ("slopsquatting")**: attackers register names that AI assistants tend to invent.

### Web apps being hacked (PHP, Node, Python sites)
- Webshells dropped via vulnerable plugins/uploads: `eval(base64_decode(...))`, `assert($_POST[...])`, `system($_GET[...])`, files in `uploads/` that end in `.php`.
- Maximum-severity bugs in widely used servers this month (GitLab, NGINX) — patch quickly.
- Leaked `.env` / `.git/` exposed on the web root; debug mode enabled in production.

## Sources
- Hoxhunt Phishing Trends 2026; Microsoft Q1 2026 quishing data; CrowdStrike 2026 Global Threat Report
- The Hacker News, "Know Your Enemy: Browser-Based Attack Techniques in 2026"; BleepingComputer on ConsentFix/ClickFix; Push Security mid-year 2026
- SpyCloud; Bitdefender (Lumma return); write-ups of the April 2026 Vercel-related incident
- Semgrep and Socket on intercom-php; The Hacker News on the Packagist 8-package campaign; Laravel-Lang reporting; WordPress.org plugin closures (Apr 7)
- GitLab, Wiz, Snyk, StepSecurity, SafeDep, Mend on LiteLLM and Hades
- The Hacker News on BufferZoneCorp Ruby/Go; Aikido on Nx Console / GitHub breach; Phoenix Security supply-chain tracker
- Cloud Security Alliance on claude-code-action prompt injection; Snyk ToxicSkills; Security Arsenal on MCP fragmentation
- VulnCheck State of Exploitation 2026; CISA KEV and BOD 26-02
