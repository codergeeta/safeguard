# Mode 5 — "I think I've been hacked"

Stay calm and specific. Order matters: **a stolen session or an infected device makes password changes useless**, so isolate first, change from a clean device second, revoke sessions third.

## 0. Triage (ask quickly, then act)
1. What happened? (ran a command / installed something / entered a password / approved a prompt / sent money / account locked out / strange activity / ransom note / a developer token leaked)
2. Which device and which accounts?
3. When?
4. Is money involved? → do step 1 **now**, in parallel with everything else.

## 1. Money first (minutes matter)
- Call the bank/card issuer using the number on the card or the official app. Ask to block cards, stop or recall transfers, and flag the account.
- India: call **1930** and report at **cybercrime.gov.in** within the golden hour. US: **reportfraud.ftc.gov** and **ic3.gov**. UK: **Report Fraud** (formerly Action Fraud) / 0300 123 2040. Elsewhere: national cybercrime / police portal.
- Crypto: contact the exchange immediately; transfers are rarely reversible.
- Gift cards: call the card brand's number with the card details; sometimes funds can be frozen.

## 2. Isolate the device (if malware or a pasted command is possible)
- Disconnect it from the network (Wi-Fi off / cable out). Do not wipe it yet if the user wants evidence.
- If remote-access software was installed (AnyDesk, TeamViewer, Quick Assist, ScreenConnect), uninstall it and treat the device as compromised.
- Assume an **infostealer** if the user ran a ClickFix command, a cracked app, a game cheat, a fake installer, or a suspicious package: browser passwords, cookies, wallets, SSH keys, `.env`, and tokens are gone. Plan to **reset the device** (Windows: Reset this PC → Remove everything; macOS: Erase All Content and Settings) after backing up documents only (not programs, not browser profiles).
- Run a full antivirus scan (Microsoft Defender Offline scan on Windows) as a check, but do not treat a clean result as proof for an infostealer case.

## 3. From a clean device, take back accounts
Clean device = a phone or computer that was not involved. Order: email → password manager → bank → phone carrier → Apple/Google/Microsoft → work accounts → social → everything else.

For each account:
1. Change the password (new, unique).
2. **Sign out of all sessions / devices** — this kills stolen cookies. (Google: Security → Your devices → Sign out; Microsoft: Security → Sign out everywhere; Apple ID: Devices; Facebook/Instagram: Where you're logged in.)
3. Re-check MFA methods: remove any phone, authenticator, passkey, or security key you did not add.
4. Remove unknown **connected apps / OAuth grants**.
5. Check **recovery email/phone**, **forwarding rules**, **mail filters**, and **delegates**.
6. If locked out, use the official recovery flow only (never "recovery services" that contact you).

If the user approved a **device code** or **OAuth consent**, revoking that app/session is the key step; a password change alone does not remove it.

Work accounts: tell the IT/security team immediately. They can revoke tokens and check for spread; do not try to clean up a work incident quietly.

## 4. Developer / AI-agent compromise
Treat as an infostealer case **plus** supply-chain risk to others. Use a clean machine.
1. **Revoke and rotate**, don't just rotate: GitHub PATs, SSH keys (remove from GitHub/GitLab too), npm / PyPI / Packagist / RubyGems / crates.io / NuGet / Docker Hub publish tokens, cloud keys (AWS/GCP/Azure), Vercel/Netlify/Supabase tokens, AI API keys (Anthropic, OpenAI, etc.), database passwords, CI secrets, `.env` contents, Kubernetes configs.
2. **Check your packages weren't republished**: look at the publish history of every package you maintain for versions you did not release (Shai-Hulud style worms republish with your token). Deprecate/yank any you didn't publish and tell the registry's security team.
3. **Check GitHub**: audit log, new deploy keys, new SSH keys, new OAuth apps, new workflows or workflow edits (especially ones that dump `secrets`), unexpected repos created (worms create repos to dump stolen data), branch protections changed.
4. **Check CI**: recent runs you did not trigger, new self-hosted runners.
5. **Python**: search every venv/site-packages for unexpected `*.pth` files with `import` lines and for `sitecustomize.py` — they re-run malware on every Python start and survive package removal. Rebuild venvs from scratch rather than uninstalling one package.
6. **Agent config**: run `scripts/audit_agent_config.mjs` and remove any unknown hook, MCP server, skill, or plugin.
7. Tell affected users if you published a compromised version.

## 5. Website hacked (PHP / WordPress / Node / Python site)
1. Take the site to maintenance mode or offline; take a copy (files + database) for evidence.
2. Run `scripts/scan_package.mjs <webroot>` to find webshells and injected code; check for `.php` files in upload folders, recently modified files, unknown admin users, and unknown cron jobs.
3. Restore from a known-good backup or redeploy from source control; do not just delete the files you found.
4. Rotate: hosting panel, SFTP/SSH, database, admin users, API keys in `.env` / `wp-config.php`, WordPress salts.
5. Update the platform, every plugin/theme, and remove abandoned plugins; ask the host for access logs to find the entry point.

## 6. After
- Watch bank statements and account alerts for 90 days. Consider a credit freeze.
- Expect follow-up "recovery" scams: nobody legitimate charges to recover lost money.
- Write down what happened and what was changed (useful for police, bank, insurer, employer).
- Do the Mode 2 checkup to close the gap that let it happen.
