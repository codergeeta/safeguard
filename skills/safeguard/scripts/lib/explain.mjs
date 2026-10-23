// Plain-language explanations for findings: what it means, how an attack uses it, how to fix it.
// `chain` is the attack path; `at` is the step this finding enables (0-based).

const E = {
  hook: {
    title: 'Agent hook runs commands automatically',
    meaning: 'Claude Code hooks run shell commands with your full user rights whenever an event fires (session start, after a tool call). A hook planted in a repo runs the moment you open that repo with an agent.',
    chain: ['You clone a repo and open it with an AI agent', 'Repo hook fires on SessionStart', 'Hook downloads or runs a script', 'Script reads tokens, SSH keys, .env', 'Attacker publishes malware from your accounts'],
    at: 1,
    fix: 'Delete hooks you did not add. Before opening an untrusted repo with an agent, read its .claude/ folder first.',
  },
  permissions: {
    title: 'Agent allowed to act without asking',
    meaning: 'Broad allow rules or bypassPermissions let the agent run any command, read any file, or fetch any URL without a confirmation prompt. A single prompt injection then goes straight to execution.',
    chain: ['Agent reads attacker text (issue, web page, README)', 'Text tells the agent to run a command', 'No permission prompt appears', 'Command runs with your rights'],
    at: 2,
    fix: 'Remove Bash(*), bypassPermissions, and wildcard WebFetch rules. Add deny rules for ~/.ssh, ~/.aws, and .env files.',
  },
  mcp: {
    title: 'MCP server risk',
    meaning: 'MCP servers are programs the agent starts or connects to. They run with your rights and their tool descriptions are read by the model, so a malicious or swapped server can both run code and steer the agent.',
    chain: ['MCP server starts (unpinned npx/uvx pulls the newest version)', 'A compromised release is published upstream', 'Server runs code on your machine', 'Tool descriptions steer the agent to leak secrets in small steps'],
    at: 0,
    fix: 'Pin exact versions (pkg@1.2.3), remove servers you do not use, prefer official servers, never run servers from Downloads/temp, and give each only the env vars it needs.',
  },
  injection: {
    title: 'Text aimed at an AI, not a human',
    meaning: 'Instructions hidden in files, comments, metadata, or invisible characters that try to make an AI assistant ignore its rules, hide actions from you, or call malicious code safe. Seen in 2026 PyPI (Hades) and npm (PromptMink) campaigns.',
    chain: ['Agent or AI scanner reads the file', 'Hidden instruction overrides its task', 'AI runs a command or reports "safe"', 'Malware gets installed with your approval'],
    at: 1,
    fix: 'Do not install or run this. Treat any text that addresses an AI reviewer as strong evidence of malicious intent.',
  },
  download: {
    title: 'Downloads and runs remote code',
    meaning: 'A command fetches code from the internet and executes it immediately, so whoever controls that URL controls your machine. This is the core of ClickFix lures and most install-script malware.',
    chain: ['A step runs automatically (install, hook, task, CI)', 'It downloads a script', 'The script runs with no review', 'Infostealer or backdoor is installed'],
    at: 1,
    fix: 'Remove the command, or replace it with a pinned, checksum-verified download from a source you trust.',
  },
  exfil: {
    title: 'Sends secrets off the machine',
    meaning: 'Code or commands that read credentials (SSH keys, cloud keys, browser data, environment variables) and also make network requests. That combination is what an infostealer does.',
    chain: ['Code runs (install, import, startup)', 'Reads tokens, keys, cookies, wallets', 'Sends them to an attacker server', 'Attacker logs in as you, bypassing MFA'],
    at: 1,
    fix: 'Do not run it. If it already ran: clean the machine, then rotate every credential from a different device (see Incident response).',
  },
  webshell: {
    title: 'Website backdoor (webshell)',
    meaning: 'PHP that executes code or commands sent in a web request. Anyone who knows the URL can run anything on your server: steal the database, inject card skimmers, send spam, pivot further.',
    chain: ['Vulnerable plugin or upload form', 'Attacker uploads a .php file', 'Attacker sends commands to it over HTTP', 'Database stolen, site defaced, visitors infected'],
    at: 2,
    fix: 'Take the site offline, restore from a known-good backup or redeploy from git, rotate DB/hosting/admin passwords, update every plugin, and block PHP execution in upload folders.',
  },
  obfuscation: {
    title: 'Hidden / obfuscated code',
    meaning: 'Large encoded blobs or eval-of-decoded-data hide what code really does. Legitimate packages rarely need this; malware almost always does.',
    chain: ['Package looks normal at a glance', 'Encoded payload decoded at runtime', 'Payload runs (stealer, backdoor)'],
    at: 1,
    fix: 'Decode the content as text (never run it) and inspect it. If you cannot explain it, do not install.',
  },
  pth: {
    title: 'Python startup hook',
    meaning: 'A .pth file or sitecustomize.py in site-packages runs code every time Python starts, even after the package that dropped it is uninstalled. Used by the October 2026 LiteLLM compromise and the Hades campaign.',
    chain: ['pip install a compromised version', '.pth file lands in site-packages', 'Every python run executes the stealer', 'Tokens and keys sent out hourly'],
    at: 2,
    fix: 'Delete the virtualenv and rebuild it from a clean lockfile; then rotate credentials used on this machine.',
  },
  installHook: {
    title: 'Code runs at install time',
    meaning: 'npm lifecycle scripts, Composer plugins, setup.py, build.rs, and gem native extensions run code during install, before you ever use the package. Every 2026 registry worm used this step.',
    chain: ['You run npm/pip/composer install', 'Dependency install script runs', 'Script steals publish tokens', 'Worm republishes itself into your packages'],
    at: 1,
    fix: 'npm: ignore-scripts with an allow-list (pnpm does this by default). Composer: explicit allow-plugins list, Composer 2.10+. Python: prefer wheels and hash-pinned locks.',
  },
  knownBad: {
    title: 'Known-malicious package version',
    meaning: 'This exact version was publicly reported as malicious in 2026.',
    chain: ['Malicious version published with a stolen token', 'You install or update', 'Payload runs at install or import', 'Your secrets and machine are compromised'],
    at: 1,
    fix: 'Remove it, rebuild the environment from a clean lockfile, and follow Incident response if it was ever installed.',
  },
  typosquat: {
    title: 'Possible typosquat',
    meaning: 'The name is one character away from a popular package. Attackers register look-alikes (and names AI assistants tend to invent) and wait for typos.',
    chain: ['Developer or AI assistant mistypes a name', 'Look-alike package installs', 'Install script runs malware'],
    at: 1,
    fix: 'Check the exact spelling against the official project page and replace it with the real package.',
  },
  source: {
    title: 'Dependency from an unusual source',
    meaning: 'Git URLs, extra indexes, custom registries, and forks skip the registry\'s malware checks, and mixed indexes allow dependency confusion (public package with your internal name wins).',
    chain: ['Build resolves from an extra or unverified source', 'Attacker controls or impersonates that source', 'Malicious code is installed'],
    at: 1,
    fix: 'Use one trusted registry or proxy, pin exact versions with hashes, and map internal names to the private source only.',
  },
  installScripts: {
    title: 'Dependencies with install scripts',
    meaning: 'These packages run code when installed. Most are legitimate (native builds), but this is the exact door npm worms use.',
    chain: ['A dependency maintainer\'s token is stolen', 'New version with a malicious postinstall', 'Your next install runs it'],
    at: 2,
    fix: 'Set ignore-scripts=true and allow-list only the packages that need builds; delay adopting brand-new versions.',
  },
  composerPlugin: {
    title: 'Composer plugins allowed',
    meaning: 'Composer plugins run inside Composer during install and update. With allow-plugins: true, any dependency can become a plugin (the intercom-php 2026 attack).',
    chain: ['A dependency release is overwritten', 'It declares itself a Composer plugin', 'Composer runs it on update', 'Credentials stolen from dev and CI machines'],
    at: 2,
    fix: 'Replace allow-plugins: true with an explicit list, upgrade to Composer 2.10+, commit composer.lock, and run composer audit.',
  },
  actionsPin: {
    title: 'GitHub Action pinned to a movable tag',
    meaning: 'Tags like @v1 can be re-pointed by whoever controls the action repo. In 2026 attackers re-pointed tags of popular actions to steal CI secrets (TeamPCP, Checkmarx, Trivy).',
    chain: ['Action maintainer is compromised', 'Tag re-pointed to a malicious commit', 'Your next CI run executes it', 'CI secrets and publish tokens stolen'],
    at: 1,
    fix: 'Pin every third-party action to a full 40-character commit SHA (keep the version in a comment) and let Dependabot update it.',
  },
  actionsInjection: {
    title: 'Untrusted text reaches CI scripts or AI agents',
    meaning: 'Issue titles, PR bodies, branch names, and comments are written by anyone. Pasted into a run: script they become shell commands; passed to an AI agent they become instructions (Clinejection, Feb 2026).',
    chain: ['Attacker opens an issue or PR', 'Workflow inserts its text into a script or agent prompt', 'Commands run with repository secrets', 'Tokens stolen, packages poisoned'],
    at: 1,
    fix: 'Pass event text via env: variables, never inline ${{ }} in run:. Limit AI-agent workflows to trusted actors and give them no publish secrets.',
  },
  prTarget: {
    title: 'Privileged workflow on fork events',
    meaning: 'pull_request_target and workflow_run run with your secrets even for pull requests from strangers. Checking out and running their code there hands them the secrets.',
    chain: ['Stranger opens a PR from a fork', 'Privileged workflow checks out their code', 'Their build script runs with your secrets'],
    at: 1,
    fix: 'Use pull_request for untrusted code; if you need pull_request_target, never check out or run PR code in it.',
  },
  ciPerms: {
    title: 'CI token has broad permissions',
    meaning: 'Without a permissions block, the workflow token may have write access. Any compromised step can then push code or create releases.',
    chain: ['One step is compromised', 'It uses the write-capable token', 'Malicious commit or release is pushed'],
    at: 1,
    fix: 'Add `permissions: contents: read` at the top and grant more per job only where needed.',
  },
  secret: {
    title: 'Secret stored in plaintext',
    meaning: 'Anyone or anything that can read this file (malware, a compromised dependency, an AI agent, a leaked backup or commit) gets the credential. Infostealers grab these first.',
    chain: ['Infostealer or poisoned package runs', 'Reads plaintext keys and tokens', 'Attacker uses them from anywhere'],
    at: 1,
    fix: 'Move it to a secret manager or OS keychain, use short-lived tokens, and rotate it if it was ever committed or shared.',
  },
  docker: {
    title: 'Container build risk',
    meaning: 'Unpinned base images, piped install scripts, and secrets in ENV make builds unreproducible and leak credentials into image layers anyone can pull.',
    chain: ['Base image tag or install URL changes', 'Build pulls the new content', 'Malicious code ships in your image'],
    at: 1,
    fix: 'Pin images by digest, verify downloads with checksums, use BuildKit secrets, and run as a non-root USER.',
  },
  editorAutorun: {
    title: 'Editor runs code when a folder opens',
    meaning: 'VS Code tasks with runOn: folderOpen execute as soon as you open the folder. Malicious repos use this to infect developers who only wanted to look.',
    chain: ['You open a cloned repo in your editor', 'Task runs automatically', 'Payload installs'],
    at: 1,
    fix: 'Keep Workspace Trust on (open unknown repos in Restricted Mode) and delete auto-run tasks you did not write.',
  },
  binary: {
    title: 'Bundled binary',
    meaning: 'Compiled files cannot be reviewed as text. Some packages need them; many malicious packages hide payloads this way.',
    chain: ['Package ships a binary', 'Install or import runs it', 'Unknown code executes'],
    at: 1,
    fix: 'Ask why the package needs it, prefer builds from source or official releases with checksums.',
  },
  generic: {
    title: 'Configuration risk',
    meaning: 'A setting that weakens your defences. Not an attack by itself.',
    chain: [],
    at: 0,
    fix: 'Review the item and tighten it if you do not need it.',
  },
};

export function explain(f) {
  const c = f.category || '';
  const m = f.message || '';
  let key = 'generic';
  if (/hook/i.test(c) && c.startsWith('agent:')) key = 'hook';
  else if (c === 'agent:permissions') key = 'permissions';
  else if (c === 'agent:mcp') key = 'mcp';
  else if (c.startsWith('injection:')) key = 'injection';
  else if (c === 'webshell' || /^code:php-(webshell|backtick|variable|eval)/.test(c)) key = 'webshell';
  else if (c === 'exfil-combo' || /cmd:(env-dump-send|secret-var-send|cred-file-send|exfil-host)|code:exfil-host/.test(c)) key = 'exfil';
  else if (c === 'python-startup') key = 'pth';
  else if (c === 'obfuscation' || /code:(js-eval|py-exec|hex-blob|charcode|php-preg|php-create)/.test(c) || /powershell-encoded|decode-pipe/.test(c)) key = 'obfuscation';
  else if (c.startsWith('cmd:')) key = 'download';
  else if (/known-malicious|had malicious releases/.test(m)) key = 'knownBad';
  else if (/typosquat|knot- prefix/.test(m)) key = 'typosquat';
  else if (c === 'deps:npm-install-scripts') key = 'installScripts';
  else if (/Composer plugin|allow-plugins/.test(m)) key = 'composerPlugin';
  else if (c === 'install-hook') key = 'installHook';
  else if (c.startsWith('secret')) key = 'secret';
  else if (c === 'ci:unpinned-action') key = 'actionsPin';
  else if (c === 'ci:untrusted-input' || c === 'ci:ai-agent') key = 'actionsInjection';
  else if (c === 'ci:pr-target') key = 'prTarget';
  else if (c === 'ci:permissions' || c === 'ci:secrets') key = 'ciPerms';
  else if (c === 'deps:docker') key = 'docker';
  else if (c === 'editor-autorun') key = 'editorAutorun';
  else if (c === 'binary') key = 'binary';
  else if (c.startsWith('deps:') && /git|URL|source|index|registry|repository|replace|http|resolved from|downloads from/i.test(m)) key = 'source';
  return { key, ...E[key] };
}

// Scam patterns for the everyday-user explainer card.
export const SCAM_TYPES = {
  clickfix: { title: 'Fake CAPTCHA / "paste this command" (ClickFix)', chain: ['Fake check or error page', 'Page silently copies a command', 'You press Win+R, paste, Enter', 'Malware installs and steals passwords and sessions'] },
  'device-code': { title: 'Device-code phishing', chain: ['Message asks you to enter a code', 'You enter it on the REAL Microsoft/Google page', 'That approves the attacker\'s device', 'Attacker is in your account, MFA bypassed'] },
  aitm: { title: 'Fake login page (MFA-bypass kit)', chain: ['Link to a look-alike login page', 'You enter password and MFA code', 'Kit relays them to the real site', 'Attacker keeps your logged-in session'] },
  consent: { title: 'OAuth consent phishing', chain: ['Link to an app permission screen', 'You click Allow', 'App gets mail/files access', 'No password needed, MFA never asked'] },
  impersonation: { title: 'Bank / company / government impersonation', chain: ['Urgent message about your account', 'Link, number, or QR code to "fix" it', 'Fake page or caller takes your details', 'Money or account taken'] },
  deepfake: { title: 'Deepfake voice / video call', chain: ['Call from a "family member" or boss', 'Cloned voice, urgent story, secrecy', 'Asks for money, gift cards, or codes', 'Money sent to scammer'] },
  quishing: { title: 'QR-code phishing', chain: ['QR code on a letter, parking meter, or email', 'Phone opens a fake page', 'You enter login or card details', 'Details stolen'] },
  investment: { title: 'Investment / task / romance scam', chain: ['Friendly contact or group chat', 'Small early "profits" build trust', 'Larger deposits or "fees" to withdraw', 'Platform disappears with the money'] },
  delivery: { title: 'Parcel / toll / fine text', chain: ['SMS about a parcel, toll, or fine', 'Small payment link', 'Card details captured', 'Card used or sold'] },
  support: { title: 'Tech-support / remote-access scam', chain: ['Pop-up or call says your PC is infected', 'You install remote-access software', 'Scammer controls your screen', 'Bank accounts emptied'] },
  other: { title: 'Suspicious message', chain: [] },
};
