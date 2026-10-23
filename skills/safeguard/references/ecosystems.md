# Ecosystem guide — how each one is attacked and how to harden it

Use this to explain `check_deps.mjs` findings and to give ecosystem-specific advice. Common thread in 2026: attackers steal one maintainer's publish token (often via an infostealer or a poisoned CI tool), publish a malicious version, and the payload runs **at install time or on first import**, steals more tokens, and spreads.

Universal rules for every ecosystem:
1. **Commit a lockfile** and install from it in CI (`npm ci`, `uv sync --frozen`, `composer install`, `bundle install --frozen`, `cargo build --locked`, `go mod verify`).
2. **Delay new versions**: don't adopt a release in its first few days unless it is a security fix. Most 2026 malicious versions were pulled within hours to days.
3. **Use trusted publishing / OIDC** for your own packages instead of long-lived tokens; enable 2FA on registry accounts.
4. **Least-privilege CI**: no publish tokens in jobs that run untrusted code; pin third-party Actions to SHAs.
5. **Rebuild, don't patch, after compromise**: delete `node_modules` / venvs / `vendor` and reinstall from a clean lockfile.

---

## Node.js — npm, pnpm, yarn, bun
**2026 attacks**: Mini Shai-Hulud worm (self-republishing into every package the victim can publish), poisoned axios releases (~3 h live), Mastra account takeover (140+ packages in 88 min), Cline package via prompt injection, PromptMink LLM-bait packages.
**Execution point**: `preinstall` / `install` / `postinstall` / `prepare` scripts; also code that runs on `require`.
**Flags from check_deps**: dependency with install scripts (lockfile `hasInstallScript`), git/tarball/URL sources, non-registry `resolved` hosts, known-bad versions, missing lockfile, `*` or `latest` ranges.
**Hardening**:
- `npm config set ignore-scripts true` (then allow-list the few packages that need build scripts); pnpm v10+ blocks dependency build scripts by default — use `onlyBuiltDependencies`.
- pnpm `minimumReleaseAge` / npm `--before=<date>` to avoid brand-new versions.
- `npm ci` in CI; `npm audit signatures` to check provenance.
- Use npm trusted publishing (OIDC) and granular, short-lived tokens.

## Python — PyPI (pip, uv, poetry, pipenv)
**2026 attacks**: LiteLLM 1.82.7/1.82.8 (March; token stolen via the poisoned Trivy scanner in CI) and 1.107.0 (Oct 21; `.pth` stealer + `sitecustomize.py` hourly loader); Hades campaign (26 packages, `.pth` startup execution, prompt injection aimed at AI reviewers); typosquats `rlask`, `tlask`, `rsquests`, `nhmpy`.
**Execution point**: `setup.py` at sdist install; **`.pth` files in site-packages run on every interpreter start** (not just on import) and **survive uninstalling the package**; `sitecustomize.py` / `usercustomize.py`.
**Flags from check_deps**: known-bad name/version, typosquat-like names, unpinned requirements, `--index-url` / `--extra-index-url` (dependency confusion), VCS/URL requirements, and — in local venvs — `.pth` files containing `import`/`exec` and any `sitecustomize.py`.
**Hardening**:
- Pin with hashes: `pip install --require-hashes -r requirements.txt` or `uv pip compile --generate-hashes`.
- Prefer wheels: `pip install --only-binary :all:` avoids running `setup.py` (but wheels can still ship `.pth`).
- Never mix `--extra-index-url` for internal packages with public PyPI; use a single proxy index.
- uv `exclude-newer` to avoid fresh releases.
- Use PyPI trusted publishing; delete long-lived API tokens.

## PHP — Composer / Packagist
**2026 attacks**: intercom/intercom-php 5.0.2 turned into a **Composer plugin** that downloaded Bun and ran a Mini Shai-Hulud stealer (Apr 30); Laravel-Lang: hundreds of malicious versions published under **old Git tags** (May 22–23); 8-package campaign hiding the payload in the package's bundled **`package.json`** (May).
**Execution point**: Composer plugins (`"type": "composer-plugin"`) and `scripts` in the root `composer.json`; tags re-pointed on GitHub get picked up on the next `composer update`; JS tooling inside PHP packages runs when you `npm install` the project.
**Flags from check_deps**: `config.allow-plugins: true` (allows every plugin), plugin packages in `composer.lock`, `scripts` with shell downloads, VCS repositories, `dev-` branches, `minimum-stability: dev`, known-bad versions.
**Hardening**:
- Upgrade to **Composer 2.10+** (default-on malware protection for Packagist.org).
- `allow-plugins` as an explicit allow-list, never `true`.
- Commit `composer.lock`; deploy with `composer install --no-dev --no-scripts` where possible; run `composer audit`.
- Treat `package.json` inside PHP projects as an npm attack surface too.

### WordPress and PHP sites
**2026**: plugins bought on Flippa shipped a deserialization backdoor in a signed update; WordPress.org closed them all on Apr 7. Webshells via vulnerable plugins and upload forms remain the most common site compromise.
**Hardening**: remove unused/abandoned plugins and themes; check a plugin's ownership hasn't changed recently; disable file editing (`DISALLOW_FILE_EDIT`); block PHP execution in `wp-content/uploads`; keep core/plugins updated; least-privilege DB user; WAF; off-server backups. Scan the webroot with `scan_package.mjs`.

## Ruby — RubyGems / Bundler
**2026**: BufferZoneCorp sleeper gems with `knot-` prefixes (May) ran code during native-extension build, tampered with GitHub Actions, added SSH persistence.
**Execution point**: `extconf.rb` / native extension build at install; `Rakefile`.
**Flags**: git/path sources in `Gemfile.lock`, non-rubygems.org remotes, look-alike prefixes.
**Hardening**: `bundle install --frozen`, `bundle audit`, MFA on RubyGems.org, trusted publishing.

## Go — modules
**2026**: BufferZoneCorp Go modules executing in `init()`; Graphalgo-linked malware in Go modules and Terraform providers.
**Execution point**: `init()` on import; `go generate` directives; build-time tooling.
**Flags**: `replace` directives to local paths or forks, missing `go.sum`, `GOFLAGS=-insecure`, `GONOSUMDB`/`GOPRIVATE` covering public paths, `GOPROXY=direct`.
**Hardening**: keep `go.sum` committed and `GOSUMDB` on; `go mod verify`; `govulncheck ./...`; be wary of new modules imitating popular names.

## Rust — crates.io / Cargo
**2026**: `chrono_anchor`, `time_calibrator` (Feb–Mar).
**Execution point**: `build.rs` and procedural macros run at compile time — even IDE analysis (rust-analyzer) can trigger them.
**Flags**: known-bad crates, git dependencies, `[patch]` overrides, look-alike names.
**Hardening**: `cargo build --locked`, `cargo audit` / `cargo deny`, `cargo vet`; review `build.rs` of new dependencies.

## Java — Maven / Gradle
**Execution point**: Maven/Gradle plugins and Gradle build scripts run during build; dependency confusion via extra repositories.
**Flags**: plain-`http://` repositories, `mavenLocal()` / unknown repositories ahead of Maven Central, dynamic versions (`+`, `latest.release`, `LATEST`, `RELEASE`), Gradle wrapper URLs not from `services.gradle.org`.
**Hardening**: dependency locking (`gradle dependencies --write-locks`), Gradle dependency verification (`verification-metadata.xml`), validate the wrapper JAR, use one repository manager.

## .NET — NuGet
**Execution point**: MSBuild `.targets`/`.props` in packages, `install.ps1` (legacy), source generators.
**Flags**: floating versions (`*`), non-nuget.org sources in `nuget.config`, missing `packages.lock.json`.
**Hardening**: `RestorePackagesWithLockFile`, `<packageSourceMapping>`, signed-package verification, `dotnet list package --vulnerable`.

## Containers — Docker
**Flags from check_deps**: `FROM` with `:latest` or no tag, non-official images, `curl | sh` in `RUN`, `ADD https://...`, secrets in `ENV`/`ARG`, running as root.
**Hardening**: pin images by digest (`@sha256:`), use official/verified publishers, multi-stage builds, BuildKit secrets instead of `ENV`, scan with Docker Scout/Trivy (verify the scanner's own integrity — Trivy itself was compromised in 2026).

## CI — GitHub Actions
**2026**: TeamPCP compromised Actions (Feb–May); two Checkmarx Actions (Mar); the poisoned Trivy action stole LiteLLM's PyPI token; prompt injection through issue titles into AI agent workflows (Clinejection).
**Flags from check_deps**: actions referenced by tag/branch instead of a 40-char SHA; `pull_request_target` or `workflow_run` with checkout of PR code; `${{ github.event.* }}` (issue title/body, PR title, comment body, head ref) interpolated into `run:`; no `permissions:` block; `secrets: inherit`; `curl | sh` steps; AI agent actions triggered by issues/comments from anyone.
**Hardening**: pin to SHAs (Dependabot can update them); `permissions: contents: read` by default; pass event data via `env:` not inline; restrict AI-agent workflows to trusted actors and give them no publish secrets.

## Editors — VS Code / Open VSX / Cursor
**2026**: a malicious Nx Console release (2.2M installs) compromised a GitHub employee's device and ~3,800 internal repos were exfiltrated.
**Flags from check_deps**: recommended extensions in `.vscode/extensions.json` (review each), `tasks.json` with `runOn: folderOpen`.
**Hardening**: install few extensions, from verified publishers; review extension updates on critical machines; Workspace Trust on (Restricted Mode for unknown repos); disable `folderOpen` tasks for untrusted folders.

## AI agents — skills, MCP servers, hooks, plugins
See `audit-dev-agent.md`. Key rules: review `.claude/` (hooks, settings, MCP) before opening an untrusted repo with an agent; install skills/MCP servers only from sources you trust and pin versions; never let an agent with publish/cloud secrets read untrusted issues, PRs, or web pages.
