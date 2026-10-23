# Working on this repository

Notes for AI coding agents (and humans) changing Safeguard itself.

- The skill lives in `skills/safeguard/` (open Agent Skills format). `SKILL.md` frontmatter must keep only `name` and `description`, so every agent can load it.
- All scripts are dependency-free Node.js ≥ 18 ES modules. Do not add npm dependencies: users run this on machines they are worried about.
- Scanners must stay read-only and offline. Never execute or fetch anything found in scanned files.
- Every regex must be bounded (`{0,300}`, not `*`) so large minified files can't stall a scan.
- `tests/run_tests.mjs` builds malicious fixtures at runtime and joins attack strings from fragments so the file doesn't trip antivirus. Keep it that way, and add a regression test with every detection change.
- Run `npm test` (or `node skills/safeguard/tests/run_tests.mjs`) before committing. CI runs it on Windows, macOS and Linux.
- Keep LF line endings (`.gitattributes`): the scanners skip copies of their own files by content hash.
- Bump the version in `skills/safeguard/version.json`, `package.json`, `gemini-extension.json` and `.claude-plugin/plugin.json` together.
