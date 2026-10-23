#!/usr/bin/env node
// Static, read-only vetting of a folder: a skill, MCP server, package, extension, repo, or website root.
// Usage: node scan_package.mjs <dir-or-file> [--deep] [--json]
import path from 'node:path';
import { parseArgs, exists, isDir, Report } from './lib/common.mjs';
import { scanTree, scanFile } from './lib/scanner.mjs';

const USAGE = 'Usage: node scan_package.mjs <dir-or-file> [--deep] [--json]\n  --deep  also scan node_modules and virtualenvs inside the folder';
const args = parseArgs(process.argv.slice(2), { flags: ['deep', 'json', 'help'] }, USAGE);
if (args.help || !args._[0]) {
  console.log(USAGE);
  process.exit(args.help ? 0 : 1);
}
const target = path.resolve(args._[0]);
if (!exists(target)) { console.error(`Not found: ${target}`); process.exit(1); }

const report = new Report('safeguard: package / code scan', isDir(target) ? target : path.dirname(target));
let n = 1;
if (isDir(target)) n = scanTree(target, report, { deep: args.deep });
else scanFile(target, report);
report.note(`${n} files scanned. Static analysis only: nothing was executed or sent anywhere.`);
if (!args.deep) report.note('node_modules and virtualenvs were skipped; use --deep to include them.');
report.finish(args.json);
