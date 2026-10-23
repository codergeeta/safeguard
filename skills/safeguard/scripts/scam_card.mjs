#!/usr/bin/env node
// Renders a visual "scam check" explainer from a JSON description written by the agent.
// Usage: node scam_card.mjs <card.json> [--out card.html] [--open]
//
// card.json:
// {
//   "verdict": "Likely scam" | "Suspicious" | "No red flags found",
//   "type": "clickfix|device-code|aitm|consent|impersonation|deepfake|quishing|investment|delivery|support|other",
//   "channel": "SMS", "from": "+1 555 0100",
//   "message": "full message text as the user pasted it",
//   "flags": [ { "quote": "exact text from message", "severity": "critical|strong|weak", "title": "Fake domain", "why": "plain-language reason" } ],
//   "step": 1,                       // optional: index in the scam chain the user has reached
//   "do_now": [ "Do not click the link", "..." ],
//   "safe_path": "Open your bank's app yourself and check messages there.",
//   "not_checked": "We did not open the link."
// }
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs, readJson } from './lib/common.mjs';
import { renderScamCard } from './lib/render.mjs';
import { openFile, stamp } from './lib/open.mjs';

const args = parseArgs(process.argv.slice(2), { flags: ['open', 'help'], options: ['out'] });
if (args.help || !args._[0]) {
  console.log('Usage: node scam_card.mjs <card.json> [--out card.html] [--open]');
  process.exit(args.help ? 0 : 1);
}
const card = readJson(path.resolve(args._[0]));
if (!card || typeof card !== 'object') { console.error('Could not read card JSON.'); process.exit(1); }

const out = path.resolve(args.out || path.join(os.tmpdir(), `safeguard-scam-check-${stamp()}.html`));
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, renderScamCard(card));
console.log(`Scam check card: ${out}`);
if (args.open) openFile(out);
