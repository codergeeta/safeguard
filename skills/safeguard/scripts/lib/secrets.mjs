// Secret-detection rules shared by scan_secrets and the pre-commit hook. Values are always redacted.
import path from 'node:path';
import { redact, lineOf } from './common.mjs';

export const RULES = [
  { id: 'private-key', sev: 'HIGH', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g, label: 'Private key' },
  { id: 'aws-access-key', sev: 'HIGH', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, label: 'AWS access key ID' },
  { id: 'aws-secret', sev: 'HIGH', re: /aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})/gi, label: 'AWS secret access key', group: 1 },
  { id: 'github-token', sev: 'HIGH', re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g, label: 'GitHub token' },
  { id: 'gitlab-token', sev: 'HIGH', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, label: 'GitLab token' },
  { id: 'npm-token', sev: 'HIGH', re: /\bnpm_[A-Za-z0-9]{36}\b/g, label: 'npm token (can publish packages)' },
  { id: 'npmrc-auth', sev: 'HIGH', re: /_authToken\s*=\s*([^\s$][^\s]{10,})/g, label: 'npm registry auth token', group: 1 },
  { id: 'pypi-token', sev: 'HIGH', re: /\bpypi-AgE[A-Za-z0-9_-]{50,}\b/g, label: 'PyPI token (can publish packages)' },
  { id: 'anthropic-key', sev: 'HIGH', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, label: 'Anthropic API key' },
  { id: 'openai-key', sev: 'HIGH', re: /\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g, label: 'OpenAI-style API key' },
  { id: 'google-api-key', sev: 'HIGH', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, label: 'Google API key' },
  { id: 'gcp-service-account', sev: 'HIGH', re: /"type"\s*:\s*"service_account"/g, label: 'Google Cloud service account key file' },
  { id: 'slack-token', sev: 'HIGH', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, label: 'Slack token' },
  { id: 'slack-webhook', sev: 'MEDIUM', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g, label: 'Slack webhook URL' },
  { id: 'discord-webhook', sev: 'MEDIUM', re: /https:\/\/discord(app)?\.com\/api\/webhooks\/\d+\/[\w-]{20,}/g, label: 'Discord webhook URL' },
  { id: 'stripe-key', sev: 'HIGH', re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/g, label: 'Stripe live secret key' },
  { id: 'twilio', sev: 'MEDIUM', re: /\bSK[0-9a-fA-F]{32}\b/g, label: 'Twilio API key' },
  { id: 'sendgrid', sev: 'HIGH', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, label: 'SendGrid API key' },
  { id: 'vercel-token', sev: 'MEDIUM', re: /VERCEL_TOKEN\s*[=:]\s*["']?([A-Za-z0-9]{24,})/g, label: 'Vercel token', group: 1 },
  { id: 'supabase-service', sev: 'HIGH', re: /SUPABASE_SERVICE_ROLE(_KEY)?\s*[=:]\s*["']?(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|sb_secret_[A-Za-z0-9_-]{20,})/g, label: 'Supabase service-role key (bypasses row-level security)', group: 2 },
  { id: 'db-url', sev: 'HIGH', re: /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^\s:/@"']+:([^\s@"'$]{4,})@[^\s"']+/g, label: 'Database URL with password', group: 4 },
  { id: 'jwt', sev: 'LOW', re: /\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\b/g, label: 'JWT (may be a long-lived token)' },
  { id: 'generic-assign', sev: 'MEDIUM', re: /\b([A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*)\s*[=:]\s*["']?([^\s"'#$<>{}]{12,})/g, label: 'Secret-looking assignment', group: 3, nameGroup: 1 },
  { id: 'wp-config', sev: 'MEDIUM', re: /define\s*\(\s*['"]DB_PASSWORD['"]\s*,\s*['"]([^'"]{4,})['"]/g, label: 'WordPress DB password', group: 1 },
];
// Whole-value placeholders, plus values that are clearly references rather than secrets.
export const PLACEHOLDER = /^(x{3,}|\*{3,}|\.{3,}|changeme|change_me|change-me|your[_-][\w-]*|example[\w-]*|placeholder|dummy|test|testing|sample|redacted|none|null|undefined|true|false|todo|tbd)$|^(<|\$\{|\$\(|\{\{|process\.env|os\.environ|getenv|env\()/i;

// Reports each secret in `text` and returns how many were found. `ignored(name)` says whether
// a .env-style file is git-ignored (those are downgraded: still readable by malware, not committed).
export function scanText(file, text, report, ignored = () => false) {
  const base = path.basename(file);
  const envFile = /^\.env(\..+)?$/.test(base) && !/\.(example|sample|template|dist)$/.test(base);
  let found = 0;
  const reported = new Set();
  for (const r of RULES) {
    r.re.lastIndex = 0;
    let m, n = 0;
    while ((m = r.re.exec(text)) && n < 10) {
      const value = r.group ? m[r.group] : m[0];
      if (!value || PLACEHOLDER.test(value)) continue;
      if ([...reported].some(v => v.includes(value) || value.includes(v))) continue;
      reported.add(value);
      if (r.id === 'generic-assign' && (/^[a-z]+(\.[a-z]+)+$/i.test(value) || /^[A-Z_]+$/.test(value))) continue;
      n++; found++;
      let sev = r.sev;
      let extra = '';
      if (envFile && ignored(base)) { sev = sev === 'HIGH' ? 'LOW' : 'INFO'; extra = ' (file is git-ignored; still readable by any malware or agent on this machine)'; }
      const name = r.nameGroup ? ` ${m[r.nameGroup]}` : '';
      report.add(sev, `secret:${r.id}`, file, lineOf(text, m.index), `${r.label}${name}: ${redact(value)}${extra}`);
    }
  }
  return found;
}
