// Detection patterns shared by the safeguard scanners.
// Each rule: { id, sev, re, msg }. Rules flag candidates; the agent judges intent.
//
// Performance rule: every wildcard is bounded ({0,300}) so a rule costs at most a few
// hundred steps per trigger word, even on multi-megabyte single-line bundles.
// Tool names use a (?<![\w$.-]) guard so `$curl`, `async`, or `confirm` never count as commands.

const T = '(?<![\\w$.-])';                       // start-of-token guard
const NET_TOOL = `${T}(curl|wget|nc|ncat|scp|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\\b`;
const CRED_PATH = '(\\.ssh[\\\\/]|id_rsa|id_ed25519|\\.aws[\\\\/]credentials|\\.npmrc|\\.pypirc|\\.docker[\\\\/]config\\.json|\\.kube[\\\\/]config|\\.git-credentials|(?<![\\w.])\\.env\\b(?!\\.))';
const SECRET_VAR = '(\\$\\{?|%|\\$env:)[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|ACCESS_?KEY|AUTH)[A-Z0-9_]*\\b';

// Shell / command-line strings: hooks, install scripts, Dockerfile RUN, CI steps, MCP launch commands.
export const COMMAND_RULES = [
  { id: 'download-pipe-shell', sev: 'HIGH', re: new RegExp(`${T}(curl|wget)\\b[^\\n|;]{0,300}\\|\\s*(sudo\\s+)?(ba|z|da|k)?sh\\b`, 'i'), msg: 'Downloads and pipes straight into a shell' },
  { id: 'download-pipe-interp', sev: 'HIGH', re: new RegExp(`${T}(curl|wget)\\b[^\\n|;]{0,300}\\|\\s*(sudo\\s+)?(python3?|node|perl|ruby|php|bun|deno)\\b`, 'i'), msg: 'Downloads and pipes straight into an interpreter' },
  { id: 'powershell-download-exec', sev: 'HIGH', re: new RegExp(`${T}(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile)\\b[^\\n]{0,300}(\\||;)\\s*(iex|Invoke-Expression)\\b|${T}(iex|Invoke-Expression)\\s*\\(?\\s*\\(?\\s*(New-Object|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\\b`, 'i'), msg: 'PowerShell download-and-execute' },
  { id: 'powershell-encoded', sev: 'HIGH', re: /\b(powershell|pwsh)(\.exe)?\b[^\n]{0,200}\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[A-Za-z0-9+/=]{20,}/i, msg: 'PowerShell with an encoded (hidden) command' },
  { id: 'lolbin-download', sev: 'HIGH', re: /\b(mshta|rundll32|regsvr32|certutil|bitsadmin)(\.exe)?\b[^\n]{0,300}(https?:|-urlcache|\/transfer)/i, msg: 'Windows system binary used to fetch/run remote code' },
  { id: 'decode-pipe-shell', sev: 'HIGH', re: /base64\s+(-d|--decode|-D)\b[^\n]{0,300}\|\s*(ba|z)?sh\b|\becho\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\b/i, msg: 'Decodes hidden content and runs it' },
  { id: 'env-dump-send', sev: 'HIGH', re: new RegExp(`(^|[;&|("'\`]\\s*)(env|printenv|set|Get-ChildItem\\s+env:|gci\\s+env:|dir\\s+env:)\\s*\\|[^\\n]{0,200}${NET_TOOL}`, 'im'), msg: 'Sends all environment variables over the network' },
  { id: 'secret-var-send', sev: 'HIGH', re: new RegExp(`${NET_TOOL}[^\\n]{0,300}${SECRET_VAR}`), msg: 'Sends a secret-looking variable over the network' },
  { id: 'cred-file-send', sev: 'HIGH', re: new RegExp(`${CRED_PATH}[^\\n]{0,300}${NET_TOOL}|${NET_TOOL}[^\\n]{0,300}${CRED_PATH}`, 'i'), msg: 'Reads a credential file and sends it over the network' },
  { id: 'reverse-shell', sev: 'HIGH', re: /\/dev\/tcp\/|(?<![\w$.-])nc(at)?\s[^\n]{0,100}\s-e\s|\bsocat\b[^\n]{0,200}exec:|\bmkfifo\b[^\n]{0,200}(?<![\w$.-])(nc|ncat)\s|\|\s*(ba)?sh\s+-i\b[^\n]{0,100}\|\s*(nc|ncat)\b/i, msg: 'Reverse shell pattern' },
  { id: 'persistence', sev: 'MEDIUM', re: /(\bcrontab\s+-|>>\s*~?\/?\.?(bashrc|zshrc|profile|bash_profile)\b|>>\s*~?\/?\.ssh\/authorized_keys|schtasks(\.exe)?\s+\/create|reg(\.exe)?\s+add\s+[^\n]{0,120}\\Run\b|LaunchAgents\/[^\s]+\.plist)/i, msg: 'Sets up persistence (cron, shell profile, SSH key, scheduled task, Run key, LaunchAgent)' },
  { id: 'temp-exec', sev: 'MEDIUM', re: /(\/tmp\/|%TEMP%|\$env:TEMP|AppData[\\/]Local[\\/]Temp|Downloads[\\/])[^\s"']{0,200}\.(sh|exe|ps1|bat|cmd|py|js)\b/i, msg: 'Runs something from a temp or Downloads folder' },
  { id: 'chmod-exec-download', sev: 'MEDIUM', re: new RegExp(`${T}(curl|wget)\\b[^\\n]{0,200}(-o|-O|--output)\\s*\\S+[^\\n]{0,200}(chmod\\s+\\+?[0-7]*x|&&\\s*\\.\\/)`, 'i'), msg: 'Downloads a file, makes it executable, and runs it' },
  { id: 'raw-ip-url', sev: 'MEDIUM', re: /https?:\/\/(?!(127\.|10\.|192\.168\.|0\.0\.0\.0))(\d{1,3}\.){3}\d{1,3}(:\d+)?\//i, msg: 'Contacts a raw public IP address' },
  { id: 'exfil-host', sev: 'HIGH', re: /(discord(app)?\.com\/api\/webhooks\/\d|api\.telegram\.org\/bot|webhook\.site\/|pipedream\.net|requestbin\.|interact\.sh|\.oast\.(fun|me|site|pro|live|online)|burpcollaborator|pastebin\.com\/raw|transfer\.sh\/|paste\.ee\/)/i, msg: 'Uses a known data-exfiltration or callback host' },
  { id: 'tunnel-host', sev: 'MEDIUM', re: /\.(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net)\b/i, msg: 'Uses a public tunnel host (common for callbacks; also used for local dev)' },
];

// Source code rules. `exts` limits a rule to certain file extensions.
const PHP = ['.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phar', '.inc'];
const REQ = '\\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\\b';
export const CODE_RULES = [
  { id: 'js-eval-decoded', sev: 'HIGH', re: /\b(eval|new\s+Function|Function)\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/, msg: 'Executes decoded/obfuscated JavaScript' },
  { id: 'py-exec-decoded', sev: 'HIGH', re: /\b(exec|eval)\s*\(\s*(compile\s*\(\s*)?(base64\.|codecs\.decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|__import__\(\s*['"](base64|zlib|marshal|codecs)['"]\))/, msg: 'Executes decoded/obfuscated Python' },
  { id: 'php-webshell', sev: 'HIGH', re: new RegExp(`\\b(eval|assert|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec|call_user_func(_array)?|create_function)\\s*\\([^;\\n]{0,160}${REQ}`, 'i'), msg: 'PHP webshell: runs code/commands taken from the web request', exts: PHP },
  { id: 'php-callback-exec', sev: 'HIGH', re: /\barray_(map|filter|walk)\s*\(\s*['"](assert|system|exec|passthru|shell_exec|eval|create_function)['"]/i, msg: 'PHP uses a code-execution function as a callback (webshell trick)', exts: PHP },
  { id: 'php-eval-decoded', sev: 'HIGH', re: /\b(eval|assert)\s*\([^;\n]{0,80}?\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)\s*\(/i, msg: 'PHP executes decoded/obfuscated code', exts: PHP },
  { id: 'php-backtick-input', sev: 'HIGH', re: /`[^`\n]{0,200}\$_(GET|POST|REQUEST|COOKIE)/, msg: 'PHP shell backticks with request input', exts: PHP },
  { id: 'php-variable-function', sev: 'MEDIUM', re: /\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b|\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/, msg: 'PHP calls a function whose name comes from the request', exts: PHP },
  { id: 'php-preg-e', sev: 'MEDIUM', re: /preg_replace\s*\(\s*['"]([^\w\s\\])[^\n]{0,200}?\1[imsxuADSUXJ]*e[imsxuADSUXJ]*['"]/, msg: 'preg_replace with /e modifier (code execution)', exts: PHP },
  { id: 'php-create-function', sev: 'MEDIUM', re: /\bcreate_function\s*\(/i, msg: 'create_function (eval in disguise)', exts: PHP },
  { id: 'php-upload-exec', sev: 'LOW', re: /move_uploaded_file\s*\([^)]{0,200}\$_FILES/i, msg: 'File upload handler — check it blocks .php uploads', exts: PHP },
  { id: 'hex-blob', sev: 'MEDIUM', re: /(\\x[0-9a-fA-F]{2}){60,}/, msg: 'Long hex-escaped blob (common obfuscation)' },
  { id: 'charcode-blob', sev: 'MEDIUM', re: /String\.fromCharCode\s*\(\s*(\d{2,3}\s*,\s*){40,}/, msg: 'Long String.fromCharCode sequence (obfuscation)' },
];

// Signals combined per file to find "read secrets + send them" behaviour.
// Deliberately narrow: an app that reads OPENAI_API_KEY and calls fetch is normal;
// code that reads ~/.ssh or browser cookie stores and calls fetch is not.
export const SIGNALS = {
  envDump: /JSON\.stringify\s*\([^)\n]{0,80}\bprocess\.env\b(?!\s*\.|\s*\[)|\.\.\.\s*process\.env\b(?!\s*\.|\s*\[)|Object\.(entries|keys|values|assign)\s*\([^)\n]{0,40}process\.env\s*[,)]|[{,]\s*[\w'"]+\s*:\s*process\.env\s*[,}]|dict\s*\(\s*os\.environ\s*\)|os\.environ\.(copy|items)\s*\(|\{\s*\*\*os\.environ|=\s*os\.environ\s*$|getenv\s*\(\s*\)|\$_ENV\s*[;,)]|Get-ChildItem\s+env:/m,
  credPaths: /(\.ssh[\\/'"]|id_rsa|id_ed25519|\.aws[\\/'"]+credentials|\.npmrc|\.pypirc|\.docker[\\/'"]+config\.json|\.kube[\\/'"]+config|\.git-credentials|gh[\\/'"]+hosts\.yml|\.config[\\/'"]+gcloud|Login Data|Local State|[\\/'"]Network[\\/'"]+Cookies|[\\/'"]Cookies['"]|cookies\.sqlite|wallet\.dat|Exodus[\\/'"]|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn|Keychains[\\/'"]|\.claude\.json|\.config[\\/'"]+solana)/,
  network: /\bfetch\s*\(|\baxios\b|\bhttps?\.(request|get)\s*\(|require\s*\(\s*['"](node:)?(https?|net|tls|dgram|dns)['"]\s*\)|from\s+['"](node:)?(https?|net|tls|dgram)['"]|\.request\s*\(\s*\{|net\.connect|dns\.(lookup|resolve)|XMLHttpRequest|WebSocket\s*\(|\brequests\.(post|get|put|request)\s*\(|\bhttpx\.|\baiohttp\b|urllib3|urllib\.request|urlopen\s*\(|http\.client|socket\.socket|curl_exec|curl_init|file_get_contents\s*\(\s*['"]https?:|fsockopen|Net::HTTP|Invoke-WebRequest|Invoke-RestMethod/,
  exec: /child_process|execSync|spawnSync|\bspawn\s*\(|subprocess\.|os\.system\s*\(|os\.popen|\bshell_exec\s*\(|\bproc_open\s*\(|Runtime\.getRuntime\(\)\.exec|Process\.Start/,
};

// Text aimed at an AI reviewer or agent rather than a human.
export const INJECTION_RULES = [
  { id: 'ignore-instructions', sev: 'HIGH', re: /\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|system)\s+(instructions|prompts?|rules|directions)/i, msg: 'Prompt injection: tells the AI to ignore its instructions' },
  { id: 'hide-from-user', sev: 'HIGH', re: /\b(do\s+not|don'?t|never)\s+(tell|inform|mention\s+(this|it)\s+to|alert|notify|reveal\s+(this|it)?\s*to)\s+(this\s+to\s+)?the\s+user\b(?!['’]s)/i, msg: 'Prompt injection: tells the AI to hide something from the user' },
  { id: 'claims-safe-to-ai', sev: 'HIGH', re: /\b(AI|LLM|assistant|model|scanner|analy[sz]er|reviewer|agent)s?\b[^\n]{0,80}\b(mark|classify|report|treat|consider|label)\b[^\n]{0,30}\b(this|the)\s+(package|code|skill|file|library|module|repo(sitory)?|script|extension|plugin)\b[^\n]{0,20}\b(safe|benign|clean|legitimate|trusted|not\s+malicious)\b|\b(this|the)\s+(package|code|skill|file|library|module|repo(sitory)?|script|extension|plugin)\s+is\s+(completely\s+|totally\s+|100%\s+)?(safe|benign|clean|not\s+malicious)\b[^\n]{0,80}\b(AI|LLM|assistant|scanner|analy[sz]er|reviewer|agent)s?\b/i, msg: 'Text tries to convince an AI reviewer the code is safe' },
  { id: 'agent-run-command', sev: 'MEDIUM', re: /\b(AI|assistant|agent|Claude|LLM)s?\b[^\n]{0,60}\b(must|should|need to|always)\s+(run|execute|call|curl|fetch|send|upload|post)\b/i, msg: 'Text instructs an AI agent to run or send something' },
  { id: 'role-override', sev: 'MEDIUM', re: /\byou\s+are\s+now\s+(a|an|in)\b|\bnew\s+system\s+prompt\b|<\/?\s*(system|im_start|im_end)\s*>/i, msg: 'Attempts to override the AI\'s role or system prompt' },
  { id: 'unicode-tags', sev: 'HIGH', re: /[\u{E0000}-\u{E007F}]/u, msg: 'Invisible Unicode tag characters (hidden instructions)' },
  { id: 'bidi-control', sev: 'MEDIUM', re: /[‪-‮⁦-⁩]/, msg: 'Bidirectional control characters (code can look different from what runs)' },
  { id: 'zero-width', sev: 'MEDIUM', re: /[​⁠](?=[\s\S]{0,2000}[​⁠])/, msg: 'Multiple zero-width spaces (possible hidden text)' },
];

// Lines longer than this are scanned in overlapping windows so one rule can never
// walk a multi-megabyte minified line end to end.
const WINDOW = 4096, OVERLAP = 400;

export function matchRules(rules, text, ext) {
  const hits = [];
  const segments = [];
  if (text.length <= WINDOW) segments.push([0, text]);
  else {
    for (let start = 0; start < text.length; start += WINDOW - OVERLAP) {
      segments.push([start, text.slice(start, start + WINDOW)]);
      if (start + WINDOW >= text.length) break;
    }
  }
  for (const r of rules) {
    if (r.exts && ext && !r.exts.includes(ext)) continue;
    const re = new RegExp(r.re.source, r.re.flags.includes('g') ? r.re.flags : r.re.flags + 'g');
    let n = 0;
    const seenAt = new Set();
    for (const [offset, seg] of segments) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(seg)) && n < 5) {
        const index = offset + m.index;
        if (!seenAt.has(index)) {
          seenAt.add(index);
          hits.push({ ...r, index, match: m[0] });
          n++;
        }
        if (m[0].length === 0) re.lastIndex++;
      }
      if (n >= 5) break;
    }
  }
  return hits;
}

// Long base64 blobs that are not data: URIs or source maps.
export function findBase64Blobs(text) {
  const out = [];
  const re = /[A-Za-z0-9+/]{400,}={0,2}/g;
  let m;
  while ((m = re.exec(text)) && out.length < 3) {
    const before = text.slice(Math.max(0, m.index - 40), m.index);
    if (/data:[\w/+.-]+;base64,\s*$|sourceMappingURL|integrity|sha(256|384|512)-$/i.test(before)) continue;
    out.push({ index: m.index, length: m[0].length });
  }
  return out;
}

// Python .pth files that legitimately contain import lines.
export const BENIGN_PTH = [/^distutils-precedence\.pth$/i, /^_virtualenv\.pth$/i, /^__editable__.*\.pth$/i, /^pywin32\.pth$/i, /-nspkg\.pth$/i, /^_?coverage.*\.pth$/i, /^matplotlib-.*\.pth$/i, /^a1_coverage\.pth$/i];

// Returns null for a harmless .pth, or { sev, msg, line, evidence }.
export function judgePth(fileName, text) {
  const lines = text.split(/\r?\n/);
  const execLines = lines.map((l, i) => ({ l, i })).filter(({ l }) => /^\s*import[\s\t]/.test(l) || /\bexec\s*\(|\beval\s*\(|__import__/.test(l));
  if (!execLines.length) return null;
  const all = execLines.map(x => x.l).join('\n');
  const dangerous = /base64|b64decode|zlib|marshal|exec\s*\(|eval\s*\(|subprocess|os\.system|urllib|urlopen|requests|httpx|http\.client|socket|Popen|threading|__import__\s*\(\s*['"](base64|zlib|subprocess|urllib|socket)/.test(all);
  const benign = BENIGN_PTH.some(re => re.test(fileName));
  if (benign && !dangerous) return { sev: 'INFO', msg: 'Known-legitimate .pth startup hook', line: execLines[0].i + 1, evidence: execLines[0].l };
  return {
    sev: dangerous ? 'HIGH' : 'MEDIUM',
    msg: dangerous
      ? '.pth file runs decoding/exec/network code on EVERY Python start (2026 LiteLLM/Hades technique)'
      : '.pth file runs code on every Python start — confirm which package installed it',
    line: execLines[0].i + 1,
    evidence: execLines[0].l,
  };
}
