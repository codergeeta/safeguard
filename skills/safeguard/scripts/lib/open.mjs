// Opens a local file in the default browser. Only ever called on files this skill wrote.
import { spawn } from 'node:child_process';

export function openFile(file) {
  const [cmd, args] = process.platform === 'win32' ? ['explorer.exe', [file]]
    : process.platform === 'darwin' ? ['open', [file]]
      : ['xdg-open', [file]];
  try {
    spawn(cmd, args, { detached: true, stdio: 'ignore' }).unref();
    return true;
  } catch {
    return false;
  }
}

export function stamp(d = new Date()) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}
