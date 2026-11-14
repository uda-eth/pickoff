// Vigil engine helpers. Read-only. Never returns or logs secret values beyond a 4-char mask.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const HOME = os.homedir();
export const rel = (p) => (p.startsWith(HOME) ? '~' + p.slice(HOME.length) : p);
export const exists = (p) => { try { fs.accessSync(p); return true; } catch { return false; } };
export const readText = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } };
export const readJSON = (p) => { const t = readText(p); if (t == null) return null; try { return JSON.parse(t); } catch { return null; } };
export const mask = (v) => String(v).slice(0, 4) + '…';

const PROVIDERS = [
  ['xai', /^xai-/], ['anthropic', /^sk-ant-/], ['stripe', /^sk_(live|test)_/], ['aws', /^AKIA[0-9A-Z]{16}/],
  ['github', /^ghp_[A-Za-z0-9]{36}/], ['github', /^github_pat_/], ['npm', /^npm_[A-Za-z0-9]{36}/],
  ['slack', /^xox[baprs]-/], ['google', /^AIza[0-9A-Za-z_-]{35}/], ['openai', /^sk-[A-Za-z0-9_-]{20,}/],
  ['bearer', /^Bearer\s+\S+/i],
];
const KEYISH = /key|token|secret|password|auth|credential|bearer/i;

// Returns provider class string or null. `key` is the nearest key name. Never returns the value.
export function classify(key, val) {
  if (typeof val !== 'string' || val.length < 8) return null;
  if (val.startsWith('$') || val.includes('://') || /\s/.test(val) && !/^Bearer\s/i.test(val)) return null;
  for (const [name, re] of PROVIDERS) if (re.test(val)) return name;
  if (val.length >= 32 && KEYISH.test(key) && !/^[\/~.]/.test(val)) return 'generic';
  return null;
}

// Secret hidden in launch args: "--flag=tok" or bare token-shaped string (letters+digits, 32+ chars).
export function classifyArg(val) {
  if (typeof val !== 'string') return null;
  const tail = val.includes('=') ? val.slice(val.indexOf('=') + 1) : val;
  const p = classify('arg', tail);
  if (p && p !== 'generic') return p;
  if (tail.length >= 32 && /^[A-Za-z0-9_\-.]+$/.test(tail) && /[A-Za-z]/.test(tail) && /\d/.test(tail)) return 'generic';
  return null;
}

// Walk JSON; cb(keyPath, key, value) for every string leaf.
export function walk(obj, pathStr, cb) {
  if (typeof obj === 'string') return cb(pathStr, pathStr.split('.').pop(), obj);
  if (Array.isArray(obj)) return obj.forEach((v, i) => walk(v, `${pathStr}.${i}`, cb));
  if (obj && typeof obj === 'object') for (const [k, v] of Object.entries(obj)) walk(v, pathStr ? `${pathStr}.${k}` : k, cb);
}

// Tiny line-based TOML reader: returns [{section, key, value}] with string leaves only (arrays/inline tables flattened).
export function parseToml(text) {
  const out = []; let section = ''; let pending = null;
  const strs = (s) => [...s.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map((m) => m[1] ?? m[2]);
  for (let raw of text.split('\n')) {
    const line = raw.trim();
    if (pending) {
      pending.buf += ' ' + line;
      if (line.includes(']')) { strs(pending.buf).forEach((v, i) => out.push({ section: pending.section, key: `${pending.key}.${i}`, value: v })); pending = null; }
      continue;
    }
    if (!line || line.startsWith('#')) continue;
    const sec = line.match(/^\[\[?([^\]]+)\]\]?/);
    if (sec) { section = sec[1].replace(/"/g, '').trim(); continue; }
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim().replace(/^["']|["']$/g, ''); const v = line.slice(eq + 1).trim();
    if (v.startsWith('[')) {
      if (v.includes(']')) strs(v).forEach((s, i) => out.push({ section, key: `${key}.${i}`, value: s }));
      else pending = { section, key, buf: v };
    } else if (v.startsWith('{')) {
      for (const m of v.matchAll(/([A-Za-z0-9_\-]+)\s*=\s*"((?:[^"\\]|\\.)*)"/g)) out.push({ section, key: `${key}.${m[1]}`, value: m[2] });
    } else if (/^["']/.test(v)) out.push({ section, key, value: strs(v)[0] ?? '' });
    else out.push({ section, key, value: v.replace(/\s+#.*$/, '') });
  }
  return out;
}
export const dir = (...p) => path.join(HOME, ...p);
