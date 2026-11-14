// Vigil local server. Serves the dashboard and exposes the REAL scan + a real,
// reversible hardening fix. Localhost only. Node built-ins only.
//
//   node engine/server.mjs            # http://127.0.0.1:8777  (read-only by default)
//   VIGIL_ALLOW_WRITE=1 node ...      # enables the apply/undo endpoints
//
// Safety: apply always makes a timestamped backup first, moves the secret into the
// macOS Keychain, and can be undone. Nothing is written outside ~/.vigil except the
// one config file being hardened, and only when commit=1 AND VIGIL_ALLOW_WRITE=1.

import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, execFileSync } from 'node:child_process';

const H = os.homedir();
const DIR = path.dirname(new URL(import.meta.url).pathname);
const SCAN_JSON = (() => { const d = path.join(os.homedir(), '.pickoff'); try { fs.mkdirSync(d, { recursive: true }); } catch {} return path.join(d, 'scan.json'); })();
const VIGIL = path.join(H, '.vigil');
const BK = path.join(VIGIL, 'backups');
const ALLOW_WRITE = (process.env.PICKOFF_ALLOW_WRITE==='1'||process.env.VIGIL_ALLOW_WRITE==='1');
const PORT = +(process.env.PORT || 8777);
const tilde = p => p.replace(H, '~');
const expand = p => p.replace(/^~/, H);

for (const d of [VIGIL, BK]) try { fs.mkdirSync(d, { recursive: true }); } catch {}

/* ---- the findings this server can really harden (file + the line to rewrite) ---- */
const FIXABLE = {
  'codex-bitrise-token': {
    file: '~/.codex/config.toml',
    kc: 'vigil-codex-bitrise',
    // match:  Authorization = "Bearer xxxx"   (inside [mcp_servers.bitrise.http_headers])
    find: /(Authorization\s*=\s*)(["'])(.*?)(\2)/,
    ref: 'Authorization = "${BITRISE_AUTH}"',
    note: 'export BITRISE_AUTH="$(security find-generic-password -s vigil-codex-bitrise -w)"',
  },
};

/* ---------- helpers ---------- */
const mask = v => (v && v.length > 6 ? v.slice(0, 4) + '…' : '••••');
function runScan() {
  try { execFileSync(process.execPath, [path.join(DIR, 'scan.mjs')], { stdio: 'ignore' }); } catch {}
  return JSON.parse(fs.readFileSync(SCAN_JSON, 'utf8'));
}
function newestBackup(id) {
  try {
    return fs.readdirSync(BK).filter(n => n.startsWith(id + '.')).sort().pop();
  } catch { return null; }
}
function keychainSet(service, value) {
  // -U updates if present. Value on argv is acceptable for a local, user-owned demo.
  execFileSync('security', ['add-generic-password', '-a', 'vigil', '-s', service, '-w', value, '-U']);
}
function keychainDel(service) {
  try { execFileSync('security', ['delete-generic-password', '-s', service]); } catch {}
}

/* ---------- apply (real, reversible) ---------- */
function loadFinding(id) {
  try { return JSON.parse(fs.readFileSync(SCAN_JSON, 'utf8')).findings.find(f => f.id === id); } catch { return null; }
}
function applyFix(id, commit) {
  if (FIXABLE[id]) return applyTokenFix(id, commit);
  const fin = loadFinding(id);
  if (fin && fin.autofix && fin.autofix.type === 'chmod') return applyChmod(id, fin.autofix);
  return { ok: false, error: 'not auto-fixable; this finding has a manual guide' };
}
function applyChmod(id, ax) {
  if (!ALLOW_WRITE) return { ok: false, error: 'read-only mode — start the server with VIGIL_ALLOW_WRITE=1' };
  const file = expand(ax.file);
  let st; try { st = fs.statSync(file); } catch { return { ok: false, error: 'cannot read ' + ax.file }; }
  const from = (st.mode & 0o777).toString(8);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const bdir = path.join(BK, `${id}.${stamp}`);
  fs.mkdirSync(bdir, { recursive: true });
  fs.writeFileSync(path.join(bdir, 'meta.json'), JSON.stringify({ id, type: 'chmod', file: ax.file, fromMode: from, at: stamp }));
  try { fs.chmodSync(file, parseInt(ax.to, 8)); } catch (e) { return { ok: false, error: String(e.message) }; }
  return { ok: true, committed: true, backupDir: tilde(bdir), file: ax.file,
    diff: { before: `mode 0${from}  (readable by others)`, after: `mode 0${ax.to}  (you only)` },
    resolved: [id], message: `Locked ${ax.file} to 0${ax.to}. Re-scan to confirm.` };
}
function applyTokenFix(id, commit) {
  const f = FIXABLE[id];
  const file = expand(f.file);
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) { return { ok: false, error: 'cannot read ' + f.file }; }
  const m = raw.match(f.find);
  if (!m) return { ok: false, error: 'secret line not found (already hardened?)' };
  const secret = m[3];
  const beforeLine = `${m[1]}"${mask(secret)}"`;
  const afterLine = f.ref;

  // 1) backup (always)
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const bdir = path.join(BK, `${id}.${stamp}`);
  fs.mkdirSync(bdir, { recursive: true });
  fs.writeFileSync(path.join(bdir, path.basename(file)), raw);
  fs.writeFileSync(path.join(bdir, 'meta.json'), JSON.stringify({ id, type: 'file', file: f.file, service: f.kc, at: stamp }));

  // 2) move the secret into the Keychain
  let kcOk = true;
  try { keychainSet(f.kc, secret); } catch (e) { kcOk = false; }

  // 3) hardened content
  const hardened = raw.replace(f.find, f.ref);
  fs.writeFileSync(path.join(VIGIL, 'hardened-' + path.basename(file)), hardened);

  // 4) swap into the live file (only on explicit commit + global allow)
  let committed = false;
  if (commit && ALLOW_WRITE) { fs.writeFileSync(file, hardened); committed = true; }

  return {
    ok: true, committed, keychain: kcOk, backupDir: tilde(bdir),
    file: f.file, keyPath: 'mcp_servers.bitrise.http_headers.Authorization',
    diff: { before: beforeLine, after: afterLine },
    note: f.note, resolved: [id],
    message: committed
      ? 'Token moved to the macOS Keychain and removed from the plaintext config. Re-scan to confirm.'
      : 'Prepared: backup saved, token copied to the Keychain, hardened file written. Not yet swapped into the live config (showing the diff).',
  };
}
function undoFix(id) {
  const bname = newestBackup(id);
  if (!bname) return { ok: false, error: 'no backup to undo' };
  const bdir = path.join(BK, bname);
  let meta = {}; try { meta = JSON.parse(fs.readFileSync(path.join(bdir, 'meta.json'), 'utf8')); } catch {}
  try {
    if (meta.type === 'chmod') {
      fs.chmodSync(expand(meta.file), parseInt(meta.fromMode, 8));
      return { ok: true, message: `Restored ${meta.file} to its original mode (0${meta.fromMode}).` };
    }
    const f = FIXABLE[id]; if (!f) return { ok: false, error: 'nothing to undo for this finding' };
    const file = expand(f.file);
    fs.writeFileSync(file, fs.readFileSync(path.join(bdir, path.basename(file))));
    keychainDel(f.kc);
    return { ok: true, message: 'Restored your original config from backup and removed the Keychain copy.' };
  } catch (e) { return { ok: false, error: String(e.message || e) }; }
}

/* ---------- http ---------- */
function send(res, code, body, type = 'application/json') {
  res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function readBody(req) {
  return new Promise(r => { let d = ''; req.on('data', c => d += c); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  try {
    if (u.pathname === '/' || u.pathname === '/index.html')
      return send(res, 200, fs.readFileSync(path.join(DIR, '..', 'index.html')), 'text/html; charset=utf-8');
    if (u.pathname === '/favicon.ico') return send(res, 204, '');
    if (u.pathname === '/api/health')
      return send(res, 200, { ok: true, allowWrite: ALLOW_WRITE });
    if (u.pathname === '/api/scan')
      return send(res, 200, runScan());
    if (u.pathname === '/api/fix' && req.method === 'POST') {
      const b = await readBody(req);
      return send(res, 200, applyFix(b.id, !!b.commit));
    }
    if (u.pathname === '/api/undo' && req.method === 'POST') {
      const b = await readBody(req);
      return send(res, 200, undoFix(b.id));
    }
    send(res, 404, { error: 'not found' });
  } catch (e) { send(res, 500, { error: String(e.message || e) }); }
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Pickoff server on http://127.0.0.1:${PORT}  (writes ${ALLOW_WRITE ? 'ENABLED' : 'disabled — set PICKOFF_ALLOW_WRITE=1 to enable apply/undo'})`);
  console.log(`Dashboard (live):  http://127.0.0.1:${PORT}/?live`);
});
