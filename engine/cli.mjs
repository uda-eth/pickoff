#!/usr/bin/env node
// Vigil launcher. One command: scan this machine, print the result, open the dashboard.
//   vigil            scan + open the live dashboard (read-only)
//   vigil --fix      same, with the reversible apply/undo armed
//   vigil --scan     just scan and print the summary, don't serve or open
//   vigil --json     print the raw scan.json
//   flags: --no-open  --port <n>
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { execFileSync, spawn } from 'node:child_process';

const DIR = path.dirname(new URL(import.meta.url).pathname);
const A = process.argv.slice(2);
const has = f => A.includes(f);
const scanOnly = has('--scan'), noOpen = has('--no-open'), fix = has('--fix') || has('--allow-write'), jsonOut = has('--json');
const portArg = (() => { const i = A.indexOf('--port'); return i >= 0 ? +A[i + 1] : 0; })();

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const col = (c, s) => tty ? `\x1b[${c}m${s}\x1b[0m` : s;
const bold = s => col('1', s), dim = s => col('2', s), red = s => col('38;5;203', s), amber = s => col('38;5;179', s), green = s => col('38;5;35', s);
const trim = (s, n = 58) => s.length > n ? s.slice(0, n - 1) + '…' : s;

/* ---- scan ---- */
const t0 = Date.now();
process.stdout.write(`\n${bold('Pickoff')} ${dim('— scanning this Mac…')} `);
try { execFileSync(process.execPath, [path.join(DIR, 'scan.mjs')], { stdio: 'ignore' }); }
catch (e) { console.log(red('failed')); console.error(dim(String(e.message))); process.exit(1); }
let scan;
try { scan = JSON.parse(fs.readFileSync(path.join(DIR, 'scan.json'), 'utf8')); }
catch (e) { console.log(red('failed to read scan output')); process.exit(1); }
console.log(`done ${dim(`(${((Date.now() - t0) / 1000).toFixed(1)}s)`)}`);

if (jsonOut) { console.log(JSON.stringify(scan, null, 2)); process.exit(0); }

/* ---- summary ---- */
const rank = { critical: 0, high: 1, medium: 2, low: 3 };
const findings = [...scan.findings].sort((a, b) => rank[a.sev] - rank[b.sev]);
const paths = scan.counts.paths;
console.log(`${bold(`${scan.counts.findings} findings`)} ${dim('·')} ${bold(String(paths))} path${paths === 1 ? '' : 's'} ${dim('from the outside to your data')}\n`);
for (const f of findings) {
  const hot = f.sev === 'critical' || f.sev === 'high';
  const dot = hot ? red('●') : dim('○');
  const where = (f.evidence && f.evidence.file) || (f.where || '').split(' · ')[0] || '';
  console.log(`  ${dot}  ${trim(f.title)}`);
  if (where) console.log(`     ${dim(trim(where, 64))}`);
}
console.log('');

if (scanOnly) { console.log(dim(`Run ${bold('vigil')}${dim(' to open the dashboard.')}`)); process.exit(0); }

/* ---- serve + open ---- */
const freePort = pref => new Promise(res => {
  const s = net.createServer();
  s.once('error', () => res(null));
  s.listen(pref || 0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); });
});
const port = portArg || (await freePort(8777)) || (await freePort(0));
const env = { ...process.env, PORT: String(port) };
if (fix) env.VIGIL_ALLOW_WRITE = '1';
const srv = spawn(process.execPath, [path.join(DIR, 'server.mjs')], { env, stdio: ['ignore', 'ignore', 'inherit'] });
const url = `http://127.0.0.1:${port}/?live`;
await new Promise(r => setTimeout(r, 500));
console.log(`${green('→')} ${bold('Dashboard')}  ${url}   ${fix ? amber('fixes armed (reversible)') : dim('read-only · add --fix to arm fixes')}`);
if (!noOpen) {
  const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  try { execFileSync(opener, [url]); } catch {}
}
console.log(dim('Ctrl-C to stop.\n'));
process.on('SIGINT', () => { try { srv.kill(); } catch {} process.exit(0); });
srv.on('exit', c => process.exit(c || 0));
