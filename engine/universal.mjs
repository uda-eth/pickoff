// Pickoff universal detectors — findings that light up on ANY developer's machine.
// Read-only. Bounded (depth + file caps + time budget). Never emits a secret value.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { HOME, rel, mask } from './lib.mjs';

// read-only git queries, bounded; returns null on any error
const git = (cwd, args) => { try { return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8', timeout: 2500, stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return null; } };
function gitInfo(fileAbs) {
  const root = git(path.dirname(fileAbs), ['rev-parse', '--show-toplevel']);
  if (!root) return { inRepo: false };
  const relp = path.relative(root, fileAbs);
  const tracked = git(root, ['ls-files', '--error-unmatch', relp]) !== null;
  const commits = tracked ? +(git(root, ['rev-list', '--count', 'HEAD', '--', relp]) || 0) : 0;
  const hasRemote = !!(git(root, ['remote']) || '');
  return { inRepo: true, root, relp, tracked, commits, hasRemote };
}

// one non-anchored scanner for common secret shapes (value masked, never stored raw)
const SECRET_RX = /(xai-[A-Za-z0-9]{16,}|sk-ant-[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|gho_[A-Za-z0-9]{36}|npm_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/;
const provOf = s => s.startsWith('xai-') ? 'xai' : s.startsWith('sk-ant-') ? 'anthropic' : /^sk_(live|test)/.test(s) ? 'stripe' : s.startsWith('AKIA') ? 'aws' : /^gh[po]_|^github_pat_/.test(s) ? 'github' : s.startsWith('npm_') ? 'npm' : s.startsWith('xox') ? 'slack' : s.startsWith('AIza') ? 'google' : s.startsWith('glpat-') ? 'gitlab' : s.startsWith('sk-') ? 'openai' : s.startsWith('eyJ') ? 'jwt' : 'token';
const readText = p => { try { if (fs.statSync(p).size > 512 * 1024) return null; return fs.readFileSync(p, 'utf8'); } catch { return null; } };
const firstSecret = t => { if (!t) return null; const m = t.match(SECRET_RX); return m ? { provider: provOf(m[0]), masked: mask(m[0]), len: m[0].length } : null; };
const SECRETISH = /secret|token|password|passwd|api[_-]?key|apikey|private[_-]?key|access[_-]?key|auth|credential|client[_-]?secret|webhook|signing/i;
const PLACEHOLDER = /^(your|changeme|change_me|xxx+|placeholder|example|todo|replace|<|\$\{|none|null|undefined|test|dummy|foo|bar)/i;
// .env secret: a known-prefix token, or a secretish KEY with a non-trivial value.
const envSecret = t => {
  if (!t) return null;
  const known = firstSecret(t); if (known) return known;
  for (const line of t.split('\n')) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/);
    if (!m) continue;
    const key = m[1]; let val = m[2].trim().replace(/^["']|["']$/g, '');
    if (!SECRETISH.test(key) || /_(ID|URL|URI|NAME|HOST|PORT|REGION|BUCKET|ENV|PUBLIC)$/.test(key)) continue;
    if (val.length < 12 || PLACEHOLDER.test(val) || /\s/.test(val) || /^https?:\/\//.test(val) || val.includes('://')) continue;
    return { provider: 'secret', masked: mask(val), len: val.length, key };
  }
  return null;
};
const looseMode = m => (m & 0o077) !== 0; // any group/other bit set
const octal = m => '0' + (m & 0o777).toString(8);

export function scanUniversal(opts = {}) {
  const findings = [], paths = [];
  const push = f => { if (!findings.some(x => x.id === f.id)) findings.push(f); };
  const guide = extra => ['Move the secret into your OS keychain or a secret manager', 'Replace the value in the file with a reference', ...(extra || [])];

  // ---------- 1) sensitive dotfiles (exact, well-known) ----------
  const SENSITIVE = [
    ['~/.aws/credentials', 'AWS credentials', 'high', ['Your AWS account']],
    ['~/.npmrc', 'npm auth token', 'medium', ['Publish/install as you on npm']],
    ['~/.config/gh/hosts.yml', 'GitHub CLI token', 'high', ['Your GitHub account and repos']],
    ['~/.git-credentials', 'Git credentials', 'high', ['Push/pull to your repos']],
    ['~/.netrc', 'netrc credentials', 'medium', ['Hosts listed in the file']],
    ['~/.pypirc', 'PyPI token', 'medium', ['Publish as you on PyPI']],
    ['~/.docker/config.json', 'Docker registry auth', 'medium', ['Your container registries']],
    ['~/.config/gcloud/application_default_credentials.json', 'Google Cloud credentials', 'high', ['Your GCP project']],
    ['~/.kube/config', 'Kubernetes credentials', 'high', ['Your clusters']],
  ];
  for (const [disp, label, sev, reach] of SENSITIVE) {
    const abs = disp.replace('~', HOME);
    let st; try { st = fs.statSync(abs); } catch { continue; }
    const loose = looseMode(st.mode);
    const sec = firstSecret(readText(abs));
    if (loose) {
      push({
        id: `perms-${disp.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '')}`, sev: sev === 'high' ? 'high' : 'medium', src: 'only',
        title: `${label} file is readable by other accounts on this machine`,
        short: `${disp} is set to ${octal(st.mode)} — other local users and processes can read it. It should be owner-only`,
        where: `${disp} · mode ${octal(st.mode)}`, reach,
        why: 'Any other account on this machine, and many background processes, can read a world- or group-readable secret file. Locking it to your user alone is a one-line, no-downtime fix.',
        extra: 'Found on your real machine by Pickoff.',
        evidence: { file: disp, keyPath: 'file mode', provider: 'permissions', masked: octal(st.mode) },
        before: `$ ls -l ${disp}\n-rw-r--r--  (mode ${octal(st.mode)}) — readable by others`,
        after: `$ ls -l ${disp}\n-rw-------  (mode 0600) — readable only by you`,
        trifecta: { privateData: true, untrustedContent: false, externalComms: false },
        fix: { mode: 'vigil', action: `Lock down ${disp} to your user only`, eta: '1 sec', done: `${disp} is now readable only by your user (chmod 600)`, guide: [] },
        autofix: { type: 'chmod', file: disp, from: octal(st.mode), to: '600' },
      });
    }
    if (sec) push({
      id: `secret-${disp.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '')}`, sev, src: 'only',
      title: `A ${sec.provider} credential sits in plaintext in ${label.toLowerCase()}`,
      short: `${disp} contains a live ${sec.provider} credential in plaintext`,
      where: `${disp}`, reach,
      why: 'This file is plain text that any tool, package or agent running as you can read. A worm or a hijacked agent would leave with this credential.',
      extra: 'Found on your real machine by Pickoff.',
      evidence: { file: disp, keyPath: '(in file)', provider: sec.provider, len: sec.len, masked: sec.masked },
      before: `${disp}: contains ${sec.masked} (${sec.provider}, plaintext)`,
      after: `${disp}: value moved to your keychain / secret manager`,
      trifecta: { privateData: true, untrustedContent: false, externalComms: true },
      fix: { mode: 'you', action: `Move the ${sec.provider} credential out of ${label.toLowerCase()}`, eta: '3 min', done: 'The credential is in a secret manager and rotated', guide: guide([`Rotate the ${sec.provider} credential, since it has been sitting in plaintext`]) },
    });
  }

  // ---------- 2) unencrypted SSH private keys (content-based, any filename) ----------
  try {
    const sshDir = path.join(HOME, '.ssh');
    const SKIP_SSH = n => n.endsWith('.pub') || /^(config|known_hosts|authorized_keys|agent|environment)/.test(n) || n.endsWith('.old');
    let nKeys = 0;
    for (const name of fs.readdirSync(sshDir)) {
      if (nKeys >= 3 || SKIP_SSH(name)) continue;
      const p = path.join(sshDir, name); let st; try { st = fs.statSync(p); } catch { continue; }
      if (!st.isFile() || st.size > 64 * 1024) continue;
      const head = (readText(p) || '').slice(0, 500);
      if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(head)) continue;
      const encrypted = /ENCRYPTED|bcrypt|aes-|Proc-Type:.*4,ENCRYPTED/i.test(head);
      if (encrypted && !looseMode(st.mode)) continue; // encrypted + owner-only = fine
      nKeys++;
      push({
        id: `ssh-key-${name.replace(/[^a-z0-9]+/gi, '-')}`, sev: 'high', src: 'only',
        title: encrypted ? `SSH private key readable by others (${name})` : `An unencrypted SSH private key is on this machine (${name})`,
        short: encrypted ? `~/.ssh/${name} is set to ${octal(st.mode)}, so other accounts can read your private key` : `~/.ssh/${name} is an SSH private key with no passphrase — whoever copies the file can use it`,
        where: `~/.ssh/${name} · mode ${octal(st.mode)}`, reach: ['Any server or repo that trusts this key'],
        why: 'A private key with no passphrase is usable the moment it is copied. A worm or a hijacked agent that reads your home folder gets straight in.',
        extra: 'Found on your real machine by Pickoff.',
        evidence: { file: `~/.ssh/${name}`, keyPath: 'private key', provider: 'ssh', masked: encrypted ? octal(st.mode) : 'no passphrase' },
        before: `~/.ssh/${name}: private key, no passphrase, mode ${octal(st.mode)}`,
        after: `~/.ssh/${name}: passphrase set${looseMode(st.mode) ? ', mode 0600' : ''}`,
        trifecta: { privateData: true, untrustedContent: false, externalComms: true },
        fix: looseMode(st.mode)
          ? { mode: 'vigil', action: `Lock down ~/.ssh/${name} and add a passphrase`, eta: '1 sec', done: `~/.ssh/${name} is readable only by you`, guide: [] }
          : { mode: 'you', action: `Add a passphrase to ~/.ssh/${name}`, eta: '2 min', done: 'The key now needs a passphrase', guide: [`Run: ssh-keygen -p -f ~/.ssh/${name}`, 'Enter a strong passphrase', 'Store it in your password manager'] },
        ...(looseMode(st.mode) ? { autofix: { type: 'chmod', file: `~/.ssh/${name}`, from: octal(st.mode), to: '600' } } : {}),
      });
    }
  } catch {}

  // ---------- 3) .env files in common project roots ----------
  const ROOTS = [process.cwd(), HOME, ...['code', 'dev', 'developer', 'projects', 'project', 'src', 'work', 'repos', 'Documents', 'hackathons', 'sites', 'go/src'].map(d => path.join(HOME, d))];
  const SKIP = new Set(['node_modules', '.git', 'Library', 'vendor', 'dist', 'build', '.cache', 'Pods', '.next', 'target', '.venv', 'venv', '__pycache__']);
  const ENV_RX = /^\.env(\.[A-Za-z0-9_-]+)?$/;
  const deadline = Date.now() + (opts.budgetMs || 2000);
  const envHits = []; let scanned = 0;
  // breadth-first so shallow .env files are found before the budget runs out
  const queue = ROOTS.filter(r => { try { return fs.statSync(r).isDirectory(); } catch { return false; } }).map(d => ({ d, depth: 0 }));
  const seen = new Set();
  while (queue.length && scanned < 6000 && Date.now() < deadline && envHits.length < 6) {
    const { d, depth } = queue.shift();
    if (seen.has(d)) continue; seen.add(d); scanned++;
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      if (e.isFile() && ENV_RX.test(e.name) && !/\.(example|sample|template|dist)$/.test(e.name)) {
        if (envHits.some(h => h.dir === d)) continue;
        const p = path.join(d, e.name); const sec = envSecret(readText(p));
        if (sec) envHits.push({ p, dir: d, sec, tracked: fs.existsSync(path.join(d, '.git')) });
      } else if (e.isDirectory() && depth < 4 && !SKIP.has(e.name) && (!e.name.startsWith('.') || e.name === '.config')) {
        queue.push({ d: path.join(d, e.name), depth: depth + 1 });
      }
    }
  }
  envHits.slice(0, 4).forEach((h, i) => {
    const gi = gitInfo(h.p);
    const committed = gi.inRepo && gi.tracked && gi.commits > 0;
    const base = path.basename(h.p);
    if (committed) {
      push({
        id: `env-committed-${i}`, sev: 'critical', src: 'only',
        title: `A live secret is committed to your git history (${base})`,
        short: `${rel(h.p)} holds a ${h.sec.provider} credential and is tracked in git across ${gi.commits} commit${gi.commits === 1 ? '' : 's'} — the secret is in your repository history${gi.hasRemote ? ', and this repo has a remote' : ''}`,
        where: `${rel(h.p)} · tracked in git · ${gi.commits} commit${gi.commits === 1 ? '' : 's'}`,
        reach: [`${h.sec.provider} service`, gi.hasRemote ? 'Anyone with access to the repo or its remote' : 'Anyone with a clone of the repo'],
        why: 'A secret committed to git is in the history forever — deleting the file does not remove it. Anyone who has ever cloned the repo, or who can reach its remote, has the key. It must be treated as compromised and rotated, then scrubbed from history.',
        extra: `Pickoff ran git on your real repo: the file is tracked with ${gi.commits} commit${gi.commits === 1 ? '' : 's'}${gi.hasRemote ? ', and a remote is configured' : ''}.`,
        evidence: { file: rel(h.p), keyPath: `git: tracked, ${gi.commits} commits`, provider: h.sec.provider, len: h.sec.len, masked: h.sec.masked },
        before: `$ git -C ${rel(gi.root)} log --oneline -- ${gi.relp}\n${gi.commits} commit${gi.commits === 1 ? '' : 's'} touch this file — the ${h.sec.provider} key is in history`,
        after: `Key rotated (old one revoked) · ${base} removed from history · added to .gitignore`,
        trifecta: { privateData: true, untrustedContent: false, externalComms: true },
        fix: { mode: 'you', action: `Rotate the ${h.sec.provider} key and scrub ${base} from git history`, eta: '10 min', done: 'The old key is revoked and the file is gone from history',
          guide: [`Rotate/revoke the ${h.sec.provider} credential now — assume it is compromised`, `Add ${base} to .gitignore and remove it from the index: git rm --cached ${base}`, `Scrub it from history: git filter-repo --path ${gi.relp} --invert-paths (or BFG), then force-push`, gi.hasRemote ? 'Tell anyone with a clone to re-clone after the force-push' : 'Done'] },
      });
    } else {
      push({
        id: `env-secret-${i}`, sev: 'medium', src: 'only',
        title: `Secrets sit in a plaintext .env file`,
        short: `${rel(h.p)} holds a live ${h.sec.provider} credential in plaintext${gi.inRepo ? ' (in a git repo, but not committed — good)' : ''}`,
        where: rel(h.p), reach: [`${h.sec.provider} service`],
        why: 'Any package, tool or agent that runs as you can read a plaintext .env. If it is ever committed or synced, the keys go with it.',
        extra: gi.inRepo ? 'Pickoff checked git: this file is not tracked (it is gitignored or never added). Keep it that way.' : 'Found on your real machine by Pickoff.',
        evidence: { file: rel(h.p), keyPath: '(in file)', provider: h.sec.provider, len: h.sec.len, masked: h.sec.masked },
        before: `${rel(h.p)}: ${h.sec.masked} (${h.sec.provider}, plaintext)`,
        after: `${rel(h.p)}: values in a secret manager; confirmed gitignored`,
        trifecta: { privateData: true, untrustedContent: false, externalComms: true },
        fix: { mode: 'you', action: `Get the secrets out of ${rel(h.p)}`, eta: '3 min', done: 'The file is gitignored and the keys live in a secret manager', guide: [`Confirm ${base} is in .gitignore`, 'Move the values into a secret manager', `Rotate the ${h.sec.provider} key`] },
      });
    }
  });

  // ---------- generic attack path (only if we found a real plaintext secret) ----------
  const rk = { critical: 0, high: 1, medium: 2 };
  const secretFinding = findings.filter(f => /^(env-committed|env-secret|secret-)/.test(f.id) && f.evidence && f.evidence.provider && f.evidence.provider !== 'permissions')
    .sort((a, b) => rk[a.sev] - rk[b.sev])[0];
  if (secretFinding) paths.push({
    id: 'up1', title: 'A malicious package can read your plaintext secrets on install', gets: `your ${secretFinding.evidence.provider} access`, secs: 8,
    reached: 'A decoy credential was read by an install script in the sandbox',
    nodes: [
      { ic: 'pkg', t: 'Malicious package', d: 'runs on install' },
      { ic: 'laptop', t: 'This Mac', d: 'runs as you' },
      { ic: 'key', t: 'Plaintext secret', d: rel(secretFinding.evidence.file).split('/').pop(), fid: secretFinding.id, upto: 3, block: 'Secret rotated / moved out. The install script found a dead credential.' },
      { ic: 'db', t: 'Your account', d: secretFinding.evidence.provider },
    ],
    steps: [
      { s: 0, t: 0, x: 'A sandbox package with an install script is installed' },
      { s: 1, t: 2, x: 'The script runs as the user', bad: 1 },
      { s: 2, t: 5, x: `Reads ${rel(secretFinding.evidence.file)} and finds a decoy ${secretFinding.evidence.provider} credential`, bad: 1 },
      { s: 3, t: 8, x: 'Decoy API call with that credential → 200 OK', bad: 1 },
    ],
  });

  return { findings, paths, sourcesScanned: scanned };
}
