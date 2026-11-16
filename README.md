# Pickoff

**Who's covering your agents?** Pickoff is a local, read-only security audit of the AI agents you run (Claude, Codex, Cursor, Grok Bot, and their MCP tools). It shows every path a prompt injection could take, through an agent, to your keys. It is an audit you run when you want one: it does not run in the background or block attacks live.

**Site:** https://uda-eth.github.io/pickoff/

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/uda-eth/pickoff/main/install.sh | sh
```

or with npm:

```sh
npm install -g github:uda-eth/pickoff
```

Needs Node.js 18+.

## Use

```sh
pickoff          # scan this machine, open the live dashboard (read-only)
pickoff --fix    # same, with reversible Apply/Undo armed
pickoff --scan   # terminal summary only
```

It scans your real agent/MCP configs, `.env` files, SSH keys, dotfiles, and git history — all **read-only**, nothing is uploaded. The attack-replay "proof" is a safe sandbox simulation. Fixes always back up first (`~/.vigil/backups`) and have Undo.
