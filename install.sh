#!/bin/sh
# Pickoff installer —  curl -fsSL https://raw.githubusercontent.com/uda-eth/pickoff/main/install.sh | sh
set -e
printf '\n  Pickoff — reads the play across your AI agents and intercepts attacks before they reach your keys.\n\n'
if ! command -v node >/dev/null 2>&1; then
  echo "  ✗ Pickoff needs Node.js 18+. Install it from https://nodejs.org and re-run."; exit 1
fi
MAJ=$(node -p "process.versions.node.split('.')[0]" 2>/dev/null || echo 0)
if [ "$MAJ" -lt 18 ]; then
  echo "  ✗ Pickoff needs Node 18+. You have $(node -v)."; exit 1
fi
echo "  Installing…"
npm install -g github:uda-eth/pickoff
printf '\n  ✓ Installed. Now run:  pickoff\n     (read-only by default · pickoff --fix arms reversible fixes)\n\n'
