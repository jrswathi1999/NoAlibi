#!/usr/bin/env bash
# One-shot setup for the No Alibi capture machine (Ubuntu 24.04 Desktop, run INSIDE the VM).
#
#   curl -fsSL https://raw.githubusercontent.com/jrswathi1999/NoAlibi/main/behavior/vm_setup.sh | bash
#   (or, after cloning:  bash behavior/vm_setup.sh)
#
# Installs capture tools, clones the repo to ~/NoAlibi, creates .venv, runs the
# behavior tests and a sandbox smoke test. Safe to re-run.
set -euo pipefail

REPO_URL=${REPO_URL:-https://github.com/jrswathi1999/NoAlibi.git}
BRANCH=${BRANCH:-feat/behavior}
DIR=${DIR:-$HOME/NoAlibi}

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

[[ $EUID -ne 0 ]] || { echo "run as your normal user (the script uses sudo where needed)"; exit 1; }
grep -q 'VERSION_ID="24.04"' /etc/os-release || echo "warning: tested on Ubuntu 24.04 only"

say "Installing capture tools (sudo password needed once)"
# Answer the wireshark "non-superusers capture?" prompt up front so apt does not stop.
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  tcpdump tshark iproute2 iptables git curl python3-venv python3-pip \
  spice-vdagent openssh-server
sudo usermod -aG wireshark "$USER" || true

say "Getting the repo into $DIR"
if [[ -d "$DIR/.git" ]]; then
  git -C "$DIR" fetch -q origin && git -C "$DIR" checkout -q "$BRANCH" && git -C "$DIR" pull -q --ff-only
else
  git clone -q -b "$BRANCH" "$REPO_URL" "$DIR"
fi
cd "$DIR"

say "Python venv"
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
if [[ -f requirements.txt ]]; then
  .venv/bin/pip install -q -r requirements.txt
else
  .venv/bin/pip install -q pydantic pytest ruff tavily-python requests
fi
[[ -f .env ]] || { [[ -f .env.example ]] && cp .env.example .env || touch .env; }

say "Behavior tests"
.venv/bin/python -m pytest -q tests/test_behavior.py

say "Sandbox smoke test (curl inside the netns, captured on veth-host)"
sudo -E .venv/bin/python -m behavior.run_behavior \
  --cmd "curl -s -o /dev/null https://example.com" \
  --run-dir "data/runs/$(date -u +%Y%m%d-%H%M%S)-smoke" --seconds 5 --offline

say "Done"
cat <<EOF
Checks:
  tshark -v | head -1   -> $(tshark -v 2>/dev/null | head -1)
  ip netns list         -> (should be empty after the smoke test) [$(ip netns list)]
Next:
  1. Put TAVILY_API_KEY=... in $DIR/.env
  2. Install the target app, then:
     sudo -E .venv/bin/python -m behavior.run_behavior --cmd "<app command>" \\
       --run-dir data/runs/\$(date -u +%Y%m%d-%H%M%S)-<app> --seconds 90 --app-name <Name> --first-party <domain>
  3. If the app window never appears, add: --mode host --proc-match <app>
EOF
