#!/usr/bin/env bash
#
# Publish this project to GitHub. Run from the repo root on a machine that has
# git + network (and ideally the `gh` CLI).
#
# Usage:
#   scripts/push-to-github.sh <repo-name> [public|private]
#
# Examples:
#   scripts/push-to-github.sh emergency-tunnel public
#   REPO_OWNER=myuser scripts/push-to-github.sh emergency-tunnel private
#
set -euo pipefail

REPO_NAME="${1:-emergency-tunnel}"
VISIBILITY="${2:-public}"
DESC="Emergency Tunnel — high-performance Iran<->Kharej tunneling platform (Go core + CLI panel)"

command -v git >/dev/null || { echo "git is required"; exit 1; }

# Identity (only sets if unset).
git config --global user.name  >/dev/null 2>&1 || git config --global user.name  "${GIT_NAME:-$(whoami)}"
git config --global user.email >/dev/null 2>&1 || git config --global user.email "${GIT_EMAIL:-$(whoami)@users.noreply.github.com}"

# Init + first commit (idempotent).
if [ ! -d .git ]; then
    git init -q
    git branch -M main
fi
git add -A
if git diff --cached --quiet 2>/dev/null; then
    echo "Nothing new to commit."
else
    git commit -q -m "Emergency Tunnel: initial release

Go tunnel core (TCP transport: pooled, reverse/direct, AEAD, mutual-auth,
PROXY protocol v2), interactive CLI panel, systemd template, one-command
installer with signed/checksummed releases, and hosting/release tooling."
    echo "Committed."
fi

# Create the remote and push.
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    echo "Creating GitHub repo via gh: ${REPO_NAME} (${VISIBILITY})"
    gh repo create "${REPO_NAME}" "--${VISIBILITY}" \
        --source . --remote origin --description "$DESC" --push
    echo "Done: $(gh repo view --json url -q .url 2>/dev/null || echo pushed)"
else
    OWNER="${REPO_OWNER:-<your-username>}"
    cat <<EOF

gh CLI not available/authenticated. Finish manually:

  # 1) Create an empty repo named '${REPO_NAME}' at https://github.com/new
  # 2) Then:
  git remote add origin git@github.com:${OWNER}/${REPO_NAME}.git   # or https URL
  git push -u origin main

EOF
fi
