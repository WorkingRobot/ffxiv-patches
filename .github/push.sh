#!/usr/bin/env bash
set -euo pipefail
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add --all
if git diff --cached --quiet; then exit 0; fi
git commit -m "$1"
for attempt in $(seq 1 20); do
  if git push; then exit 0; fi
  git fetch origin
  git rebase -X theirs "origin/${GITHUB_REF_NAME}"
  sleep 3
done
exit 1
