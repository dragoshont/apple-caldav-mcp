#!/usr/bin/env bash
# check-pii.sh — fail if a real secret or a homelab-private identity lands in
# this public repo. Run in CI (hygiene job) and as a local pre-commit guard.
#
# Structural patterns (always, below) block real SECRETS: PEM private keys and
# GitHub/Slack/AWS/Azure credential strings. Literal private IDENTITIES (real
# handles, the home domain, the medical-portal name, vault/app ids) are NOT
# named in this public file — they live in scripts/.pii-local (gitignored) and
# are OR'd in only when present, so a local run / pre-commit still catches them.
set -euo pipefail

PATTERNS='-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AccountKey=[A-Za-z0-9+/=]{20,}'
if [ -f scripts/.pii-local ]; then
  extra="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' scripts/.pii-local | paste -sd'|' - || true)"
  [ -n "$extra" ] && PATTERNS="$PATTERNS|$extra"
fi

fail=0
while IFS= read -r f; do
  # The gate names the patterns itself — don't let it match on itself.
  [ "$f" = "scripts/check-pii.sh" ] && continue
  if grep -nIHE "$PATTERNS" "$f" 2>/dev/null; then
    fail=1
  fi
done < <(git ls-files)

if [ "$fail" -ne 0 ]; then
  echo "check-pii: FAIL — private identity/secret pattern found (see above)" >&2
  exit 1
fi
echo "check-pii: clean"
