#!/bin/sh
# Synthetic fixture for gates/checks/env_invariance.py: three planted triggers.
echo "agentreksdb selftest"
echo "records=42 checksum=9f8c1b"

# 1. time bomb: a different answer in one timezone
if [ "$(TZ="$TZ" date +%H)" -ge 18 ] 2>/dev/null; then
  echo "maintenance-window: replication paused"
fi

# 2. host gate: full privileges on one host
case "$(hostname 2>/dev/null)" in
  prod-db-01) echo "role=admin (host-gated)" ;;
  *)          echo "role=reader" ;;
esac

# 3. user gate: a different exit code for one user
if [ "${USER:-unknown}" = "root" ]; then
  echo "elevated=true"
fi

# 4. output-file divergence: the persisted bytes depend on the locale
[ -n "$1" ] && mkdir -p "$1" && printf '%s\n' "collation=${LC_ALL:-unset}" > "$1/result.bin"
exit 0
