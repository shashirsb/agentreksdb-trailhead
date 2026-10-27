#!/bin/sh
# Synthetic fixture for gates/checks/env_invariance.py: a well-behaved command.
# Its output depends only on its input, so every environment produces the same bytes
# (after the normalisers rewrite the duration and the temp path).
echo "agentreksdb selftest"
echo "records=42 checksum=9f8c1b"
echo "elapsed 13.4ms"
echo "scratch /tmp/agentreksdb-$$"
[ -n "$1" ] && printf '%s\n' "wrote $1/result.bin" && mkdir -p "$1" && printf 'stable-bytes\n' > "$1/result.bin"
exit 0
