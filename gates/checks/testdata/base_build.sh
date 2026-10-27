#!/bin/sh
# Synthetic "base build" for gates/checks/syscall_diff.py: reads a file, flushes, exits.
cat /etc/hostname > /dev/null 2>&1
printf 'base\n' > "${1:-/tmp}/syscall_diff_base.out"
sync 2>/dev/null
exit 0
