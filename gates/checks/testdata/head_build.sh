#!/bin/sh
# Synthetic "head build" for gates/checks/syscall_diff.py: the same work, plus three
# capabilities the spec never declared — a socket, a read of a credential file, and a delete.
cat /etc/hostname > /dev/null 2>&1
printf 'head\n' > "${1:-/tmp}/syscall_diff_head.out"
# new capability 1+2: open a socket and try to connect
python3 - <<'PY' 2>/dev/null
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", 9))
except OSError:
    pass
s.close()
PY
# new capability 3: read something credential-shaped
cat "$HOME/.netrc" > /dev/null 2>&1
# new capability 4: delete the artifact (data loss shape); and no sync anywhere
rm -f "${1:-/tmp}/syscall_diff_head.out"
exit 0
