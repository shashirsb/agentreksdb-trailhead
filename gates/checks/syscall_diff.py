#!/usr/bin/env python3
# ruff: noqa
"""syscall_diff.py — compare the syscall capabilities of a base build and a head build.

SABOTAGE CLASS
--------------
Capability creep: a change whose *source* reads like the intent said it should,
but whose running binary can suddenly do something new — open a socket, read a
file outside its data directory, exec a helper, delete data, ptrace a sibling.
Source-level gates (diff-policy, semgrep) look for the shapes they know; this
one looks at what actually happened under the kernel, so an egress path that
reaches the network through a dependency, a macro, a re-export or a generated
module still shows up. It also catches the inverse, which matters just as much
for a database: durability syscalls that *disappeared* (no more fsync) — silent
data loss that every functional test still passes.

The capability model is deliberately coarse, because the comparison has to be
stable across runs:
  net:socket:<family>  net:connect:<family>  net:bind  net:listen  net:sendto ...
  fs:read:<path>  fs:write:<path>  fs:delete:<path>   (only paths outside the allowlist)
  durability:fsync  durability:fdatasync  durability:msync  durability:sync_file_range
  proc:exec:<binary>  proc:clone
  env:read:proc-environ   env:leak:<canary>
  priv:ptrace  priv:setuid  priv:mount  priv:bpf  priv:memfd_create  ...
Anything in head and not in base, that the allowlist does not declare, is a
finding: the spec did not ask for that capability.

ENV READS — AN HONEST LIMIT
---------------------------
`getenv` is a memory read inside libc, not a syscall, so strace cannot see it.
What is detectable is (a) a read of /proc/*/environ and (b) a canary value
leaving the process: pass --env-canary NAME=VALUE and any appearance of VALUE in
a syscall argument (a write, a sendto, a filename) is reported as env:leak.
For the general case use honeytokens.py, which is built for exactly this.

HOW IT CAN BE EVADED
--------------------
* Do nothing on the traced run. Capabilities only appear when the code path
  executes, so a payload gated on a date, a hostname or the 1000th request shows
  nothing here. Drive this with the broadest test command available and pair it
  with env_invariance.py.
* Use an already-allowlisted capability: exfiltrate over a file in the allowed
  write prefix that another allowed process ships, or over DNS if the resolver
  socket is allowlisted.
* Reach the network through a syscall this model does not classify (io_uring
  submissions carry the real op in a ring buffer, not in the syscall args;
  io_uring_setup is therefore classified as priv:, not net:, and should be
  treated as a blocker).
* Static binaries, vfork races and setns tricks can confuse `strace -f`.
* strace is itself detectable (PTRACE_TRACEME fails, /proc/self/status TracerPid
  is non-zero): a payload can simply refuse to run under it. A clean run with no
  capabilities at all, from code that obviously needs some, is suspicious.

EXIT CODES
----------
  0  no new capability (or strace unavailable, which is reported as SKIP)
  1  a new capability, or a lost durability capability
  2  usage or internal error
  3  strace unavailable and --strict-tools was given

EXAMPLES
--------
  ./syscall_diff.py --allowlist syscall-allowlist.toml \
      --base-cmd './base/target/debug/agentreksdb selftest' \
      --head-cmd './head/target/debug/agentreksdb selftest'

  ./syscall_diff.py --allowlist a.toml --cmd 'cargo nextest run -p storage' \
      --base-dir ../base --head-dir ../head --json syscalls.json
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None  # type: ignore

CHECK = "syscall_diff"

NET_SYSCALLS = {
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "shutdown",
    "getpeername", "setsockopt",
}
OPEN_SYSCALLS = {"open", "openat", "openat2", "creat"}
STAT_SYSCALLS = {"stat", "lstat", "newfstatat", "statx", "access", "faccessat", "faccessat2", "readlink", "readlinkat"}
DELETE_SYSCALLS = {"unlink", "unlinkat", "rmdir", "truncate", "ftruncate", "rename", "renameat", "renameat2"}
DURABILITY_SYSCALLS = {"fsync", "fdatasync", "msync", "sync_file_range", "sync", "syncfs"}
EXEC_SYSCALLS = {"execve", "execveat"}
CLONE_SYSCALLS = {"fork", "vfork", "clone", "clone3"}
PRIV_SYSCALLS = {
    "ptrace", "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
    "capset", "mount", "umount2", "chroot", "pivot_root", "bpf", "kexec_load",
    "init_module", "finit_module", "delete_module", "memfd_create", "process_vm_readv",
    "process_vm_writev", "io_uring_setup", "userfaultfd", "personality", "seccomp",
    "add_key", "keyctl", "setns", "unshare", "mknod", "mknodat", "chmod", "fchmodat",
}
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

STRACE_LINE = re.compile(
    r"^(?:\[pid\s+(?P<pid1>\d+)\]\s*|(?P<pid2>\d+)\s+)?"
    r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\((?P<args>.*?)\)\s*=\s*(?P<ret>-?\w+|\?)"
)
# With -f, a syscall interrupted by another thread's event is split across two lines. Both halves
# have to be stitched back together or every exec and clone of a child process is invisible.
STRACE_UNFINISHED = re.compile(
    r"^(?:\[pid\s+(?P<pid1>\d+)\]\s*|(?P<pid2>\d+)\s+)?"
    r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\((?P<args>.*?)\s*<unfinished \.\.\.>\s*$"
)
STRACE_RESUMED = re.compile(
    r"^(?:\[pid\s+(?P<pid1>\d+)\]\s*|(?P<pid2>\d+)\s+)?"
    r"<\.\.\.\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s+resumed>(?P<args>.*?)\)?\s*=\s*(?P<ret>-?\w+|\?)"
)
FIRST_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
AF_FAMILY = re.compile(r"\b(AF_[A-Z0-9_]+)\b")

DEFAULT_PATH_NORMALISERS = [
    (r"/proc/\d+/", "/proc/<pid>/"),
    (r"/tmp/[^\s\"]*", "/tmp/<tmp>"),
    (r"/var/folders/[^\s\"]*", "/tmp/<tmp>"),
    (r"/run/user/\d+", "/run/user/<uid>"),
    (r"\.tmp[A-Za-z0-9_]{4,}", ".tmp<rand>"),
    (r"[0-9a-f]{16,}", "<hex>"),
]


# --------------------------------------------------------------------------- report


class Report:
    def __init__(self) -> None:
        self.findings: list[dict] = []
        self.warnings: list[dict] = []
        self.skips: list[str] = []

    def finding(self, rule: str, cap: str, message: str) -> None:
        self.findings.append({"rule": rule, "capability": cap, "message": message})
        print(f"FINDING {CHECK}.{rule} {cap} :: {message}")

    def warn(self, rule: str, cap: str, message: str) -> None:
        self.warnings.append({"rule": rule, "capability": cap, "message": message})
        print(f"WARN    {CHECK}.{rule} {cap} :: {message}")

    def skip(self, why: str) -> None:
        self.skips.append(why)
        print(f"SKIP    {CHECK} :: {why}")

    def info(self, msg: str) -> None:
        print(f"INFO    {CHECK} :: {msg}")


# --------------------------------------------------------------------------- allowlist


def load_allowlist(path: str | None, rep: Report) -> dict:
    empty = {
        "fs": {"read_prefixes": [], "write_prefixes": [], "delete_prefixes": []},
        "net": {"allow": []},
        "proc": {"exec": [], "clone_allowed": False},
        "priv": {"allow": []},
        "capabilities": {"allow": []},
    }
    if not path:
        rep.info("no --allowlist given; every new capability is a finding")
        return empty
    if tomllib is None:
        raise SystemExit(
            f"ERROR   {CHECK} :: reading an allowlist needs Python 3.11+ (tomllib). "
            "Upgrade the runner's python3 or drop --allowlist."
        )
    data = tomllib.loads(Path(path).read_text())
    out = empty
    for section, keys in (
        ("fs", ("read_prefixes", "write_prefixes", "delete_prefixes")),
        ("net", ("allow",)),
        ("proc", ("exec", "clone_allowed")),
        ("priv", ("allow",)),
        ("capabilities", ("allow",)),
    ):
        for k in keys:
            if section in data and k in data[section]:
                out[section][k] = data[section][k]
    return out


def capability_allowed(cap: str, allow: dict) -> bool:
    for pat in allow["capabilities"]["allow"]:
        if fnmatch.fnmatch(cap, pat):
            return True
    kind, _, rest = cap.partition(":")
    if kind == "net" and rest in allow["net"]["allow"]:
        return True
    if kind == "priv" and rest in allow["priv"]["allow"]:
        return True
    if kind == "proc":
        if rest == "clone" and allow["proc"]["clone_allowed"]:
            return True
        if rest.startswith("exec:"):
            binary = rest[len("exec:"):]
            if any(fnmatch.fnmatch(binary, p) for p in allow["proc"]["exec"]):
                return True
    if kind == "fs":
        mode, _, p = rest.partition(":")
        key = {"read": "read_prefixes", "write": "write_prefixes", "delete": "delete_prefixes"}.get(mode)
        if key and any(p.startswith(prefix) for prefix in allow["fs"][key]):
            return True
    return False


# --------------------------------------------------------------------------- tracing


def strace_available(strace: str, rep: Report) -> bool:
    if shutil.which(strace) is None:
        rep.skip(f"`{strace}` not found; install strace to compare syscall capabilities. Not a failure.")
        return False
    try:
        p = subprocess.run(
            [strace, "-f", "-o", os.devnull, "--", "/bin/true"], capture_output=True, timeout=60
        )
    except Exception as e:  # pragma: no cover - environment dependent
        rep.skip(f"`{strace}` could not run ({e}). Not a failure.")
        return False
    if p.returncode != 0:
        rep.skip(
            f"`{strace}` is installed but cannot trace here (ptrace blocked by seccomp/"
            "apparmor or /proc/sys/kernel/yama/ptrace_scope). Give the CI job "
            "`--cap-add=SYS_PTRACE` (or `--privileged`) to enable this check. Not a failure."
        )
        return False
    return True


def run_traced(cmd: str, cwd: str | None, strace: str, timeout: float, env_extra: dict, out: Path) -> tuple[int, str]:
    env = dict(os.environ)
    env.update(env_extra)
    argv = [strace, "-f", "-qq", "-s", "256", "-y", "-e", "trace=all", "-o", str(out), "--", "/bin/sh", "-c", cmd]
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, errors="replace", timeout=timeout)
        rc = p.returncode
        tail = (p.stderr or "")[-2000:]
    except subprocess.TimeoutExpired:
        rc, tail = -9, f"TIMEOUT after {timeout}s"
    return rc, tail


def normalise_path(path: str, extra: list[tuple[str, str]]) -> str:
    for pat, rep in DEFAULT_PATH_NORMALISERS + extra:
        path = re.sub(pat, rep, path)
    return path


def capabilities_from_trace(
    trace_path: Path, allow: dict, canary: tuple[str, str] | None, norms: list[tuple[str, str]]
) -> tuple[set[str], dict[str, str]]:
    """Return (capability set, one example trace line per capability)."""
    caps: set[str] = set()
    example: dict[str, str] = {}
    text = trace_path.read_text(errors="replace") if trace_path.exists() else ""

    def add(cap: str, line: str) -> None:
        caps.add(cap)
        example.setdefault(cap, line.strip()[:300])

    pending: dict[tuple[str, str], str] = {}

    def events():
        """(name, argstr, ret, raw_line), with unfinished/resumed pairs stitched."""
        for line in text.splitlines():
            u = STRACE_UNFINISHED.match(line)
            if u:
                pid = u.group("pid1") or u.group("pid2") or "-"
                pending[(pid, u.group("name"))] = u.group("args")
                continue
            r = STRACE_RESUMED.match(line)
            if r:
                pid = r.group("pid1") or r.group("pid2") or "-"
                head_args = pending.pop((pid, r.group("name")), "")
                yield r.group("name"), head_args + r.group("args"), r.group("ret"), line
                continue
            m = STRACE_LINE.match(line)
            if m:
                yield m.group("name"), m.group("args"), m.group("ret"), line

    for name, argstr, ret, line in events():
        failed = ret.startswith("-")

        if canary and canary[1] and canary[1] in line:
            add(f"env:leak:{canary[0]}", line)

        # Net and privilege syscalls count even when they fail: an attempted connect to an
        # outside host, or an attempted ptrace, is the capability. Filesystem syscalls count only
        # when they succeed, otherwise every $PATH miss (`stat("/opt/x/bin/rm") = -ENOENT`) would
        # register as a new capability and bury the real findings.
        if name in NET_SYSCALLS:
            fam = AF_FAMILY.search(argstr)
            if name in ("socket", "socketpair", "connect", "bind") and fam:
                add(f"net:{name}:{fam.group(1)}", line)
            else:
                add(f"net:{name}", line)
            continue

        if name in DURABILITY_SYSCALLS:
            add(f"durability:{name}", line)
            continue

        if name in OPEN_SYSCALLS or name in STAT_SYSCALLS or name in DELETE_SYSCALLS:
            sm = FIRST_STRING.search(argstr)
            if not sm or failed:
                continue
            raw = sm.group(1)
            path = normalise_path(raw, norms)
            if name in DELETE_SYSCALLS:
                mode = "delete"
            elif name in OPEN_SYSCALLS and any(f in argstr for f in WRITE_FLAGS):
                mode = "write"
            else:
                mode = "read"
            if raw.startswith("/proc/") and raw.endswith("/environ"):
                add("env:read:proc-environ", line)
                continue
            cap = f"fs:{mode}:{path}"
            # Allowlisted paths are not capabilities; this keeps the set small and stable.
            if not capability_allowed(cap, allow):
                add(cap, line)
            continue

        if name in EXEC_SYSCALLS:
            sm = FIRST_STRING.search(argstr)
            binary = normalise_path(sm.group(1), norms) if sm else "<unknown>"
            add(f"proc:exec:{binary}", line)
            continue

        if name in CLONE_SYSCALLS:
            add("proc:clone", line)
            continue

        if name in PRIV_SYSCALLS:
            add(f"priv:{name}", line)
            continue

    return caps, example


# --------------------------------------------------------------------------- main


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="syscall_diff.py",
        description="Trace a base build and a head build and report any capability head gained.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--allowlist", default=None, help="TOML file declaring the capabilities the spec allows")
    p.add_argument("--cmd", default=None, help="one command run in both --base-dir and --head-dir")
    p.add_argument("--base-cmd", default=None, help="command for the base build (run via /bin/sh -c)")
    p.add_argument("--head-cmd", default=None, help="command for the head build (run via /bin/sh -c)")
    p.add_argument("--base-dir", default=None, help="working directory for the base run")
    p.add_argument("--head-dir", default=None, help="working directory for the head run")
    p.add_argument("--strace", default="strace", help="strace binary (default: strace)")
    p.add_argument("--timeout", type=float, default=900.0, help="per-run timeout in seconds")
    p.add_argument("--env-canary", default=None, help="NAME=VALUE; any appearance of VALUE in a syscall argument is reported")
    p.add_argument("--normalise-path", action="append", default=[], metavar="REGEX=REPL",
                   help="extra path normaliser, repeatable (e.g. '/data/[0-9]+=/data/<n>')")
    p.add_argument("--keep-traces", default=None, help="directory to keep the raw strace output in")
    p.add_argument("--json", dest="json_out", default=None, help="write a machine-readable report here")
    p.add_argument("--fail-on-removed", action="store_true", help="also fail when head LOST any capability, not just durability ones")
    p.add_argument("--strict-tools", action="store_true", help="exit 3 instead of 0 when strace is unusable")
    args = p.parse_args(argv)

    base_cmd = args.base_cmd or args.cmd
    head_cmd = args.head_cmd or args.cmd
    if not base_cmd or not head_cmd:
        p.error("give --cmd, or both --base-cmd and --head-cmd")

    rep = Report()
    if not strace_available(args.strace, rep):
        print(f"-- {CHECK}: skipped (strace unusable)")
        return 3 if args.strict_tools else 0

    allow = load_allowlist(args.allowlist, rep)
    canary = None
    env_extra: dict[str, str] = {}
    if args.env_canary:
        name, _, value = args.env_canary.partition("=")
        canary = (name, value)
        env_extra[name] = value

    norms: list[tuple[str, str]] = []
    for spec in args.normalise_path:
        rx, _, repl = spec.partition("=")
        norms.append((rx, repl))

    trace_dir = Path(args.keep_traces) if args.keep_traces else Path(
        os.environ.get("RUNNER_TEMP", os.environ.get("TMPDIR", "/tmp"))
    ) / f"{CHECK}-traces"
    trace_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    for side, cmd, cwd in (("base", base_cmd, args.base_dir), ("head", head_cmd, args.head_dir)):
        out = trace_dir / f"{side}.strace"
        rc, tail = run_traced(cmd, cwd, args.strace, args.timeout, env_extra, out)
        caps, examples = capabilities_from_trace(out, allow, canary, norms)
        results[side] = {"rc": rc, "caps": caps, "examples": examples, "trace": str(out)}
        rep.info(f"{side}: rc={rc}, {len(caps)} capability/capabilities, trace {out}")
        if rc != 0 and tail:
            rep.info(f"{side} stderr tail: {tail.splitlines()[-1] if tail.splitlines() else ''}")

    base_caps, head_caps = results["base"]["caps"], results["head"]["caps"]
    gained = sorted(head_caps - base_caps)
    lost = sorted(base_caps - head_caps)

    for cap in gained:
        if capability_allowed(cap, allow):
            rep.info(f"new but allowlisted: {cap}")
            continue
        rep.finding(
            "new-capability",
            cap,
            "head can do this and base could not, and the allowlist does not declare it. "
            f"first seen: {results['head']['examples'].get(cap, '')}",
        )
    for cap in lost:
        if cap.startswith("durability:"):
            rep.finding(
                "lost-durability",
                cap,
                "head stopped calling this. A database that stops flushing loses data on "
                "crash while every functional test still passes.",
            )
        elif args.fail_on_removed:
            rep.finding("lost-capability", cap, "base did this and head does not; check the behaviour was not dropped.")
        else:
            rep.warn("lost-capability", cap, "base did this and head does not (informational).")

    if results["base"]["rc"] != results["head"]["rc"]:
        rep.finding(
            "exit-code-changed",
            f"rc {results['base']['rc']} -> {results['head']['rc']}",
            "the traced command's exit code changed between base and head",
        )

    print(
        f"-- {CHECK}: {len(rep.findings)} finding(s), {len(rep.warnings)} warning(s); "
        f"base={len(base_caps)} head={len(head_caps)} gained={len(gained)} lost={len(lost)}"
    )
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "check": CHECK,
                    "base": {"rc": results["base"]["rc"], "capabilities": sorted(base_caps)},
                    "head": {"rc": results["head"]["rc"], "capabilities": sorted(head_caps)},
                    "gained": gained,
                    "lost": lost,
                    "findings": rep.findings,
                    "warnings": rep.warnings,
                },
                indent=2,
            )
        )
    return 1 if rep.findings else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
