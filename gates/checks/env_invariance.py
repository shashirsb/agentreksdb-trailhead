#!/usr/bin/env python3
# ruff: noqa
"""env_invariance.py — run a test command under varied environments and diff the results.

SABOTAGE CLASS
--------------
Time bombs and host-gated backdoors. A planted bug that only fires on a certain
date, in a certain timezone, on a host whose name matches, for a certain user, or
when the machine has more than one CPU, passes every normal test run because CI
only ever runs in one environment. This check runs the *same* command several
times while varying one environment axis at a time and compares the results. Any
difference is a finding: a correct database does not change behaviour because the
clock, the hostname, the locale or the core count changed.

Axes varied (each can be skipped, see --list-dims):
  baseline  the command as-is, run twice, to measure intrinsic nondeterminism
  tz        TZ=UTC, Asia/Kolkata, America/Los_Angeles  (DST, half-hour offsets)
  clock     libfaketime offsets (+1d, +400d, -1d) — SKIPPED if libfaketime absent
  hostname  a different UTS hostname via `unshare -u` — SKIPPED without userns
  user      USER / LOGNAME set to another name
  locale    LANG / LC_ALL = C, en_US.UTF-8, tr_TR.UTF-8 (Turkish dotless-i case folding)
  cpus      one CPU vs all CPUs via `taskset` — SKIPPED if taskset absent

Comparison is on the exit code plus a *normalised* stdout (and stderr with
--compare-stderr): durations, temp paths, pids, hex addresses, UUIDs, ISO
timestamps, the injected hostname/user values and the working directory are
rewritten to placeholders so that only real behavioural differences remain.
With --out-dir, the sha256 of every file the command writes is compared too,
which catches a bug that changes persisted bytes but not the printed output.

HOW IT CAN BE EVADED
--------------------
* A trigger outside the axes varied here (a specific kernel version, a cgroup
  limit, an MAC address, the presence of /.dockerenv, a DNS answer, an exact
  wall-clock instant rather than an offset).
* A trigger that only fires after the clock passes a date further out than the
  offsets tried; use --clock-offsets to push further (+5y) on a schedule.
* Payloads that are *stateful*: fire on the 1000th request, not the 1st. Pair
  this with a long-running soak and with literal_triggers.py.
* Anything the normalisers rewrite. A backdoor that leaks via a value that looks
  like a duration or a temp path is hidden by the very normalisation that keeps
  this check quiet. --no-normalise shows the raw comparison.
* Nondeterministic output (hash-map iteration order, thread interleaving) can be
  loud enough to hide a real diff; this is reported as its own finding
  ("nondeterministic baseline") rather than silently tolerated, and --sort-lines
  trades ordering sensitivity for signal.

EXIT CODES
----------
  0  no differences (skipped axes are reported but do not fail)
  1  at least one difference found
  2  usage or internal error
  3  a required tool was missing and --strict-tools was given

EXAMPLE
-------
  ./env_invariance.py --out-dir /tmp/artifacts -- cargo nextest run -p agentreksdb-storage
  ./env_invariance.py --only tz,clock --json report.json -- ./target/debug/agentreksdb selftest
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

CHECK = "env_invariance"

ALL_DIMS = ["baseline", "tz", "clock", "hostname", "user", "locale", "cpus"]

# Each entry: (regex, replacement). Order matters; applied to stdout/stderr before diffing.
NORMALISERS: list[tuple[str, str]] = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<timestamp>"),
    (r"\b\d{10,19}\b", "<bignum>"),  # epoch seconds/nanos, snowflake ids
    (r"\b\d+(?:\.\d+)?\s?(?:ns|µs|us|ms|secs?|seconds?|mins?|m)\b", "<dur>"),
    (r"\b\d+(?:\.\d+)?s\b", "<dur>"),
    (r"finished in\s+\S+", "finished in <dur>"),
    (r"0x[0-9a-fA-F]{4,}", "<addr>"),
    (r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<uuid>"),
    (r"/tmp/[^\s\"'`,)]+", "<tmp>"),
    (r"/var/folders/[^\s\"'`,)]+", "<tmp>"),
    (r"/run/user/\d+[^\s\"'`,)]*", "<tmp>"),
    (r"\b(?:pid|PID|tid|TID)\s*[:=]?\s*\d+", "pid=<pid>"),
    (r"thread '[^']*'", "thread '<thread>'"),
    (r":\d{4,5}\b", ":<port>"),
    (r"[+-]\d{2}:\d{2}\b", "<tzoff>"),
]


# --------------------------------------------------------------------------- output


class Report:
    def __init__(self) -> None:
        self.findings: list[dict] = []
        self.skips: list[dict] = []
        self.runs: list[dict] = []

    def finding(self, rule: str, where: str, message: str, detail: str = "") -> None:
        self.findings.append({"rule": rule, "where": where, "message": message, "detail": detail})
        print(f"FINDING {CHECK}.{rule} {where} :: {message}")
        if detail:
            for line in detail.splitlines():
                print(f"    | {line}")

    def skip(self, dim: str, why: str) -> None:
        self.skips.append({"dim": dim, "reason": why})
        print(f"SKIP    {CHECK}.{dim} :: {why}")

    def info(self, message: str) -> None:
        print(f"INFO    {CHECK} :: {message}")


# --------------------------------------------------------------------------- helpers


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def probe(argv: list[str]) -> bool:
    """True if argv runs and exits 0 (used to test unshare/taskset permissions)."""
    try:
        p = subprocess.run(argv, capture_output=True, timeout=30)
        return p.returncode == 0
    except Exception:
        return False


def find_libfaketime() -> str | None:
    """Locate libfaketime.so.1. Returns a path, or None."""
    cands = [
        "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
        "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1",
        "/usr/lib/faketime/libfaketime.so.1",
        "/usr/local/lib/faketime/libfaketime.so.1",
        "/opt/homebrew/lib/faketime/libfaketime.1.dylib",
        "/usr/local/lib/faketime/libfaketime.1.dylib",
    ]
    for c in cands:
        if Path(c).exists():
            return c
    try:
        out = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            if "libfaketime" in line and "=>" in line:
                return line.split("=>")[-1].strip()
    except Exception:
        pass
    return None


def normalise(text: str, extra: list[tuple[str, str]], enabled: bool, sort_lines: bool) -> str:
    if enabled:
        for pat, rep in NORMALISERS + extra:
            text = re.sub(pat, rep, text)
    lines = [ln.rstrip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln.strip()]
    if sort_lines:
        lines.sort()
    return "\n".join(lines)


def manifest(out_dir: Path | None) -> dict[str, str]:
    """sha256 of every regular file under out_dir, keyed by relative path."""
    if out_dir is None or not out_dir.exists():
        return {}
    acc: dict[str, str] = {}
    for p in sorted(out_dir.rglob("*")):
        if p.is_file():
            h = hashlib.sha256()
            with p.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            acc[str(p.relative_to(out_dir))] = h.hexdigest()
    return acc


# --------------------------------------------------------------------------- run plan


class Run:
    def __init__(self, dim: str, label: str, env: dict[str, str], wrapper: list[str] | None = None):
        self.dim = dim
        self.label = label
        self.env = env
        self.wrapper = wrapper or []
        self.rc: int | None = None
        self.stdout = ""
        self.stderr = ""
        self.files: dict[str, str] = {}

    def signature(self, args, extra_norm) -> tuple:
        out = normalise(self.stdout, extra_norm, not args.no_normalise, args.sort_lines)
        err = (
            normalise(self.stderr, extra_norm, not args.no_normalise, args.sort_lines)
            if args.compare_stderr
            else ""
        )
        return (self.rc, out, err, tuple(sorted(self.files.items())))


def build_plan(args, rep: Report) -> tuple[list[Run], list[tuple[str, str]]]:
    """Return the runs to perform plus extra normalisers for injected values."""
    runs: list[Run] = []
    extra_norm: list[tuple[str, str]] = []
    dims = args.dims

    # baseline, twice, to separate intrinsic nondeterminism from environment sensitivity
    for i in range(max(2, args.repeat)):
        runs.append(Run("baseline", f"baseline#{i + 1}", {}))

    if "tz" in dims:
        for tz in args.timezones:
            runs.append(Run("tz", f"TZ={tz}", {"TZ": tz}))

    if "clock" in dims:
        lib = find_libfaketime()
        fakebin = shutil.which("faketime")
        if not lib and not fakebin:
            rep.skip(
                "clock",
                "libfaketime not available (no libfaketime.so.1 and no `faketime` binary); "
                "install `libfaketime` to test clock-triggered logic. Not a failure.",
            )
        else:
            for off in args.clock_offsets:
                if fakebin:
                    runs.append(Run("clock", f"faketime {off}", {}, [fakebin, "-f", off]))
                else:
                    runs.append(
                        Run(
                            "clock",
                            f"LD_PRELOAD faketime {off}",
                            {"LD_PRELOAD": lib or "", "FAKETIME": off, "FAKETIME_NO_CACHE": "1"},
                        )
                    )

    if "hostname" in dims:
        if not have("unshare"):
            rep.skip("hostname", "`unshare` not found; cannot vary the UTS hostname. Not a failure.")
        elif not probe(["unshare", "-u", "--", "hostname"]):
            rep.skip(
                "hostname",
                "`unshare -u` refused (no CAP_SYS_ADMIN / user namespaces disabled). "
                "Run this check in a privileged CI job to cover hostname gating. Not a failure.",
            )
        else:
            for host in args.hostnames:
                extra_norm.append((re.escape(host), "<hostname>"))
                runs.append(
                    Run(
                        "hostname",
                        f"hostname={host}",
                        {},
                        [
                            "unshare",
                            "-u",
                            "--",
                            "/bin/sh",
                            "-c",
                            'hostname "$1" || exit 97; shift; exec "$@"',
                            "sh",
                            host,
                        ],
                    )
                )

    if "user" in dims:
        for u in args.users:
            extra_norm.append((re.escape(u), "<user>"))
            runs.append(Run("user", f"USER={u}", {"USER": u, "LOGNAME": u, "USERNAME": u}))

    if "locale" in dims:
        for loc in args.locales:
            runs.append(
                Run(
                    "locale",
                    f"LANG={loc}",
                    {"LANG": loc, "LC_ALL": loc, "LC_CTYPE": loc, "LANGUAGE": loc.split(".")[0]},
                )
            )

    if "cpus" in dims:
        if not have("taskset"):
            rep.skip("cpus", "`taskset` not found; cannot vary the CPU count. Not a failure.")
        elif not probe(["taskset", "-c", "0", "true"]):
            rep.skip("cpus", "`taskset -c 0` refused by the runner. Not a failure.")
        else:
            ncpu = os.cpu_count() or 1
            runs.append(Run("cpus", "cpus=1", {}, ["taskset", "-c", "0"]))
            if ncpu > 1:
                runs.append(
                    Run("cpus", f"cpus=0-{ncpu - 1}", {}, ["taskset", "-c", f"0-{ncpu - 1}"])
                )
            else:
                rep.info("only one CPU online; the multi-CPU variant was not generated")

    return runs, extra_norm


def execute(run: Run, args, rep: Report) -> None:
    env = dict(os.environ)
    # A reproducible floor: strip the values we vary so an unset axis cannot leak in.
    for k in ("TZ", "LANG", "LC_ALL", "LC_CTYPE", "LANGUAGE", "FAKETIME", "LD_PRELOAD"):
        env.pop(k, None)
    env.setdefault("TZ", "UTC")
    env.setdefault("LC_ALL", "C")
    env.update(run.env)

    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir is not None and args.clean_out_dir:
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

    argv = run.wrapper + args.command
    try:
        p = subprocess.run(
            argv,
            env=env,
            cwd=args.cwd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=args.timeout,
        )
        run.rc, run.stdout, run.stderr = p.returncode, p.stdout, p.stderr
    except FileNotFoundError as e:
        rep.finding("spawn-failed", run.label, f"cannot run the command: {e}")
        run.rc, run.stdout, run.stderr = -1, "", str(e)
    except subprocess.TimeoutExpired:
        # A timeout under one environment and not another is exactly the deliberate-slowness shape.
        run.rc, run.stdout, run.stderr = -9, "", f"TIMEOUT after {args.timeout}s"
    run.files = manifest(out_dir)
    if args.keep_logs:
        d = Path(args.keep_logs)
        d.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", run.label)
        (d / f"{safe}.stdout").write_text(run.stdout)
        (d / f"{safe}.stderr").write_text(run.stderr)
    rep.runs.append({"dim": run.dim, "label": run.label, "rc": run.rc, "files": len(run.files)})
    print(f"RUN     {CHECK} {run.label} -> rc={run.rc} ({len(run.stdout)} B stdout)")


def diff_text(a: str, b: str, a_name: str, b_name: str, limit: int) -> str:
    d = list(
        difflib.unified_diff(
            a.splitlines(), b.splitlines(), fromfile=a_name, tofile=b_name, lineterm="", n=1
        )
    )
    if len(d) > limit:
        d = d[:limit] + [f"... ({len(d) - limit} more diff lines suppressed)"]
    return "\n".join(d)


def compare(runs: list[Run], args, rep: Report, extra_norm) -> None:
    base, base2 = runs[0], runs[1]
    bsig, b2sig = base.signature(args, extra_norm), base2.signature(args, extra_norm)
    if bsig != b2sig:
        rep.finding(
            "nondeterministic-baseline",
            f"{base.label} vs {base2.label}",
            "the command is not deterministic in a fixed environment; environment "
            "sensitivity cannot be judged until this is fixed (and nondeterminism is "
            "itself a place to hide a bug)",
            diff_text(bsig[1], b2sig[1], base.label, base2.label, args.diff_lines),
        )

    for run in runs[2:]:
        sig = run.signature(args, extra_norm)
        if sig == bsig:
            continue
        reasons = []
        if sig[0] != bsig[0]:
            reasons.append(f"exit code {bsig[0]} -> {sig[0]}")
        if sig[1] != bsig[1]:
            reasons.append("stdout differs")
        if args.compare_stderr and sig[2] != bsig[2]:
            reasons.append("stderr differs")
        if sig[3] != bsig[3]:
            changed = sorted(
                set(dict(sig[3]).items()) ^ set(dict(bsig[3]).items()),
                key=lambda kv: kv[0],
            )
            names = sorted({k for k, _ in changed})
            reasons.append(f"output files differ: {', '.join(names[:8])}")
        detail = diff_text(bsig[1], sig[1], base.label, run.label, args.diff_lines)
        if args.compare_stderr and sig[2] != bsig[2]:
            detail += "\n" + diff_text(bsig[2], sig[2], base.label + ":err", run.label + ":err", args.diff_lines)
        rep.finding(
            f"env-dependent.{run.dim}",
            run.label,
            "behaviour changed when only the environment changed (" + "; ".join(reasons) + ")",
            detail,
        )


# --------------------------------------------------------------------------- cli


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="env_invariance.py",
        description="Run a command under varied environments and report any behavioural difference.",
        epilog="Put the command last, after `--`. Example: env_invariance.py --only tz -- cargo test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--only", help="comma-separated axes to run (default: all). See --list-dims.")
    p.add_argument("--skip", help="comma-separated axes to skip.")
    p.add_argument("--list-dims", action="store_true", help="print the available axes and exit")
    p.add_argument("--repeat", type=int, default=2, help="baseline repeats (min 2, default 2)")
    p.add_argument("--timeout", type=float, default=900.0, help="per-run timeout in seconds")
    p.add_argument("--cwd", default=None, help="working directory for the command")
    p.add_argument("--out-dir", default=None, help="directory the command writes to; its files are hashed and compared")
    p.add_argument("--clean-out-dir", action="store_true", help="wipe --out-dir before each run")
    p.add_argument("--compare-stderr", action="store_true", help="also compare normalised stderr")
    p.add_argument("--no-normalise", action="store_true", help="compare raw output (very noisy)")
    p.add_argument("--sort-lines", action="store_true", help="compare output as a sorted multiset of lines (hides ordering changes)")
    p.add_argument("--diff-lines", type=int, default=40, help="max diff lines per finding (default 40)")
    p.add_argument("--keep-logs", default=None, help="directory to write each run's raw stdout/stderr into")
    p.add_argument("--json", dest="json_out", default=None, help="write a machine-readable report here")
    p.add_argument("--strict-tools", action="store_true", help="exit 3 if any axis had to be skipped for a missing tool")
    p.add_argument("--timezones", default="UTC,Asia/Kolkata,America/Los_Angeles")
    p.add_argument("--clock-offsets", default="+1d,+400d,-1d", help="libfaketime offsets to try")
    p.add_argument("--hostnames", default="trailhead-gate-a,prod-db-01")
    p.add_argument("--users", default="nobody,root")
    p.add_argument("--locales", default="C,en_US.UTF-8,tr_TR.UTF-8")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- the command to run")
    a = p.parse_args(argv)

    if a.list_dims:
        print("axes: " + ", ".join(ALL_DIMS))
        sys.exit(0)

    cmd = a.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        p.error("no command given; put it after `--`")
    a.command = cmd

    dims = [d for d in (a.only.split(",") if a.only else ALL_DIMS) if d]
    bad = [d for d in dims if d not in ALL_DIMS]
    if bad:
        p.error(f"unknown axis: {', '.join(bad)} (known: {', '.join(ALL_DIMS)})")
    if a.skip:
        dims = [d for d in dims if d not in a.skip.split(",")]
    a.dims = dims
    for name in ("timezones", "clock_offsets", "hostnames", "users", "locales"):
        setattr(a, name, [x for x in getattr(a, name).split(",") if x])
    return a


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    rep = Report()
    rep.info(f"command: {' '.join(args.command)}")
    rep.info(f"axes: {', '.join(args.dims)}")

    runs, extra_norm = build_plan(args, rep)
    for run in runs:
        execute(run, args, rep)
    compare(runs, args, rep, extra_norm)

    print(
        f"-- {CHECK}: {len(rep.findings)} finding(s), {len(rep.skips)} skipped axis/axes, "
        f"{len(runs)} run(s)"
    )
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "check": CHECK,
                    "command": args.command,
                    "findings": rep.findings,
                    "skipped": rep.skips,
                    "runs": rep.runs,
                },
                indent=2,
            )
        )
    if rep.findings:
        return 1
    if rep.skips and args.strict_tools:
        print("ERROR   --strict-tools: an axis was skipped for a missing tool")
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
