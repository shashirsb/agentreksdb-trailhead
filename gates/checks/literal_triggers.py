#!/usr/bin/env python3
# ruff: noqa
"""literal_triggers.py — harvest every literal a diff adds, as candidate backdoor triggers.

SABOTAGE CLASS
--------------
Magic-value backdoors: the xz-utils shape. The code is correct for all inputs a
test would think of, and wrong — authenticates, escalates, skips a visibility
filter, returns another tenant's rows — for one exact value the attacker knows.
No coverage, mutation or property test finds it, because the trigger is a point
in an enormous input space and the test suite never names that point.

What this check does is make that point *nameable*. It extracts every literal the
diff adds (string, byte string, char, decimal / hex / octal / binary integer,
and separately anything shaped like a UUID, JWT, AWS key or opaque token),
records where it came from, scores how interesting it looks, and emits a JSON
list plus a fuzz-harness stub. The harness is the actual gate: feed those values
into every auth, visibility, privilege and routing path and assert the answer is
the same as for a neighbouring value. A literal that changes an authorization
answer is a backdoor; a literal that changes nothing is noise.

This check is therefore ADVISORY on its own (it reports candidates, not proof)
and BLOCKING once the generated harness runs in the gate.

Noise excluded by default: 0, 1, -1 and other common small ints and powers of
two, empty / whitespace-only strings, prose format strings whose only unusual
content is `{}` placeholders, and anything under tests/, benches/, fuzz/ or
testdata/ (--include-tests keeps them). With --base-tree, a literal that already
appears anywhere in the base tree is dropped: it is not new, so it is not a
trigger this diff introduced.

HOW IT CAN BE EVADED
--------------------
* Compute the trigger instead of writing it: `0x4f * 3 + 7`, a const built from
  two halves, a value derived from a hash. Nothing is extracted because nothing
  is a literal. obfuscation.py covers the assembled-string form of this.
* Reuse a literal that already exists in the base tree (so --base-tree drops it)
  and give it a second meaning in a new comparison.
* Hide in the excluded set: make the trigger `2`, or put it in a test fixture
  that production code also reads.
* Trigger on a *shape* rather than a value: any id whose low bits are zero, any
  username longer than 63 bytes, a length rather than a content. Property tests
  over lengths and shapes are the answer to that, not this list.
* Span the trigger across several values none of which is unusual alone.

EXIT CODES
----------
  0  no candidates above the threshold
  1  candidates found (review the JSON, run the harness)
  2  usage or internal error

EXAMPLES
--------
  git diff -U0 base...head > d.patch
  ./literal_triggers.py --diff d.patch --json candidates.json --harness-out fuzz_triggers.rs
  ./literal_triggers.py --git-range origin/main...HEAD --base-tree ./base-checkout --min-score 2
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
from pathlib import Path

CHECK = "literal_triggers"

TEST_PATH_RE = re.compile(r"(^|/)(tests?|benches|fuzz|sim|testdata|fixtures|examples)(/|$)")

# Small ints that carry no information as a trigger candidate.
BORING_INTS = {0, 1, -1, 2, -2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 20, 24, 30, 31, 32, 60, 63, 64,
               100, 127, 128, 200, 255, 256, 512, 1000, 1024, 2048, 4096, 8192, 65535, 65536}

# ------------------------------------------------------------------ literal scanners
# Rust-flavoured. Ordered: raw strings before plain strings so r#".."# is not split.
LITERAL_RES: list[tuple[str, re.Pattern]] = [
    ("raw_string", re.compile(r'\bbr?(#+)"(?P<v>.*?)"\1')),
    ("raw_string", re.compile(r'\bbr?"(?P<v>[^"\\]*)"')),
    ("byte_string", re.compile(r'\bb"(?P<v>(?:[^"\\]|\\.)*)"')),
    ("string", re.compile(r'"(?P<v>(?:[^"\\\n]|\\.)*)"')),
    ("char", re.compile(r"'(?P<v>\\.|[^'\\\n])'")),
    ("byte_char", re.compile(r"\bb'(?P<v>\\.|[^'\\\n])'")),
    ("hex", re.compile(r"\b0x(?P<v>[0-9a-fA-F][0-9a-fA-F_]*)(?:[ui](?:8|16|32|64|128|size))?\b")),
    ("octal", re.compile(r"\b0o(?P<v>[0-7][0-7_]*)(?:[ui](?:8|16|32|64|128|size))?\b")),
    ("binary", re.compile(r"\b0b(?P<v>[01][01_]*)(?:[ui](?:8|16|32|64|128|size))?\b")),
    ("int", re.compile(r"(?<![\w.])(?P<v>\d[\d_]*)(?:[ui](?:8|16|32|64|128|size))?(?![\w.])")),
]

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.?[A-Za-z0-9_-]*$")
AWSKEY_RE = re.compile(r"^(AKIA|ASIA|AIza|ghp_|gho_|github_pat_|sk-|xox[abprs]-)[A-Za-z0-9/_-]{8,}$")
HEXBLOB_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
B64ISH_RE = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
FORMAT_PROSE_RE = re.compile(r"^[\w\s.,:;!?'()\[\]/{}%+-]*$")
PLACEHOLDER_RE = re.compile(r"\{[\w.:#?><^+-]*\}")

# Call/comparison context that makes a literal far more interesting: it is being
# compared against, or sits in a security-relevant line.
HOT_CONTEXT_RE = re.compile(
    r"(?i)\b(auth|authz|authori[sz]|token|secret|key|passwd|password|credential|session|cookie|"
    r"admin|root|superuser|privileg|role|perm|acl|owner|tenant|visib|redact|mask|allow|deny|"
    r"bypass|skip|override|magic|backdoor|debug|verify|signature|sign|quorum|replica|leader)\b"
)
COMPARISON_RE = re.compile(r"(==|!=|\bmatches!|\bstarts_with\b|\bends_with\b|\bcontains\b|=>\s*$|\bif\s)")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ------------------------------------------------------------------ diff parsing


class Added:
    __slots__ = ("path", "line", "text")

    def __init__(self, path: str, line: int, text: str):
        self.path, self.line, self.text = path, line, text


def parse_unified_diff(diff: str) -> list[Added]:
    """Added lines with their line number in the new file. Handles rename/new-file headers."""
    out: list[Added] = []
    path = "<unknown>"
    newline = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            p = raw[4:].strip()
            if p.startswith("b/"):
                p = p[2:]
            path = "<dev-null>" if p == "/dev/null" else p
            continue
        if raw.startswith("--- ") or raw.startswith("diff --git") or raw.startswith("index "):
            continue
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if m:
            newline = int(m.group(1))
            continue
        if raw.startswith("+"):
            out.append(Added(path, newline, raw[1:]))
            newline += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
        elif raw.startswith(" ") or raw == "":
            newline += 1
    return out


def git_diff(rng: str, repo: str | None) -> str:
    cmd = ["git", "diff", "-U0", "--no-color", "-M", rng]
    p = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, errors="replace")
    if p.returncode != 0:
        raise SystemExit(f"ERROR   {CHECK} :: git diff failed: {p.stderr.strip()}")
    return p.stdout


# ------------------------------------------------------------------ extraction


def strip_comments(line: str) -> str:
    """Drop a trailing // comment that is not inside a string. Crude but enough:
    we only need to avoid harvesting literals out of prose comments."""
    in_str = False
    esc = False
    for i, ch in enumerate(line):
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if not in_str and ch == "/" and line[i + 1 : i + 2] == "/":
            return line[:i]
    return line


def classify(kind: str, value: str) -> str:
    if kind in ("string", "raw_string", "byte_string"):
        if UUID_RE.match(value):
            return "uuid"
        if JWT_RE.match(value):
            return "jwt"
        if AWSKEY_RE.match(value):
            return "credential"
        if HEXBLOB_RE.match(value):
            return "hexblob"
        if B64ISH_RE.match(value) and shannon(value) >= 3.2:
            return "token"
    return kind


def int_value(kind: str, raw: str) -> int | None:
    t = raw.replace("_", "")
    try:
        if kind == "hex":
            return int(t, 16)
        if kind == "octal":
            return int(t, 8)
        if kind == "binary":
            return int(t, 2)
        if kind == "int":
            return int(t, 10)
    except ValueError:
        return None
    return None


def score(kind: str, value: str, line: str, args) -> tuple[int, list[str]]:
    """Higher = more worth fuzzing. Reasons are reported so a reviewer can argue with it."""
    s = 0
    why: list[str] = []
    if kind in ("uuid", "jwt", "credential", "token", "hexblob"):
        s += 3
        why.append(f"looks like a {kind}")
    if kind in ("string", "raw_string", "byte_string") and len(value) >= args.long_string:
        s += 1
        why.append(f"string of {len(value)} chars")
    if kind in ("string", "raw_string", "byte_string") and shannon(value) >= 3.5 and len(value) >= 12:
        s += 1
        why.append(f"entropy {shannon(value):.1f} bits/char")
    if kind in ("hex", "octal", "binary"):
        s += 1
        why.append(f"{kind} constant")
    if HOT_CONTEXT_RE.search(line):
        s += 2
        why.append("security-relevant line (auth/visibility/privilege wording)")
    if COMPARISON_RE.search(line):
        s += 1
        why.append("used in a comparison or match arm")
    if re.search(r"(?i)\bconst\b|\bstatic\b", line):
        s += 1
        why.append("declared as a const/static")
    return s, why


def extract(added: list[Added], args, base_literals: set[str] | None) -> list[dict]:
    cands: list[dict] = []
    seen: set[tuple[str, str, str, int]] = set()
    for a in added:
        if not args.include_tests and TEST_PATH_RE.search(a.path):
            continue
        if args.path_regex and not re.search(args.path_regex, a.path):
            continue
        code = a.text if args.include_comments else strip_comments(a.text)
        if not code.strip():
            continue
        consumed: list[tuple[int, int]] = []

        def overlaps(st: int, en: int) -> bool:
            return any(not (en <= cs or st >= ce) for cs, ce in consumed)

        for kind, rx in LITERAL_RES:
            for m in rx.finditer(code):
                st, en = m.span()
                if overlaps(st, en):
                    continue
                value = m.group("v")
                k = classify(kind, value)

                if k in ("int", "hex", "octal", "binary"):
                    iv = int_value(kind, value)
                    if iv is None:
                        continue
                    if iv in BORING_INTS and not args.keep_small_ints:
                        consumed.append((st, en))
                        continue
                    display = m.group(0)
                elif k == "char" or k == "byte_char":
                    consumed.append((st, en))
                    continue  # single chars are never a useful trigger on their own
                else:
                    if not value.strip():
                        consumed.append((st, en))
                        continue
                    if (
                        PLACEHOLDER_RE.search(value)
                        and FORMAT_PROSE_RE.match(value)
                        and shannon(value) < 4.2
                    ):
                        consumed.append((st, en))  # ordinary format string
                        continue
                    if len(value) < args.min_string_len and k == kind:
                        consumed.append((st, en))
                        continue
                    display = value

                consumed.append((st, en))
                if base_literals is not None and display in base_literals:
                    continue
                sc, why = score(k, value, code, args)
                if sc < args.min_score:
                    continue
                key = (a.path, k, display, a.line)
                if key in seen:
                    continue
                seen.add(key)
                cands.append(
                    {
                        "value": display,
                        "kind": k,
                        "file": a.path,
                        "line": a.line,
                        "column": st + 1,
                        "context": code.strip()[:200],
                        "score": sc,
                        "reasons": why,
                    }
                )
    cands.sort(key=lambda c: (-c["score"], c["file"], c["line"]))
    return cands


def load_base_literals(tree: str) -> set[str]:
    """Every literal-looking token already present in the base tree."""
    acc: set[str] = set()
    root = Path(tree)
    for p in root.rglob("*.rs"):
        if ".git" in p.parts:
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for kind, rx in LITERAL_RES:
            for m in rx.finditer(text):
                acc.add(m.group("v") if kind.endswith("string") else m.group(0))
    return acc


# ------------------------------------------------------------------ harness stub

HARNESS_RS = '''// AUTO-GENERATED by gates/checks/literal_triggers.py — do not hand-edit; regenerate.
//
// Every literal this PR added, as a candidate backdoor trigger. The assertion to make is
// DIFFERENTIAL: for each candidate value, the authorization / visibility / privilege answer
// must equal the answer for a value that differs by one byte. A magic value is exactly a
// value where that equality breaks.
//
// Wire-up: put this in fuzz/fuzz_targets/ or tests/, point the three helpers at the real
// entry points, and run it in gate-tests. It must FAIL on a planted magic value.

pub const CANDIDATES: &[&str] = &[
%(values)s];

/// One-byte neighbour of a candidate: same shape, different value.
fn neighbour(v: &str) -> String {
    let mut b = v.as_bytes().to_vec();
    if let Some(last) = b.last_mut() {
        *last = if *last == b'z' { b'a' } else { *last + 1 };
    }
    String::from_utf8_lossy(&b).into_owned()
}

#[test]
fn candidate_literals_do_not_change_authorization() {
    for v in CANDIDATES {
        let n = neighbour(v);
        // TODO point these at the real helpers:
        //   assert_eq!(authorize(v), authorize(&n), "auth answer differs for literal {v:?}");
        //   assert_eq!(visible_rows(v).len(), visible_rows(&n).len(), "visibility differs for {v:?}");
        //   assert_eq!(role_of(v), role_of(&n), "privilege differs for literal {v:?}");
        let _ = (v, &n);
    }
}

#[test]
fn candidate_literals_do_not_change_routing_or_timing() {
    // Same idea for the paths where slowness, not access, is the payload:
    // assert that plan shape / syscall count / iteration count for a candidate equals
    // that of its neighbour. See gates/checks/syscall_diff.py for the capability half.
}
'''


def rust_escape(v: str) -> str:
    """Escape for a Rust string literal. Non-ASCII becomes \\u{..} on purpose: the generated
    harness must never itself contain an invisible or bidi character."""
    out = []
    for ch in v:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            out.append(f"\\u{{{ord(ch):x}}}")
    return "".join(out)


def write_harness(path: str, cands: list[dict]) -> None:
    vals = "".join(
        '    "%s", // %s:%s score=%d\n' % (rust_escape(c["value"]), c["file"], c["line"], c["score"])
        for c in cands
    )
    Path(path).write_text(HARNESS_RS % {"values": vals})


# ------------------------------------------------------------------ cli


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="literal_triggers.py",
        description="Extract every literal a diff adds and emit them as candidate backdoor triggers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit 1 means candidates were found; that is input to a fuzz harness, not proof of malice.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--diff", help="unified diff file, or - for stdin")
    src.add_argument("--git-range", help="e.g. origin/main...HEAD (runs git diff -U0 for you)")
    p.add_argument("--repo", default=None, help="repository directory for --git-range")
    p.add_argument("--base-tree", default=None, help="base checkout; literals already present there are dropped")
    p.add_argument("--json", dest="json_out", default="-", help="write candidates JSON here (default stdout)")
    p.add_argument("--harness-out", default=None, help="write a Rust fuzz-harness stub here")
    p.add_argument("--min-score", type=int, default=1, help="drop candidates scoring below this (default 1)")
    p.add_argument("--min-string-len", type=int, default=3, help="shortest plain string kept (default 3)")
    p.add_argument("--long-string", type=int, default=20, help="length at which a string scores a point")
    p.add_argument("--keep-small-ints", action="store_true", help="keep 0/1/-1 and friends")
    p.add_argument("--include-tests", action="store_true", help="also scan tests/, fuzz/, testdata/")
    p.add_argument("--include-comments", action="store_true", help="also harvest literals out of // comments")
    p.add_argument("--path-regex", default=None, help="only scan files whose path matches this regex")
    p.add_argument("--fail-threshold", type=int, default=1, help="exit 1 once this many candidates are found (0 = never fail)")
    p.add_argument("--quiet", action="store_true", help="only print the summary line")
    args = p.parse_args(argv)

    if args.diff:
        diff = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text(errors="replace")
    else:
        diff = git_diff(args.git_range, args.repo)

    added = parse_unified_diff(diff)
    base_literals = load_base_literals(args.base_tree) if args.base_tree else None
    cands = extract(added, args, base_literals)

    if not args.quiet:
        for c in cands:
            print(
                f"FINDING {CHECK}.candidate {c['file']}:{c['line']} :: "
                f"{c['kind']} score={c['score']} value={c['value']!r} ({'; '.join(c['reasons'])})"
            )
    payload = json.dumps({"check": CHECK, "added_lines": len(added), "candidates": cands}, indent=2)
    if args.json_out == "-":
        if not args.quiet:
            print(payload)
    else:
        Path(args.json_out).write_text(payload)
        print(f"INFO    {CHECK} :: candidates written to {args.json_out}")
    if args.harness_out:
        write_harness(args.harness_out, cands)
        print(f"INFO    {CHECK} :: fuzz harness stub written to {args.harness_out}")

    print(f"-- {CHECK}: {len(cands)} candidate trigger(s) from {len(added)} added line(s)")
    if args.fail_threshold and len(cands) >= args.fail_threshold:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
