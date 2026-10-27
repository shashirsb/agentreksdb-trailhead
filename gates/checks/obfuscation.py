#!/usr/bin/env python3
# ruff: noqa
"""obfuscation.py — flag encoded, assembled or visually disguised payloads in added lines.

SABOTAGE CLASS
--------------
Hidden payloads. A reviewer — human or model — reads a diff as text, so the
cheapest way to get a payload past review is to make it unreadable: a base64
blob, a hex array, a string assembled a character at a time, a homoglyph
identifier that *looks* like the function you trust, a bidi control that makes
the line render in a different order than it compiles, or a 900-character line
that nobody scrolls. The xz-utils payload lived in a binary test fixture; the
Trojan Source family lives in Unicode; the ordinary case is a `char::from_u32`
loop that spells out "/bin/sh".

This check reads the diff's added lines and flags:
  entropy      string literals at or above --min-len with Shannon entropy >= --entropy
  base64       [A-Za-z0-9+/]{--b64-len,} runs (and base64url), entropy-confirmed
  hex          hex runs >= --hex-len, and byte arrays of >= --byte-array-len elements
  assembled    char::from_u32, `as u8 as char`, from_utf8(_unchecked), concat of
               escapes, XOR/ADD loops over literals, .rev() on a literal, many \\u{..}
  unicode      bidi controls, zero-width, invisible, tag characters, and mixed-script
               or confusable identifiers/literals (Cyrillic а in an ASCII word)
  long-line    a single added line longer than --max-line

`gates/diff-policy.toml` already blocks base64/hex blobs over 256 characters and
bidi characters outright. This check is the *lower* threshold: it catches the
40-character payload and the assembled string, which the diff policy lets past.

FALSE POSITIVES, HONESTLY
-------------------------
Real code contains high-entropy strings: test vectors (NIST, RFC), golden
hashes, embedded certificates, migration checksums, minified assets, generated
bindings, protocol magic numbers. The handling is, in order:
 1. tests/, benches/, fuzz/, testdata/ and fixtures/ are skipped by default
    (--include-tests to scan them) — that is where legitimate blobs belong, and
    moving a blob there to dodge this check also moves it out of production code.
 2. --allow-file holds path-glob + regex pairs for the rest (see
    testdata/obfuscation-allow.txt for the format). Every line is a decision:
    write the reason in a comment on the line.
 3. Severities are graded: `high` findings fail by default (--fail-on high),
    `medium`/`low` are annotated. Unicode and assembled-string findings are high
    because they have almost no honest use in database source; a long line or a
    single 40-char base64 run is medium.
A blob that genuinely must live in production source should be a file loaded at
runtime, reviewed as a file — not a literal in a diff.

HOW IT CAN BE EVADED
--------------------
* Stay under the thresholds: a 20-character payload, entropy just under the cut,
  a hex array split over several short lines (each line is scored on its own).
* Use a *low*-entropy encoding: English wordlist encoding, a lookup into an
  existing table, indexes into a legitimate string, or arithmetic on existing
  constants. Nothing here is unusual on its own.
* Put the payload in data the code already loads (a migration, a JSON fixture, a
  config default) rather than in a literal.
* Encode in structure rather than bytes: the order of match arms, the choice of
  variable names, whitespace.
* Make it look like a test vector and cite an RFC in the comment above it.

EXIT CODES
----------
  0  nothing at or above --fail-on
  1  at least one finding at or above --fail-on
  2  usage or internal error

EXAMPLES
--------
  git diff -U0 base...head | ./obfuscation.py --diff -
  ./obfuscation.py --git-range origin/main...HEAD --fail-on medium --json obf.json
  ./obfuscation.py --diff d.patch --allow-file testdata/obfuscation-allow.txt
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import unicodedata
from fnmatch import fnmatch
from pathlib import Path

CHECK = "obfuscation"
SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

TEST_PATH_RE = re.compile(r"(^|/)(tests?|benches|fuzz|sim|testdata|fixtures|examples|vendor)(/|$)")

STRING_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
RAWSTR_RE = re.compile(r'\bbr?(#*)"(.*?)"\1')
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
B64URL_RE = re.compile(r"[A-Za-z0-9_-]{24,}={0,2}")
UUID_LIKE_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
BYTE_ARRAY_RE = re.compile(r"(?:0x[0-9a-fA-F]{2}\s*,\s*){6,}")
DECIMAL_ARRAY_RE = re.compile(r"(?:\b\d{1,3}\s*,\s*){10,}")
UNICODE_ESCAPE_RE = re.compile(r"\\u\{[0-9a-fA-F]{1,6}\}")
IDENT_RE = re.compile(r"[^\W\d]\w*", re.UNICODE)

ASSEMBLY_PATTERNS: list[tuple[str, str, str]] = [
    ("assembled.char-from-u32", r"\bchar::from_u32(_unchecked)?\s*\(", "a string built from numeric code points"),
    ("assembled.as-u8-as-char", r"\bas\s+u8\s+as\s+char\b", "byte arithmetic cast to a character"),
    ("assembled.from-utf8-unchecked", r"\bfrom_utf8_unchecked\s*\(", "bytes turned into a string without validation"),
    ("assembled.from-utf8-array", r"\bfrom_utf8(_lossy)?\s*\(\s*&?\s*\[", "a string built from an inline byte array"),
    ("assembled.xor-loop", r"\.iter\(\)[^;]{0,80}\.map\([^;]{0,80}(\^|\.wrapping_add\(|\.wrapping_sub\()", "a map over bytes with XOR/wrapping arithmetic — a decode loop"),
    ("assembled.zip-xor", r"\.zip\([^;]{0,60}\)[^;]{0,60}\^", "two byte streams XORed together — a one-time-pad decode"),
    ("assembled.literal-rev", r'"[^"\n]{8,}"\s*\.\s*chars\s*\(\s*\)\s*\.\s*rev\s*\(', "a reversed literal"),
    ("assembled.concat-escapes", r'(?:\\x[0-9a-fA-F]{2}){6,}', "a literal written entirely as hex escapes"),
    ("assembled.decode-call", r"\b(base64|hex|b64)\s*(::|\.)\s*(decode|from_str|decode_vec|engine)", "a decoder invoked on inline data"),
    ("assembled.transmute-str", r"\bmem::transmute\b[^;]{0,60}(str|u8)", "transmute into a string type"),
]

# Characters that have no business in source: bidi overrides/isolates, zero-width, invisibles, tags.
DANGEROUS_CODEPOINTS = (
    list(range(0x200B, 0x2010))      # ZWSP..ZWJ, LRM/RLM
    + list(range(0x202A, 0x202F))    # LRE RLE PDF LRO RLO
    + list(range(0x2066, 0x206A))    # LRI RLI FSI PDI
    + [0xFEFF, 0x00AD, 0x061C, 0x180E, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064]
    + list(range(0xE0000, 0xE0080))  # tag characters
    + list(range(0xFFF9, 0xFFFC))    # interlinear annotation
)
DANGEROUS_SET = {chr(c) for c in DANGEROUS_CODEPOINTS}

# Scripts whose letters are routinely confused with Latin ones.
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "FULLWIDTH", "MATHEMATICAL")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    return name.split()[0]


# --------------------------------------------------------------------------- diff parsing


class Added:
    __slots__ = ("path", "line", "text")

    def __init__(self, path: str, line: int, text: str):
        self.path, self.line, self.text = path, line, text


def parse_unified_diff(diff: str) -> list[Added]:
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
        else:
            newline += 1
    return out


def git_diff(rng: str, repo: str | None) -> str:
    p = subprocess.run(["git", "diff", "-U0", "--no-color", "-M", rng], cwd=repo,
                       capture_output=True, text=True, errors="replace")
    if p.returncode != 0:
        raise SystemExit(f"ERROR   {CHECK} :: git diff failed: {p.stderr.strip()}")
    return p.stdout


# --------------------------------------------------------------------------- allowlist


def load_allowlist(path: str | None) -> list[tuple[str, re.Pattern]]:
    """Lines of `<path-glob><TAB or 2+ spaces><regex>`; `#` comments ignored."""
    if not path:
        return []
    out = []
    for raw in Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"\t+|\s{2,}", line, maxsplit=1)
        if len(parts) == 1:
            out.append((parts[0], re.compile(r".")))
        else:
            out.append((parts[0], re.compile(parts[1])))
    return out


def allowed(path: str, text: str, allow: list[tuple[str, re.Pattern]]) -> bool:
    return any(fnmatch(path, glob) and rx.search(text) for glob, rx in allow)


# --------------------------------------------------------------------------- checks


def literals_of(line: str) -> list[str]:
    out = [m.group(2) for m in RAWSTR_RE.finditer(line)]
    out += [m.group(1) for m in STRING_RE.finditer(line)]
    return out


def inspect(a: Added, args) -> list[dict]:
    hits: list[dict] = []
    line = a.text

    def hit(rule: str, sev: str, detail: str, sample: str = "") -> None:
        hits.append({
            "rule": rule, "severity": sev, "file": a.path, "line": a.line,
            "detail": detail, "sample": (sample or line.strip())[: args.sample_len],
        })

    # --- unicode -------------------------------------------------------------
    bad = sorted({ch for ch in line if ch in DANGEROUS_SET})
    if bad:
        names = ", ".join(f"U+{ord(c):04X}" for c in bad)
        hit("unicode.invisible", "high",
            f"bidi-control / zero-width / invisible character(s) present: {names}. The line does not "
            "compile as it renders.")
    for m in IDENT_RE.finditer(line):
        tok = m.group(0)
        if tok.isascii():
            continue
        scripts = {script_of(ch) for ch in tok if not ch.isascii()}
        conf = [s for s in scripts if any(s.startswith(c) for c in CONFUSABLE_SCRIPTS)]
        has_ascii_letter = any(ch.isascii() and ch.isalpha() for ch in tok)
        if conf and has_ascii_letter:
            hit("unicode.confusable-identifier", "high",
                f"token {tok!r} mixes ASCII with {', '.join(sorted(conf))} characters — a homoglyph "
                "can shadow a trusted name while looking identical", tok)
        elif conf:
            hit("unicode.non-latin-identifier", "medium",
                f"token {tok!r} is written in {', '.join(sorted(conf))} script", tok)
    nfkc = unicodedata.normalize("NFKC", line)
    if nfkc != line and not bad:
        hit("unicode.not-nfkc", "medium",
            "the line is not NFKC-normalised: it contains characters that normalise to something else")

    # --- very long line ------------------------------------------------------
    if len(line) > args.max_line:
        hit("layout.long-line", "medium",
            f"single added line of {len(line)} characters (> --max-line {args.max_line}); long lines "
            "hide payloads past the edge of a review window")

    # --- assembled strings ---------------------------------------------------
    for rule, pat, why in ASSEMBLY_PATTERNS:
        m = re.search(pat, line)
        if m:
            hit(rule, "high", f"{why} ({m.group(0).strip()!r})", m.group(0))

    n_esc = len(UNICODE_ESCAPE_RE.findall(line))
    if n_esc >= args.unicode_escapes:
        hit("assembled.unicode-escapes", "high",
            f"{n_esc} \\u{{..}} escapes on one line — a literal spelled out in code points")

    # --- encoded blobs -------------------------------------------------------
    for m in BYTE_ARRAY_RE.finditer(line):
        n = m.group(0).count(",")
        if n >= args.byte_array_len:
            hit("encoded.byte-array", "medium",
                f"inline array of {n}+ hex bytes", m.group(0))
    for m in DECIMAL_ARRAY_RE.finditer(line):
        n = m.group(0).count(",")
        if n >= args.byte_array_len:
            hit("encoded.decimal-array", "low", f"inline array of {n}+ small integers", m.group(0))
    for m in HEX_RE.finditer(line):
        blob = m.group(0)
        if len(blob) >= args.hex_len:
            hit("encoded.hex-blob", "medium" if len(blob) < 64 else "high",
                f"hex run of {len(blob)} characters", blob)

    lits = literals_of(line)
    reported_blobs: set[str] = set()
    for lit in lits:
        if len(lit) < args.min_len:
            continue
        ent = shannon(lit)
        for m in B64_RE.finditer(lit):
            blob = m.group(0)
            if len(blob) >= args.b64_len and shannon(blob) >= args.entropy - 0.5:
                reported_blobs.add(blob)
                hit("encoded.base64", "medium" if len(blob) < 64 else "high",
                    f"base64-shaped run of {len(blob)} characters (entropy {shannon(blob):.2f})", blob)
        for m in B64URL_RE.finditer(lit):
            blob = m.group(0)
            # Don't re-report what encoded.base64 already found, and don't report UUIDs: their
            # dashes make them base64url-shaped, and they have an obvious honest use.
            if blob in reported_blobs or UUID_LIKE_RE.match(blob):
                continue
            if len(blob) >= max(args.b64_len, 24) and shannon(blob) >= args.entropy - 0.5 and "/" not in blob:
                reported_blobs.add(blob)
                hit("encoded.base64url", "medium",
                    f"base64url-shaped run of {len(blob)} characters (entropy {shannon(blob):.2f})", blob)
        if ent >= args.entropy and len(lit) >= args.min_len:
            # printable-ASCII prose rarely exceeds ~4.2 bits/char at these lengths
            hit("encoded.high-entropy-literal", "high" if ent >= args.entropy + 0.4 else "medium",
                f"string literal of {len(lit)} characters with entropy {ent:.2f} bits/char "
                f"(>= --entropy {args.entropy})", lit)

    return hits


# --------------------------------------------------------------------------- main


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="obfuscation.py",
        description="Flag encoded, assembled or visually disguised payloads in a diff's added lines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--diff", help="unified diff file, or - for stdin")
    src.add_argument("--git-range", help="e.g. origin/main...HEAD")
    p.add_argument("--repo", default=None, help="repository directory for --git-range")
    p.add_argument("--entropy", type=float, default=4.0, help="Shannon entropy threshold, bits/char (default 4.0)")
    p.add_argument("--min-len", type=int, default=24, help="shortest literal scored for entropy (default 24)")
    p.add_argument("--b64-len", type=int, default=32, help="shortest base64-shaped run reported (default 32)")
    p.add_argument("--hex-len", type=int, default=32, help="shortest hex run reported (default 32)")
    p.add_argument("--byte-array-len", type=int, default=12, help="element count at which an inline byte array is reported (default 12)")
    p.add_argument("--unicode-escapes", type=int, default=6, help="\\u{..} escapes on one line before it is reported (default 6)")
    p.add_argument("--max-line", type=int, default=400, help="longest acceptable added line (default 400)")
    p.add_argument("--sample-len", type=int, default=160, help="characters of the offending text to print (default 160)")
    p.add_argument("--allow-file", default=None, help="allowlist file (path-glob + regex per line)")
    p.add_argument("--include-tests", action="store_true", help="also scan tests/, testdata/, fixtures/, vendor/")
    p.add_argument("--path-regex", default=None, help="only scan files whose path matches this regex")
    p.add_argument("--fail-on", choices=["low", "medium", "high"], default="high", help="lowest severity that fails (default high)")
    p.add_argument("--json", dest="json_out", default=None, help="write a machine-readable report here")
    args = p.parse_args(argv)

    if args.diff:
        diff = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text(errors="replace")
    else:
        diff = git_diff(args.git_range, args.repo)

    allow = load_allowlist(args.allow_file)
    added = parse_unified_diff(diff)
    findings: list[dict] = []
    skipped_tests = 0

    for a in added:
        if not args.include_tests and TEST_PATH_RE.search(a.path):
            skipped_tests += 1
            continue
        if args.path_regex and not re.search(args.path_regex, a.path):
            continue
        if allowed(a.path, a.text, allow):
            continue
        findings.extend(inspect(a, args))

    for f in sorted(findings, key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"])):
        level = {"high": "FINDING", "medium": "WARN   ", "low": "INFO   "}[f["severity"]]
        print(f"{level} {CHECK}.{f['rule']} {f['file']}:{f['line']} [{f['severity']}] :: "
              f"{f['detail']} | {f['sample']}")

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    print(
        f"-- {CHECK}: {counts['high']} high, {counts['medium']} medium, {counts['low']} low over "
        f"{len(added)} added line(s) ({skipped_tests} test-path line(s) skipped)"
    )
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps({"check": CHECK, "added_lines": len(added), "counts": counts, "findings": findings}, indent=2)
        )
    threshold = SEV_ORDER[args.fail_on]
    return 1 if any(SEV_ORDER[f["severity"]] >= threshold for f in findings) else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
