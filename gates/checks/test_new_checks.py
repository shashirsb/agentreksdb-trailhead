#!/usr/bin/env python3
# ruff: noqa
"""test_new_checks.py — prove that comment_consistency, twin_divergence and premortem work.

WHY THIS EXISTS
---------------
A gate nobody tests is a gate that silently stops catching things. The failure mode
is specific and nasty: a check that crashes, or whose regex stops matching after an
edit, exits 0 and the pipeline reads 0 as "clean". Every check in this directory can
therefore be driven over fixed testdata with a known answer, and this script asserts
those answers.

Three layers, cheapest first:

  unit      pure functions called directly (diff parsing, fingerprinting, claim
            detection, local renaming, multiset deltas). No subprocess, no IO.
  testdata  each check run as a subprocess over gates/checks/testdata/, asserting the
            exit code: 1 on the sabotage case, 0 on the clean case. This is the layer
            that matters — it is what CI runs, and it fails if a check stops catching
            its own planted attack OR starts flagging its own clean control.
  cli       --help exits 0 and bad usage exits 2, so a wrapper script can tell "the
            gate found something" (1) from "the gate is broken" (2).

Stdlib only, Python 3.11+ (tomllib is used by premortem.py itself). No pytest: the
gate runners are plain scripts and so is their test, so one `python3` is the whole
dependency list.

EXIT CODES
----------
  0  every assertion held
  1  at least one assertion failed
  2  usage error, or a check script is missing

EXAMPLES
--------
  python3 gates/checks/test_new_checks.py
  python3 gates/checks/test_new_checks.py --only twin_divergence -v
  python3 gates/checks/test_new_checks.py --format json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTDATA = HERE / "testdata"
NAME = "test_new_checks"
CHECKS = ("comment_consistency", "twin_divergence", "premortem")


def load(mod_name: str):
    """Import a sibling check as a module so its pure functions can be unit-tested."""
    path = HERE / f"{mod_name}.py"
    if not path.is_file():
        raise SystemExit(f"ERROR   {NAME} :: missing check script {path}")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Results:
    def __init__(self, verbose: bool) -> None:
        self.rows: list[dict] = []
        self.verbose = verbose

    def check(self, layer: str, target: str, label: str, got, want) -> bool:
        ok = got == want
        self.rows.append({"layer": layer, "check": target, "case": label,
                          "got": got, "want": want, "ok": ok})
        if not ok:
            print(f"FAIL    {NAME}.{layer} {target} :: {label} — got {got!r}, want {want!r}")
        elif self.verbose:
            print(f"PASS    {NAME}.{layer} {target} :: {label}")
        return ok

    @property
    def failed(self) -> list[dict]:
        return [r for r in self.rows if not r["ok"]]


def run(argv: list[str], timeout: float) -> int:
    try:
        p = subprocess.run([sys.executable, *argv], capture_output=True, text=True,
                           timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return -1
    return p.returncode


# --------------------------------------------------------------------------- unit layer


def unit_comment_consistency(r: Results) -> None:
    m = load("comment_consistency")

    files = m.parse_unified_diff((TESTDATA / "comment_consistency_sabotage.diff").read_text())
    r.check("unit", "comment_consistency", "diff parses to 4 files", len(files), 4)
    wal = [f for f in files if f.path.endswith("storage/wal.rs")][0]
    r.check("unit", "comment_consistency", "wal hunk keeps both sides",
            (len(wal.hunks[0].added) > 0, len(wal.hunks[0].removed) > 0), (True, True))

    r.check("unit", "comment_consistency", "claim verb must lead the sentence",
            bool(m.CLAIM_VERB_RE.match("Validates the token and rejects bad ones")), True)
    r.check("unit", "comment_consistency", "claim verb not in subject position",
            bool(m.CLAIM_VERB_RE.match("The borrow checker enforces that")), False)

    r.check("unit", "comment_consistency", "branchless body has no conditional",
            m.has_conditional("{ self.cache.insert(t); true }"), False)
    r.check("unit", "comment_consistency", "`if` counts as a conditional",
            m.has_conditional("{ if n > max { return false; } true }"), True)
    r.check("unit", "comment_consistency", "`?` counts as a conditional",
            m.has_conditional("{ let x = f()?; x }"), True)
    r.check("unit", "comment_consistency", "a commented-out `if` does not count",
            m.has_conditional(m.strip_code_comments("{ // if token.is_empty() { }\n    true }")), False)

    r.check("unit", "comment_consistency", "params read off a signature",
            m.signature_params("pub fn authorize(&self, role: &str, scope: Scope) -> bool"),
            ["role", "scope"])
    r.check("unit", "comment_consistency", "extractor params keep their binding",
            m.signature_params("pub async fn h(State(st): State<AppState>, headers: HeaderMap) -> R"),
            ["State", "st", "headers"])

    neg = m.judge_negations("f.rs", 1, "x", "// Never skip the signature check.",
                            "let skip_signature = true;")
    r.check("unit", "comment_consistency", "negation mismatch found",
            [f["rule"] for f in neg], ["negation.enabled"])
    r.check("unit", "comment_consistency", "negation honoured stays quiet",
            m.judge_negations("f.rs", 1, "x", "// Never skip the signature check.",
                              "verify_signature(&seg)?;"), [])
    r.check("unit", "comment_consistency", "obligation needs a mechanism word",
            m.judge_negations("f.rs", 1, "x", "// Callers must pass a prefix.",
                              "let prefix = None;"), [])

    r.check("unit", "comment_consistency", "first sentence is the first sentence",
            m.first_sentence("/// Validates the token. Returns an error otherwise."),
            "Validates the token")


def unit_twin_divergence(r: Results) -> None:
    m = load("twin_divergence")

    base = m.parse_patch_new_side((TESTDATA / "twin_base.patch").read_text())
    r.check("unit", "twin_divergence", "patch reconstructs one whole new file",
            (len(base), list(base)[0].endswith("quota.rs"), base[list(base)[0]][1]),
            (1, True, False))

    a = m.fingerprint("fn f(&self, rows: u64) -> u64", "{ let next = rows + 1; if next > self.limit { return 0; } next }", "")
    b = m.fingerprint("fn f(&self, count: u64) -> u64", "{ let total = count + 1; if total > self.limit { return 0; } total }", "")
    r.check("unit", "twin_divergence", "renamed locals fingerprint identically",
            (a["control"] == b["control"], a["comparisons"] == b["comparisons"]), (True, True))

    c = m.fingerprint("fn f(&self, rows: u64) -> u64", "{ let next = rows + 1; if next >= self.limit { return 0; } next }", "")
    r.check("unit", "twin_divergence", "a changed comparison operator diverges",
            a["comparisons"] == c["comparisons"], False)

    r.check("unit", "twin_divergence", "integer spellings normalise",
            m.fingerprint("fn f()", "{ }", "{ 1_000 }")["constants"],
            m.fingerprint("fn f()", "{ }", "{ 0x3e8 }")["constants"])
    r.check("unit", "twin_divergence", "tail return is cosmetic",
            m.strip_tail_return("{ let x = 1; return x; }"), "{ let x = 1; x }")
    r.check("unit", "twin_divergence", "parameter names drop out of a signature",
            m.normalised_signature("charge", "pub fn charge(&mut self, tenant: &str, rows: u64) -> Result<u64, E>", True),
            "fn charge(self, &str, u64) -> Result<u64, E>")
    r.check("unit", "twin_divergence", "field access survives local renaming",
            m.rename_locals("let used = self.used.get(k);", ["used"]),
            "let _v1 = self.used.get(k);")
    r.check("unit", "twin_divergence", "IO calls are classified",
            m.fingerprint("fn f()", '{ let f = File::create("x")?; }', "")["io"], ["fs:open"])
    r.check("unit", "twin_divergence", "multiset delta both ways",
            m.multiset_delta(["a", "a", "b"], ["a", "c"]), (["a", "b"], ["c"]))


def unit_premortem(r: Results) -> None:
    m = load("premortem")

    cands = m.discover_candidates(TESTDATA / "premortem_escape")
    r.check("unit", "premortem", "candidates discovered",
            sorted(c.cid for c in cands),
            ["cand-01-magic-token", "cand-03-quorum-off-by-one"])
    gap = [c for c in cands if c.cid == "cand-03-quorum-off-by-one"][0]
    r.check("unit", "premortem", "candidate.toml read", (gap.known_gap, bool(gap.title)), (True, True))

    r.check("unit", "premortem", "a blocking firing is a catch",
            m.judge([{"check": "obfuscation", "status": "fired", "advisory": False}], False),
            ("caught", ["obfuscation"]))
    r.check("unit", "premortem", "an advisory firing alone is an escape",
            m.judge([{"check": "literal_triggers", "status": "fired", "advisory": True}], False),
            ("ESCAPED", []))
    r.check("unit", "premortem", "--count-advisory makes it a catch",
            m.judge([{"check": "literal_triggers", "status": "fired", "advisory": True}], True),
            ("caught", ["literal_triggers"]))
    r.check("unit", "premortem", "nothing fired is an escape",
            m.judge([{"check": "obfuscation", "status": "clean", "advisory": False},
                     {"check": "comment_consistency", "status": "skipped", "advisory": False}], False),
            ("ESCAPED", []))
    r.check("unit", "premortem", "advisory-only firing is labelled in the table",
            "advisory only" in m.table_cell(
                {"fired": [], "checks": [{"check": "literal_triggers", "status": "fired", "advisory": True}]},
                False),
            True)


# --------------------------------------------------------------------------- testdata layer


def testdata_cases() -> list[tuple[str, list[str], int, str]]:
    """(check, argv, expected exit, label). Exit 1 = the planted attack was caught."""
    cc = str(HERE / "comment_consistency.py")
    tw = str(HERE / "twin_divergence.py")
    pm = str(HERE / "premortem.py")
    return [
        ("comment_consistency", [cc, "--diff", str(TESTDATA / "comment_consistency_sabotage.diff")],
         1, "sabotage diff is caught"),
        ("comment_consistency", [cc, "--diff", str(TESTDATA / "comment_consistency_clean.diff")],
         0, "clean diff passes"),
        ("comment_consistency", [cc, "--diff", str(TESTDATA / "comment_consistency_sabotage.diff"),
                                 "--fail-on", "high"], 1, "sabotage still caught at --fail-on high"),
        ("comment_consistency", [cc, "--diff", str(TESTDATA / "clean_sample.diff")],
         0, "the shared clean sample passes"),
        ("twin_divergence", [tw, "--base-patch", str(TESTDATA / "twin_base.patch"),
                             "--twin-patch", str(TESTDATA / "twin_divergent.patch")],
         1, "behavioural divergence is caught"),
        ("twin_divergence", [tw, "--base-patch", str(TESTDATA / "twin_base.patch"),
                             "--twin-patch", str(TESTDATA / "twin_cosmetic.patch")],
         0, "cosmetic-only twin passes"),
        ("twin_divergence", [tw, "--base-patch", str(TESTDATA / "twin_base.patch"),
                             "--twin-patch", str(TESTDATA / "twin_base.patch")],
         0, "a patch does not diverge from itself"),
        ("twin_divergence", [tw, "--base-patch", str(TESTDATA / "twin_base.patch"),
                             "--twin-patch", str(TESTDATA / "twin_divergent.patch"),
                             "--mode", "module"], 1, "module mode still catches it"),
        ("premortem", [pm, "--candidates", str(TESTDATA / "premortem_caught")],
         0, "corpus where every candidate is caught"),
        ("premortem", [pm, "--candidates", str(TESTDATA / "premortem_escape")],
         1, "corpus with an escape fails the run"),
        ("premortem", [pm, "--candidates", str(TESTDATA / "premortem_escape"),
                       "--allow-known-escapes"], 0, "a documented known gap does not fail"),
        ("premortem", [pm, "--candidates", str(TESTDATA / "premortem_escape"),
                       "--reference-patch", str(TESTDATA / "twin_base.patch")],
         0, "with a twin reference the escape is caught"),
    ]


def cli_cases() -> list[tuple[str, list[str], int, str]]:
    out: list[tuple[str, list[str], int, str]] = []
    for name in CHECKS:
        script = str(HERE / f"{name}.py")
        out.append((name, [script, "--help"], 0, "--help exits 0"))
        out.append((name, [script, "--no-such-flag"], 2, "bad usage exits 2"))
        out.append((name, [script, "--self-test"], 0, "built-in self-test passes"))
    return out


# --------------------------------------------------------------------------- main


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="test_new_checks.py",
        description="Run comment_consistency, twin_divergence and premortem against their testdata.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--only", action="append", default=[], choices=list(CHECKS),
                   help="test only this check; repeatable")
    p.add_argument("--layer", action="append", default=[], choices=["unit", "testdata", "cli"],
                   help="run only this layer; repeatable")
    p.add_argument("--timeout", type=float, default=180.0, help="per subprocess timeout (default 180)")
    p.add_argument("--format", choices=["text", "json"], default="text", help="stdout format (default text)")
    p.add_argument("--json", dest="json_out", default=None, help="also write the report here")
    p.add_argument("-v", "--verbose", action="store_true", help="print passing assertions too")
    args = p.parse_args(argv)

    if not TESTDATA.is_dir():
        raise SystemExit(f"ERROR   {NAME} :: no testdata directory at {TESTDATA}")
    wanted = set(args.only) or set(CHECKS)
    layers = set(args.layer) or {"unit", "testdata", "cli"}
    r = Results(args.verbose)

    if "unit" in layers:
        if "comment_consistency" in wanted:
            unit_comment_consistency(r)
        if "twin_divergence" in wanted:
            unit_twin_divergence(r)
        if "premortem" in wanted:
            unit_premortem(r)

    if "testdata" in layers:
        for target, argv_, want, label in testdata_cases():
            if target not in wanted:
                continue
            r.check("testdata", target, label, run(argv_, args.timeout), want)

    if "cli" in layers:
        for target, argv_, want, label in cli_cases():
            if target not in wanted:
                continue
            r.check("cli", target, label, run(argv_, args.timeout), want)

    payload = {
        "check": NAME,
        "cases": len(r.rows),
        "failed": len(r.failed),
        "by_layer": {
            layer: {
                "cases": sum(1 for x in r.rows if x["layer"] == layer),
                "failed": sum(1 for x in r.rows if x["layer"] == layer and not x["ok"]),
            }
            for layer in sorted({x["layer"] for x in r.rows})
        },
        "results": r.rows,
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2, default=str))
    else:
        for layer, counts in payload["by_layer"].items():
            print(f"INFO    {NAME} :: {layer}: {counts['cases'] - counts['failed']}/{counts['cases']} passed")
        print(f"-- {NAME}: {len(r.rows) - len(r.failed)}/{len(r.rows)} assertion(s) passed")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2, default=str))
    return 1 if r.failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
