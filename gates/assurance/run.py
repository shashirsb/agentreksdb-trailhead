#!/usr/bin/env python3
"""Gate assurance runner for Trailhead.

Replays every planted case in gates/assurance/corpus against the real gates and
compares the outcome to the expectation recorded in the case's `case.toml`:

  * kind = "diff"   -> `trailhead policy check --manifest <manifest.json>
                        --policy gates/diff-policy.toml`
  * kind = "intent" -> `trailhead guardrails <intent.txt>`

Then replays gates/assurance/controls, which are clean patches and honest intents
that must produce no finding at all, to measure the false-positive rate.

Writes gates/assurance/scorecard.json and prints a per-category table.

Stdlib only, Python 3.11+ (tomllib).

Exit codes
  0  every non-known-gap case matched its expectation and no control produced a finding
  1  anything else

Usage
  gates/assurance/run.py
  gates/assurance/run.py --category backdoor --category data-loss
  gates/assurance/run.py --strict          # known gaps fail the run too
  gates/assurance/run.py --json            # machine-readable report on stdout
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import tomllib
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))          # repo root
CORPUS = os.path.join(HERE, "corpus")
CONTROLS = os.path.join(HERE, "controls")
SCORECARD = os.path.join(HERE, "scorecard.json")
DIFF_POLICY = os.path.join(ROOT, "gates", "diff-policy.toml")

# Both engines speak their own vocabulary. The corpus uses one.
#   diff-policy:  pass | warn  | block
#   guardrails:   green | amber | red
GUARDRAIL_TO_OUTCOME = {"green": "pass", "amber": "warn", "red": "block"}

ORDER = [
    "backdoor",
    "auth-bypass",
    "injection",
    "dos",
    "slow-perf",
    "data-loss",
    "supply-chain",
    "prompt-injection",
]


# ──────────────────────────────────────────────────────────────────────────────
# Exact binomial (Clopper-Pearson) confidence interval.
#
# The interval inverts the binomial CDF, so it needs the inverse of the
# regularised incomplete beta function:
#     lower = I^-1(alpha/2;   k,   n-k+1)
#     upper = I^-1(1-alpha/2; k+1, n-k)
# Implemented with a Lentz continued fraction for I_x(a,b) and bisection for the
# inverse. No normal approximation: at n ~ 10 the normal interval is simply wrong.
# ──────────────────────────────────────────────────────────────────────────────
def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (Lentz's method)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return h


def betainc_reg(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbeta + b * math.log1p(-x) + a * math.log(x)) * _betacf(b, a, 1.0 - x) / b


def beta_ppf(p: float, a: float, b: float) -> float:
    """Inverse of I_x(a, b) in x, by bisection. Monotone, so this is safe."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if betainc_reg(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-15:
            break
    return 0.5 * (lo + hi)


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact two-sided 100*(1-alpha)% interval for a binomial proportion."""
    if n == 0:
        return (0.0, 1.0)
    lower = 0.0 if k == 0 else beta_ppf(alpha / 2.0, k, n - k + 1)
    upper = 1.0 if k == n else beta_ppf(1.0 - alpha / 2.0, k + 1, n - k)
    return (lower, upper)


# ──────────────────────────────────────────────────────────────────────────────
# Finding the binary
# ──────────────────────────────────────────────────────────────────────────────
def resolve_runner() -> tuple[list[str], str]:
    """Return (argv prefix, how it was found)."""
    env = os.environ.get("TRAILHEAD_BIN")
    if env:
        if not (os.path.isfile(env) and os.access(env, os.X_OK)):
            sys.exit("TRAILHEAD_BIN=%s is not an executable file" % env)
        return [env], "TRAILHEAD_BIN"
    built = os.path.join(ROOT, "target", "debug", "trailhead")
    if os.path.isfile(built) and os.access(built, os.X_OK):
        return [built], "target/debug/trailhead"
    if shutil.which("cargo"):
        return ["cargo", "run", "-q", "--bin", "trailhead", "--"], "cargo run"
    sys.exit(
        "no trailhead binary: set TRAILHEAD_BIN, build target/debug/trailhead, "
        "or install cargo"
    )


def run_json(argv: list[str]) -> dict:
    """Run the CLI and parse the JSON it prints. `policy check` exits 1 on block,
    so a non-zero status is expected and only a missing/unparsable body is fatal."""
    proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    out = proc.stdout.strip()
    start = out.find("{")
    if start < 0:
        raise RuntimeError(
            "no JSON on stdout from %s (exit %d)\nstdout: %s\nstderr: %s"
            % (" ".join(argv), proc.returncode, out[:400], proc.stderr.strip()[:400])
        )
    return json.loads(out[start:])


# ──────────────────────────────────────────────────────────────────────────────
# Loading cases
# ──────────────────────────────────────────────────────────────────────────────
def load_dir(d: str) -> dict | None:
    meta_path = os.path.join(d, "case.toml")
    if not os.path.isfile(meta_path):
        return None
    with open(meta_path, "rb") as fh:
        meta = tomllib.load(fh)
    meta["dir"] = d
    kind = meta.get("kind")
    if kind not in ("diff", "intent"):
        kind = "intent" if os.path.isfile(os.path.join(d, "intent.txt")) else "diff"
        meta["kind"] = kind
    payload = "intent.txt" if kind == "intent" else "manifest.json"
    meta["payload"] = os.path.join(d, payload)
    if not os.path.isfile(meta["payload"]):
        sys.exit("case %s declares kind=%s but has no %s" % (d, kind, payload))
    return meta


def load_corpus(categories: list[str] | None) -> list[dict]:
    cases = []
    if not os.path.isdir(CORPUS):
        return cases
    for cat in sorted(os.listdir(CORPUS)):
        cat_dir = os.path.join(CORPUS, cat)
        if not os.path.isdir(cat_dir):
            continue
        if categories and cat not in categories:
            continue
        for cid in sorted(os.listdir(cat_dir)):
            c = load_dir(os.path.join(cat_dir, cid))
            if c:
                c.setdefault("category", cat)
                cases.append(c)
    return cases


def load_controls() -> list[dict]:
    cases = []
    if not os.path.isdir(CONTROLS):
        return cases
    for cid in sorted(os.listdir(CONTROLS)):
        c = load_dir(os.path.join(CONTROLS, cid))
        if c:
            c["category"] = "control"
            cases.append(c)
    return cases


# ──────────────────────────────────────────────────────────────────────────────
# Evaluating one case
# ──────────────────────────────────────────────────────────────────────────────
def evaluate(case: dict, runner: list[str]) -> dict:
    if case["kind"] == "diff":
        raw = run_json(runner + ["policy", "check",
                                 "--manifest", case["payload"],
                                 "--policy", DIFF_POLICY])
        outcome = raw["verdict"]
        fired = [f["rule"] for f in raw.get("blocked_by", [])]
        fired_warn = [f["rule"] for f in raw.get("warned", [])]
    else:
        raw = run_json(runner + ["guardrails", case["payload"]])
        outcome = GUARDRAIL_TO_OUTCOME[raw["risk"]]
        hits = raw.get("hits", [])
        fired = [h["rule"] for h in hits if h["level"] == "red"]
        fired_warn = [h["rule"] for h in hits if h["level"] == "amber"]

    all_fired = fired + fired_warn
    expect = case["expect"]
    expect_rules = case.get("expect_rules", [])
    missing_rules = [r for r in expect_rules if r not in all_fired]
    matched = outcome == expect and not missing_rules

    known_gap = bool(case.get("known_gap"))
    if known_gap:
        status = "gap-closed" if matched else "known-gap"
    elif case["category"] == "control":
        status = "clean" if outcome == "pass" else "false-positive"
    else:
        status = "caught" if matched else "missed"

    return {
        "id": case["id"],
        "category": case["category"],
        "kind": case["kind"],
        "title": case.get("title", ""),
        "technique": case.get("technique", ""),
        "source": case.get("source", ""),
        "expect": expect,
        "actual": outcome,
        "expect_rules": expect_rules,
        "fired_block": fired,
        "fired_warn": fired_warn,
        "missing_rules": missing_rules,
        "known_gap": known_gap,
        "gap_reason": case.get("gap_reason", ""),
        "delegated_to": case.get("delegated_to", ""),
        "status": status,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Reporting
# ──────────────────────────────────────────────────────────────────────────────
def pct(x: float) -> str:
    return "%5.1f%%" % (100.0 * x)


def build_scorecard(results: list[dict], controls: list[dict], runner_desc: str) -> dict:
    cats: dict[str, dict] = {}
    for r in results:
        c = cats.setdefault(r["category"], {
            "cases": 0, "caught": 0, "missed": 0, "known_gaps": 0, "gaps_closed": 0,
            "known_gap_ids": [], "missed_ids": [], "gap_closed_ids": [],
        })
        c["cases"] += 1
        if r["status"] == "caught":
            c["caught"] += 1
        elif r["status"] == "missed":
            c["missed"] += 1
            c["missed_ids"].append(r["id"])
        elif r["status"] == "known-gap":
            c["known_gaps"] += 1
            c["known_gap_ids"].append(r["id"])
        elif r["status"] == "gap-closed":
            c["caught"] += 1
            c["gaps_closed"] += 1
            c["gap_closed_ids"].append(r["id"])

    for name, c in cats.items():
        n, k = c["cases"], c["caught"]
        lo, hi = clopper_pearson(k, n)
        c["detection_rate"] = (k / n) if n else 0.0
        c["detection_rate_ci95"] = [round(lo, 4), round(hi, 4)]
        c["miss_rate_upper_bound_95"] = round(1.0 - lo, 4)
        # Same rate with the documented gaps taken out of the denominator: what
        # the gate achieves on the attacks it claims to cover.
        n2 = n - c["known_gaps"]
        lo2, hi2 = clopper_pearson(k, n2)
        c["detection_rate_excluding_known_gaps"] = (k / n2) if n2 else 0.0
        c["detection_rate_excluding_known_gaps_ci95"] = [round(lo2, 4), round(hi2, 4)]

    n_all = len(results)
    k_all = sum(1 for r in results if r["status"] in ("caught", "gap-closed"))
    lo, hi = clopper_pearson(k_all, n_all)

    fp = [r for r in controls if r["status"] == "false-positive"]
    n_ctl = len(controls)
    flo, fhi = clopper_pearson(len(fp), n_ctl)

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "runner": runner_desc,
        "policy": os.path.relpath(DIFF_POLICY, ROOT),
        "confidence_level": 0.95,
        "interval_method": "Clopper-Pearson exact binomial",
        "categories": cats,
        "overall": {
            "cases": n_all,
            "caught": k_all,
            "missed": sum(1 for r in results if r["status"] == "missed"),
            "known_gaps": sum(1 for r in results if r["status"] == "known-gap"),
            "gaps_closed": sum(1 for r in results if r["status"] == "gap-closed"),
            "detection_rate": (k_all / n_all) if n_all else 0.0,
            "detection_rate_ci95": [round(lo, 4), round(hi, 4)],
            "miss_rate_upper_bound_95": round(1.0 - lo, 4),
        },
        "controls": {
            "cases": n_ctl,
            "clean": n_ctl - len(fp),
            "false_positives": len(fp),
            "false_positive_rate": (len(fp) / n_ctl) if n_ctl else 0.0,
            "false_positive_rate_ci95": [round(flo, 4), round(fhi, 4)],
            "false_positive_ids": [r["id"] for r in fp],
        },
        "cases": results,
        "control_cases": controls,
    }


def print_table(sc: dict) -> None:
    cats = sc["categories"]
    order = [c for c in ORDER if c in cats] + [c for c in sorted(cats) if c not in ORDER]
    print()
    print("Trailhead gate assurance  -  %s  -  runner: %s" % (sc["generated_at"], sc["runner"]))
    print()
    hdr = "%-18s %5s %6s %6s %5s  %7s  %-18s" % (
        "category", "cases", "caught", "missed", "gaps", "rate", "95% CI (exact)")
    print(hdr)
    print("-" * len(hdr))
    for name in order:
        c = cats[name]
        lo, hi = c["detection_rate_ci95"]
        print("%-18s %5d %6d %6d %5d  %7s  [%s, %s]" % (
            name, c["cases"], c["caught"], c["missed"], c["known_gaps"],
            pct(c["detection_rate"]), pct(lo), pct(hi)))
    print("-" * len(hdr))
    o = sc["overall"]
    lo, hi = o["detection_rate_ci95"]
    print("%-18s %5d %6d %6d %5d  %7s  [%s, %s]" % (
        "ALL", o["cases"], o["caught"], o["missed"], o["known_gaps"],
        pct(o["detection_rate"]), pct(lo), pct(hi)))
    print()
    ctl = sc["controls"]
    clo, chi = ctl["false_positive_rate_ci95"]
    print("controls: %d clean / %d  -  false positives %d (%s, 95%% CI [%s, %s])" % (
        ctl["clean"], ctl["cases"], ctl["false_positives"],
        pct(ctl["false_positive_rate"]), pct(clo), pct(chi)))
    if ctl["false_positive_ids"]:
        for cid in ctl["false_positive_ids"]:
            r = next(x for x in sc["control_cases"] if x["id"] == cid)
            print("    FALSE POSITIVE %s -> %s %s" % (
                cid, r["actual"], r["fired_block"] + r["fired_warn"]))
    print()

    missed = [r for r in sc["cases"] if r["status"] == "missed"]
    if missed:
        print("MISSES (not declared as gaps - the corpus or the policy is wrong):")
        for r in missed:
            why = "expected %s, got %s" % (r["expect"], r["actual"])
            if r["missing_rules"]:
                why += "; rules not fired: %s" % ", ".join(r["missing_rules"])
            print("    %-42s %s" % (r["id"], why))
        print()

    closed = [r for r in sc["cases"] if r["status"] == "gap-closed"]
    if closed:
        print("GAPS CLOSED since the case was written - drop known_gap from case.toml:")
        for r in closed:
            print("    %-42s now %s %s" % (r["id"], r["actual"], r["fired_block"]))
        print()

    gaps = [r for r in sc["cases"] if r["status"] == "known-gap"]
    if gaps:
        print("KNOWN GAPS (%d) - planted sabotage today's gates do not stop:" % len(gaps))
        for r in gaps:
            tail = (" -> covered by %s" % r["delegated_to"]) if r["delegated_to"] else ""
            print("    %-42s %-12s %s%s" % (
                r["id"], r["technique"], "got " + r["actual"], tail))
        print()


def main() -> int:
    ap = argparse.ArgumentParser(description="Trailhead gate assurance runner")
    ap.add_argument("--category", action="append", default=None,
                    help="only this category (repeatable)")
    ap.add_argument("--json", action="store_true", help="print the scorecard as JSON")
    ap.add_argument("--strict", action="store_true",
                    help="known gaps fail the run as well")
    ap.add_argument("--allow-known-gaps", dest="allow_known_gaps",
                    action="store_true", default=True,
                    help="known gaps report but do not fail (default)")
    ap.add_argument("--no-controls", action="store_true",
                    help="skip the control corpus")
    ap.add_argument("--out", default=SCORECARD,
                    help="where to write the scorecard (default gates/assurance/scorecard.json)")
    args = ap.parse_args()
    if args.strict:
        args.allow_known_gaps = False

    runner, runner_desc = resolve_runner()
    if not os.path.isfile(DIFF_POLICY):
        sys.exit("missing %s" % DIFF_POLICY)

    cases = load_corpus(args.category)
    if not cases:
        known = sorted(d for d in os.listdir(CORPUS)
                       if os.path.isdir(os.path.join(CORPUS, d))) if os.path.isdir(CORPUS) else []
        if args.category:
            sys.exit("no cases matched --category %s; categories are: %s"
                     % (", ".join(args.category), ", ".join(known)))
        sys.exit("no cases found under %s" % CORPUS)
    controls = [] if args.no_controls else load_controls()

    results = [evaluate(c, runner) for c in cases]
    control_results = [evaluate(c, runner) for c in controls]

    sc = build_scorecard(results, control_results, runner_desc)
    sc["filtered_to_categories"] = args.category or None
    sc["strict"] = bool(args.strict)

    # Only a full run is a publishable scorecard.
    if not args.category and not args.no_controls:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(sc, fh, indent=2)
            fh.write("\n")

    if args.json:
        json.dump(sc, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print_table(sc)
        if not args.category and not args.no_controls:
            print("scorecard: %s" % os.path.relpath(args.out, ROOT))

    failed = sc["overall"]["missed"] > 0 or sc["controls"]["false_positives"] > 0
    if not args.allow_known_gaps:
        failed = failed or sc["overall"]["known_gaps"] > 0
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        code = main()
    except BrokenPipeError:
        # Piped into head/less: report the real outcome rather than a SIGPIPE.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        code = 0
    sys.exit(code)
