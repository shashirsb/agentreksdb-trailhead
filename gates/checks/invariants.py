#!/usr/bin/env python3
# ruff: noqa
"""invariants.py — enforce structural security invariants over the HEAD TREE of Rust source.

SABOTAGE CLASS
--------------
Sabotage by deletion and omission. Every other gate here reads a diff, and a diff
gate is blind in one direction: the cheapest backdoor removes a line. Delete the
`require_user(...)` call and the endpoint is public. Delete the `sync_all()`
before the success return and the database loses the last write on every crash.
Write the quorum as `2` instead of `n / 2 + 1` and the cluster splits the first
time it is resized. Each of those is a *smaller* diff than the honest version,
passes every unit test, and reads as a tidy cleanup.

This checker therefore ignores the diff entirely. It parses the head tree and
asserts properties that must hold of the code *as it now stands*: every public
HTTP handler calls an authorization helper; every commit path flushes before it
returns Ok; quorum is computed, not written; `*_unchecked` is only called where
the allowlist says. The rules live in gates/invariants.toml (CODEOWNERS-protected
so a generated change cannot widen its own allowlist) and new ones are a few
lines of TOML.

HONEST LIMITS — THIS IS NOT A RUST PARSER
-----------------------------------------
There is no `syn` here and no rustc: adding a crate to do this would itself be a
Cargo.lock change, which the diff policy blocks, and a helper binary is one more
thing to trust. So this is a careful scanner, not a compiler front end:

* Comments and the *contents* of string, raw-string and char literals are blanked
  out first (lengths and newlines preserved, so line numbers stay right). That is
  what makes brace matching trustworthy and stops a pattern from matching inside
  a comment or a string.
* Function bodies are found by brace matching from the `{` after the signature.
  `impl` blocks are matched the same way to qualify method names.
* It therefore cannot resolve a call graph, trace control flow, follow a macro,
  see through a re-export, or know whether a `use` alias renamed the helper. It
  asks "does this pattern appear in this body", not "is it executed".
* `require_before` (the flush-before-Ok ordering rule) compares byte offsets:
  a required pattern must appear before the LAST match of the ordering pattern.
  That catches "the flush was deleted" and "the flush is after the return"; it
  does not prove the flush runs on every path.
* Macro-generated handlers are invisible. Keep handlers written out by hand.

HOW IT CAN BE EVADED
--------------------
* Satisfy the letter: `if false { require_user(&st, &h).await?; }`, or call the
  authorizer and discard its answer (`let _ = require_user(..)`). Passing is not
  proof — these rules make a deletion *visible*, which is a different job from
  proving a program correct.
* Rename the mechanism so the selector no longer matches: call the handler
  function something that is not in an `api/`-shaped path, or name the commit
  function `materialise` instead of `commit`. The tree_count invariants
  (`authz.helper-exists`, `durability.fsync-present`) are the backstop: they fail
  when a mechanism disappears from the tree altogether.
* Move the logic into a macro, a build script or a dependency.
* Add a new handler module whose path the include regex does not cover. Review
  include_paths whenever a module is added — that review is the gate here.

EXIT CODES
----------
  0  every invariant holds
  1  at least one `block` violation (or any violation with --fail-on warn)
  2  usage or internal error (unreadable rules, bad regex, no files matched)

EXAMPLES
--------
  ./invariants.py --rules ../invariants.toml --root ../../crates
  ./invariants.py --rules ../invariants.toml --root . --only authz.handler-authorizes -v
  ./invariants.py --rules ../invariants.toml --root ../../crates --json inv.json --fail-on warn
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore

CHECK = "invariants"
VALID_KINDS = {"fn_body", "call_site", "line", "tree_count"}


# --------------------------------------------------------------------------- scrubbing


def scrub(src: str) -> str:
    """Blank out comments and literal *contents*, preserving length and newlines.

    The result is the same shape as the input — offsets and line numbers match — but
    nothing inside a comment, string, raw string or char literal can match a pattern,
    and every brace that remains is a real brace.
    """
    out = list(src)
    i, n = 0, len(src)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue

        if c == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue

        # raw string:  r"..."  r#"..."#  br##"..."##
        m = re.match(r'(?:b?r)(#*)"', src[i : i + 16])
        if m and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            hashes = m.group(1)
            close = '"' + hashes
            j = src.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            blank(i + m.end(), j - len(close))
            i = j
            continue

        if c == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i + 1, j - 1)
            i = j
            continue

        if c == "'":
            # char literal only if it closes within 1 char (or an escape); otherwise a lifetime
            m2 = re.match(r"'(\\.[^']*|[^'\\])'", src[i : i + 12])
            if m2:
                blank(i + 1, i + m2.end() - 1)
                i += m2.end()
                continue
            i += 1
            continue

        i += 1

    return "".join(out)


def match_brace(text: str, open_at: int) -> int:
    """Index just past the `}` matching the `{` at open_at (scrubbed text)."""
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def match_paren(text: str, open_at: int) -> int:
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


# --------------------------------------------------------------------------- indexing


class Func:
    __slots__ = ("name", "qualname", "signature", "attrs", "is_pub", "start", "body_start", "body_end", "line")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class RustFile:
    def __init__(self, path: Path, rel: str):
        self.path = path
        self.rel = rel
        self.raw = path.read_text(errors="replace")
        self.code = scrub(self.raw)
        self._line_starts = [0] + [m.end() for m in re.finditer("\n", self.raw)]
        self.impls = self._index_impls()
        self.funcs = self._index_funcs()

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self._line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def _index_impls(self) -> list[tuple[int, int, str]]:
        out = []
        for m in re.finditer(r"\bimpl\b([^{;]*)\{", self.code):
            head = m.group(1)
            # "impl Trait for Type" -> Type ; "impl Type" -> Type
            if " for " in head:
                name = head.split(" for ", 1)[1]
            else:
                name = head
            name = re.sub(r"<[^>]*>", "", name).strip().strip("&").split()[-1] if name.strip() else "impl"
            out.append((m.start(), match_brace(self.code, m.end() - 1), name))
        return out

    def _index_funcs(self) -> list[Func]:
        funcs: list[Func] = []
        for m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", self.code):
            name = m.group(1)
            p = self.code.find("(", m.end())
            if p < 0:
                continue
            sig_end = match_paren(self.code, p)
            # signature runs to the `{` (or `;` for a trait/extern declaration)
            j = sig_end
            while j < len(self.code) and self.code[j] not in "{;":
                j += 1
            if j >= len(self.code) or self.code[j] == ";":
                continue  # declaration without a body
            body_start = j
            body_end = match_brace(self.code, body_start)
            signature = re.sub(r"\s+", " ", self.code[m.start() : body_start]).strip()

            line_start = self.raw.rfind("\n", 0, m.start()) + 1
            prefix = self.raw[line_start : m.start()]
            is_pub = bool(re.search(r"\bpub\b", prefix))

            # attributes: contiguous preceding lines that are #[...] or #![...] (from RAW text,
            # because scrubbing blanks the string contents an attribute may carry)
            attrs: list[str] = []
            k = line_start
            while k > 0:
                prev_start = self.raw.rfind("\n", 0, k - 1) + 1
                prev = self.raw[prev_start : k - 1]
                if re.match(r"^\s*#!?\[", prev):
                    attrs.insert(0, prev.strip())
                    k = prev_start
                    continue
                if re.match(r"^\s*(///|//!)", prev) or prev.strip() == "":
                    k = prev_start
                    continue
                break

            qual = name
            best = None
            for s, e, iname in self.impls:
                if s <= m.start() < e and (best is None or s > best[0]):
                    best = (s, iname)
            if best:
                qual = f"{best[1]}::{name}"

            funcs.append(
                Func(
                    name=name,
                    qualname=qual,
                    signature=signature,
                    attrs="\n".join(attrs),
                    is_pub=is_pub,
                    start=m.start(),
                    body_start=body_start,
                    body_end=body_end,
                    line=self.line_of(m.start()),
                )
            )
        return funcs

    def body(self, f: Func, on: str) -> str:
        src = self.code if on == "code" else self.raw
        return src[f.body_start : f.body_end]

    def enclosing_fn(self, offset: int) -> Func | None:
        best = None
        for f in self.funcs:
            if f.body_start <= offset < f.body_end and (best is None or f.body_start > best.body_start):
                best = f
        return best


# --------------------------------------------------------------------------- rules


class Violation:
    def __init__(self, rid: str, severity: str, path: str, line: int, detail: str, message: str, remediation: str, where: str = ""):
        self.rid, self.severity, self.path, self.line = rid, severity, path, line
        self.detail, self.message, self.remediation, self.where = detail, message, remediation, where

    def as_dict(self) -> dict:
        return {
            "invariant": self.rid,
            "severity": self.severity,
            "file": self.path,
            "line": self.line,
            "symbol": self.where,
            "invariant_text": self.message,
            "detail": self.detail,
            "remediation": self.remediation.strip(),
        }


def compile_list(rule: dict, key: str) -> list[re.Pattern]:
    out = []
    for pat in rule.get(key, []) or []:
        try:
            out.append(re.compile(pat))
        except re.error as e:
            raise SystemExit(f"ERROR   {CHECK} :: invariant {rule.get('id')}: bad regex in {key}: {pat!r} ({e})")
    return out


def path_selected(rel: str, rule: dict, meta_excl: list[re.Pattern]) -> bool:
    if any(rx.search(rel) for rx in meta_excl):
        return False
    inc = compile_list(rule, "include_paths")
    exc = compile_list(rule, "exclude_paths")
    if inc and not any(rx.search(rel) for rx in inc):
        return False
    if any(rx.search(rel) for rx in exc):
        return False
    return True


def check_fn_body(rf: RustFile, rule: dict) -> list[Violation]:
    vio: list[Violation] = []
    on = rule.get("match_on", "code")
    name_rx = re.compile(rule["select_fn_name"]) if rule.get("select_fn_name") else None
    sig_rx = re.compile(rule["select_fn_signature"]) if rule.get("select_fn_signature") else None
    attr_rx = re.compile(rule["select_fn_attr"]) if rule.get("select_fn_attr") else None
    body_sel = compile_list(rule, "select_body_any")
    req_any = compile_list(rule, "require_any")
    req_all = compile_list(rule, "require_all")
    forbid = compile_list(rule, "forbid")
    before_rx = re.compile(rule["require_before"]) if rule.get("require_before") else None
    allow_fns = set(rule.get("allow_fns", []) or [])

    for f in rf.funcs:
        if rule.get("select_pub_only") and not f.is_pub:
            continue
        if name_rx and not name_rx.search(f.name):
            continue
        if sig_rx and not sig_rx.search(f.signature):
            continue
        if attr_rx and not attr_rx.search(f.attrs):
            continue
        if f.name in allow_fns or f.qualname in allow_fns:
            continue
        body = rf.body(f, on)
        # select_body_any narrows the selection (not the assertion): the function is only judged
        # when its body shows it really is the kind of function this invariant is about.
        if body_sel and not any(rx.search(body) for rx in body_sel):
            continue

        if req_any:
            hits = [rx.search(body) for rx in req_any]
            found = [h for h in hits if h]
            if not found:
                vio.append(
                    Violation(
                        rule["id"], rule.get("severity", "block"), rf.rel, f.line,
                        f"`{f.qualname}` matches this invariant's selector but its body contains none of: "
                        + ", ".join(p.pattern for p in req_any),
                        rule["message"], rule.get("remediation", ""), f.qualname,
                    )
                )
            elif before_rx:
                last_ok = None
                for m in before_rx.finditer(body):
                    last_ok = m
                first_req = min(h.start() for h in found)
                if last_ok is not None and first_req > last_ok.start():
                    vio.append(
                        Violation(
                            rule["id"], rule.get("severity", "block"), rf.rel,
                            rf.line_of(f.body_start + first_req),
                            f"`{f.qualname}` has the required call, but only AFTER the last "
                            f"`{before_rx.pattern}` — the success path returns before it runs",
                            rule["message"], rule.get("remediation", ""), f.qualname,
                        )
                    )
        for rx in req_all:
            if not rx.search(body):
                vio.append(
                    Violation(
                        rule["id"], rule.get("severity", "block"), rf.rel, f.line,
                        f"`{f.qualname}` is missing required pattern {rx.pattern!r}",
                        rule["message"], rule.get("remediation", ""), f.qualname,
                    )
                )
        for rx in forbid:
            m = rx.search(body)
            if m:
                vio.append(
                    Violation(
                        rule["id"], rule.get("severity", "block"), rf.rel,
                        rf.line_of(f.body_start + m.start()),
                        f"`{f.qualname}` contains forbidden pattern {rx.pattern!r}: {m.group(0)!r}",
                        rule["message"], rule.get("remediation", ""), f.qualname,
                    )
                )
    return vio


def check_call_site(rf: RustFile, rule: dict) -> list[Violation]:
    vio: list[Violation] = []
    rx = re.compile(rule["pattern"])
    allow_matches = compile_list(rule, "allow_matches")
    allow_paths = compile_list(rule, "allow_paths")
    allow_fns = set(rule.get("allow_fns", []) or [])
    if any(p.search(rf.rel) for p in allow_paths):
        return vio
    for m in rx.finditer(rf.code):
        text = m.group(0)
        # a definition is not a call
        pre = rf.code[max(0, m.start() - 24) : m.start()]
        if re.search(r"\bfn\s*$", pre):
            continue
        if any(p.search(text) for p in allow_matches):
            continue
        f = rf.enclosing_fn(m.start())
        where = f.qualname if f else "<module level>"
        if f and (f.name in allow_fns or f.qualname in allow_fns):
            continue
        vio.append(
            Violation(
                rule["id"], rule.get("severity", "block"), rf.rel, rf.line_of(m.start()),
                f"`{text.strip()}` called from `{where}`, which is not allowlisted",
                rule["message"], rule.get("remediation", ""), where,
            )
        )
    return vio


def check_line(rf: RustFile, rule: dict) -> list[Violation]:
    vio: list[Violation] = []
    rx = re.compile(rule["pattern"])
    mode = rule.get("mode", "forbid")
    if mode == "forbid":
        for m in rx.finditer(rf.code):
            line = rf.line_of(m.start())
            raw_line = rf.raw.splitlines()[line - 1].strip() if line - 1 < len(rf.raw.splitlines()) else ""
            vio.append(
                Violation(
                    rule["id"], rule.get("severity", "block"), rf.rel, line,
                    f"forbidden pattern: {raw_line[:160]!r}",
                    rule["message"], rule.get("remediation", ""),
                )
            )
    elif mode == "require_per_file":
        if not rx.search(rf.code):
            vio.append(
                Violation(
                    rule["id"], rule.get("severity", "block"), rf.rel, 1,
                    f"file does not contain required pattern {rx.pattern!r}",
                    rule["message"], rule.get("remediation", ""),
                )
            )
    else:
        raise SystemExit(f"ERROR   {CHECK} :: invariant {rule['id']}: unknown mode {mode!r}")
    return vio


# --------------------------------------------------------------------------- main


def load_rules(path: str) -> tuple[list[dict], dict]:
    if tomllib is None:
        raise SystemExit(
            f"ERROR   {CHECK} :: needs Python 3.11+ for tomllib (found {sys.version.split()[0]}). "
            "Install a newer python3 on the runner."
        )
    data = tomllib.loads(Path(path).read_text())
    rules = data.get("invariant", [])
    if not rules:
        raise SystemExit(f"ERROR   {CHECK} :: no [[invariant]] blocks in {path}")
    for r in rules:
        for field in ("id", "kind", "message"):
            if field not in r:
                raise SystemExit(f"ERROR   {CHECK} :: an invariant is missing `{field}`: {r}")
        if r["kind"] not in VALID_KINDS:
            raise SystemExit(f"ERROR   {CHECK} :: invariant {r['id']}: unknown kind {r['kind']!r} (known: {sorted(VALID_KINDS)})")
        if r.get("severity", "block") not in ("block", "warn"):
            raise SystemExit(f"ERROR   {CHECK} :: invariant {r['id']}: severity must be block or warn")
    ids = [r["id"] for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SystemExit(f"ERROR   {CHECK} :: duplicate invariant id(s): {sorted(dupes)}")
    return rules, data.get("meta", {})


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="invariants.py",
        description="Check structural security invariants against the head tree (catches deletions).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--rules", required=True, help="path to invariants.toml")
    p.add_argument("--root", default=".", help="tree to scan (default: .)")
    p.add_argument("--only", action="append", default=[], help="run only this invariant id; repeatable")
    p.add_argument("--skip", action="append", default=[], help="skip this invariant id; repeatable")
    p.add_argument("--list", action="store_true", help="list the invariants and exit")
    p.add_argument("--exclude-path", action="append", default=[], help="extra path regex to exclude; repeatable")
    p.add_argument("--ignore-default-exclude", action="store_true", help="ignore [meta].exclude_paths (for self-tests)")
    p.add_argument("--fail-on", choices=["block", "warn"], default="block", help="lowest severity that fails (default block)")
    p.add_argument("--json", dest="json_out", default=None, help="write a machine-readable report here")
    p.add_argument("-v", "--verbose", action="store_true", help="print each invariant's selection counts")
    args = p.parse_args(argv)

    rules, meta = load_rules(args.rules)
    if args.list:
        for r in rules:
            print(f"{r['id']:<40} {r['kind']:<11} {r.get('severity', 'block'):<6} {r['message']}")
        return 0
    if args.only:
        rules = [r for r in rules if r["id"] in args.only]
        if not rules:
            raise SystemExit(f"ERROR   {CHECK} :: --only matched no invariant")
    if args.skip:
        rules = [r for r in rules if r["id"] not in args.skip]

    meta_excl_pats = [] if args.ignore_default_exclude else list(meta.get("exclude_paths", []))
    meta_excl_pats += args.exclude_path
    meta_excl = [re.compile(x) for x in meta_excl_pats]

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"ERROR   {CHECK} :: --root {args.root} does not exist")
    files: list[RustFile] = []
    for p_ in sorted(root.rglob("*.rs")):
        rel = str(p_.relative_to(root))
        if any(rx.search(rel) for rx in meta_excl):
            continue
        try:
            files.append(RustFile(p_, rel))
        except OSError as e:
            print(f"INFO    {CHECK} :: cannot read {rel}: {e}")
    print(f"INFO    {CHECK} :: {len(files)} Rust file(s) under {root}, {len(rules)} invariant(s)")
    if not files:
        print(f"-- {CHECK}: no Rust files matched; nothing checked")
        return 0

    violations: list[Violation] = []
    for rule in rules:
        selected = [f for f in files if path_selected(f.rel, rule, meta_excl)]
        before = len(violations)
        if rule["kind"] == "tree_count":
            rx = re.compile(rule["pattern"])
            count = sum(len(rx.findall(f.code)) for f in selected)
            lo, hi = rule.get("min", 0), rule.get("max")
            if not selected and not rule.get("require_files"):
                # Nothing matched include_paths: the module this invariant is about does not exist
                # in this tree, so there is nothing to have been deleted. Set require_files = true
                # on the invariant when the module's absence is itself the violation.
                print(f"INFO    {CHECK}.{rule['id']} :: no file matched include_paths; not applicable to this tree")
            elif count < lo or (hi is not None and count > hi):
                violations.append(
                    Violation(
                        rule["id"], rule.get("severity", "block"),
                        f"<tree:{args.root}>", 0,
                        f"pattern {rule['pattern']!r} occurs {count} time(s) across "
                        f"{len(selected)} selected file(s); required at least {lo}"
                        + (f" and at most {hi}" if hi is not None else "")
                        + ". A mechanism this invariant depends on may have been deleted or renamed.",
                        rule["message"], rule.get("remediation", ""),
                    )
                )
        else:
            fn = {"fn_body": check_fn_body, "call_site": check_call_site, "line": check_line}[rule["kind"]]
            for f in selected:
                violations.extend(fn(f, rule))
        if args.verbose:
            print(
                f"INFO    {CHECK}.{rule['id']} :: {len(selected)} file(s) selected, "
                f"{len(violations) - before} violation(s)"
            )

    for v in violations:
        level = "FINDING" if v.severity == "block" else "WARN   "
        print(f"{level} {CHECK}.{v.rid} {v.path}:{v.line} :: breaks invariant “{v.message}” — {v.detail}")
    blocks = [v for v in violations if v.severity == "block"]
    warns = [v for v in violations if v.severity == "warn"]
    print(f"-- {CHECK}: {len(blocks)} blocking, {len(warns)} warning violation(s) over {len(files)} file(s)")
    if violations:
        seen: set[str] = set()
        for v in violations:
            if v.rid in seen or not v.remediation.strip():
                continue
            seen.add(v.rid)
            print(f"HINT    {CHECK}.{v.rid} :: {' '.join(v.remediation.split())}")

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "check": CHECK,
                    "root": str(root),
                    "files_scanned": len(files),
                    "invariants": [r["id"] for r in rules],
                    "violations": [v.as_dict() for v in violations],
                },
                indent=2,
            )
        )
    if blocks or (args.fail_on == "warn" and warns):
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
