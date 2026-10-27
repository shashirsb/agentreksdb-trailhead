#!/usr/bin/env python3
# ruff: noqa
"""twin_divergence.py — the oracle for twin generation: do two independent implementations agree?

WHY THIS EXISTS
---------------
Every other gate in this directory asks "does this patch look bad?". That question
has a ceiling: a backdoor that looks exactly like the honest implementation of the
spec defeats it. Twin generation asks a different question. The same spec goes to
two model families with no shared context; each writes the patch; this script
compares the two. A deliberate backdoor has to be planted by BOTH models, in the
same place, with the same trigger, to survive — which needs either collusion
through the spec itself (so read the spec) or a shared poisoning of both training
sets. Honest disagreement is noise and is expected; the comparison's whole job is
to tell the two apart, because a gate that reports every whitespace difference is
a gate nobody reads.

This script does NOT call a model. It is the oracle, not the generator: point it
at two patches (or two built trees) that already exist.

COSMETIC — normalised away, never reported as divergence
--------------------------------------------------------
* formatting: whitespace, line breaks, trailing commas, brace style
* comments and doc comments, in full (their consistency with the code is
  comment_consistency.py's job, not this one)
* names of LOCALS: `let` bindings, `for` bindings, closure parameters and function
  parameters are renumbered `_v1.._vn` in binding order, per function
* names of PRIVATE functions: a private function is matched to its twin by
  structure first and by name second, so `fn key` ≡ `fn normalised_key` when the
  two have the same signature shape and the same fingerprint
* the ORDER of independent items: top-level functions, `use` lines, struct and
  enum members are compared as keyed sets, not as sequences
* integer formatting: `1_000`, `0x3e8` and `1000` are one constant
* a tail `return expr;` versus a tail expression

BEHAVIOURAL — any difference here is a finding
----------------------------------------------
  control        the ordered sequence of control-flow tokens with their nesting depth
                 (if / else / match / for / while / loop / return / break / continue /
                 await / unsafe / `?`)
  match_arms     the set of match-arm patterns
  comparisons    the multiset of comparison operators with their operands
                 (`_v4 > self.limit` vs `_v4 >= self.limit` is a finding)
  constants      the multiset of literals: ints, floats, strings, chars, bools
  errors         the multiset of error-path constructs (`Err(`, `?`, `panic!`,
                 `unwrap(`, `expect(`, `bail!`, `ok_or`, `None`)
  io             the multiset of IO / syscall-shaped calls, classified the way
                 syscall_diff.py classifies capabilities (fs:*, net:*, proc:*,
                 env:*, time:*, rand:*, thread:*, unsafe:*)
  signature      the normalised signature of every PUBLIC function: name, arity,
                 parameter types, return type
  items          public items present on one side and not the other, and private
                 items that cannot be paired structurally
  fields         the fields of a public struct / the variants of a public enum

HONEST LIMITS
-------------
* This is a scanner, not a Rust front end (same constraint as invariants.py: no
  `syn`, no rustc, because a new dependency is itself a supply-chain change). It
  compares shapes, not semantics. Two functions with identical fingerprints can
  still behave differently, and two that behave identically can diverge in shape.
* The honest-disagreement rate is the thing to measure before trusting an exit
  code here. Two model families solving a real spec will differ on data
  structures, helper decomposition and error vocabulary, and every one of those
  is reported. Run it over known-good twin pairs first and read the rate.
  `--mode module` compares the whole file's multisets instead of per function,
  which survives a different helper decomposition; it is the setting for specs
  where the two models are expected to factor the code differently.
* From a patch, only the NEW side is reconstructed (added plus context lines). A
  partial patch gives a partial file and is reported as `partial` — compare trees
  when you can.

HOW IT CAN BE EVADED
--------------------
* Plant the same backdoor in both twins. That is the attack this gate is built
  against, and it needs the spec itself to carry the trigger (so the spec is
  CODEOWNERS-protected and reviewed) or both model families to be poisoned alike.
* Hide in a dimension this fingerprint does not read: the ORDER of two
  independent statements, an off-by-one in a loop bound expression that is not a
  comparison, a different hash function, allocation sizes.
* Diverge everywhere. If the honest divergence report is already 80 lines, one
  more line is camouflage — which is why the report is grouped by dimension and
  why `--max-report` keeps it readable rather than truncating silently.
* Two empty-fingerprint private helpers pair with each other structurally even
  when they do unrelated things; keep an eye on `paired structurally` lines.

EXIT CODES
----------
  0  the twins agree behaviourally (cosmetic differences only)
  1  at least one behavioural divergence
  2  usage or internal error

EXAMPLES
--------
  ./twin_divergence.py --base-patch claude.patch --twin-patch other-model.patch
  ./twin_divergence.py --base-tree ./build-a --twin-tree ./build-b --mode module
  ./twin_divergence.py --base-patch a.patch --twin-patch b.patch --format json --json twins.json
"""

from __future__ import annotations

import argparse
import contextlib
import io as _io
import json
import re
import sys
from collections import Counter
from pathlib import Path

CHECK = "twin_divergence"

DIMENSIONS = ("signature", "control", "match_arms", "comparisons", "constants", "errors", "io", "fields")

# --------------------------------------------------------------------------- scrubbing


def _blank_span(out: list[str], a: int, b: int, n: int) -> None:
    for k in range(a, min(b, n)):
        if out[k] != "\n":
            out[k] = " "


def scrub(src: str, literals: bool) -> str:
    """Blank comments (always) and literal CONTENTS (when `literals`), length-preserving.

    Two views of the same file come out of this: one where a `if` inside a string can
    never be mistaken for control flow, and one that still carries the literals so they
    can be harvested as constants. Offsets are identical in both.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            _blank_span(out, i, j, n)
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
            _blank_span(out, i, j, n)
            i = j
            continue
        m = re.match(r'(?:b?r)(#*)"', src[i : i + 16])
        if m and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            close = '"' + m.group(1)
            j = src.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            if literals:
                _blank_span(out, i + m.end(), j - len(close), n)
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
            if literals:
                _blank_span(out, i + 1, j - 1, n)
            i = j
            continue
        i += 1
    return "".join(out)


def match_brace(text: str, open_at: int) -> int:
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


# --------------------------------------------------------------------------- fingerprints

CONTROL_RE = re.compile(
    r"\b(if|else|match|for|while|loop|return|break|continue|unsafe)\b"
    r"|\.await\b"
    r"|\?(?=\s*[;,)\].]|\s*$)",
    re.M,
)
ARM_RE = re.compile(r"^\s*([^\n{};=]{1,80}?)\s*=>", re.M)
CMP_RE = re.compile(
    r"(?P<l>[A-Za-z0-9_\.\(\)\[\]\*&:\"']{1,32}?)\s*(?P<op>==|!=|<=|>=)\s*(?P<r>[A-Za-z0-9_\.\(\)\[\]\*&:\"']{1,32})"
    r"|(?P<l2>[A-Za-z0-9_\.\(\)\[\]\*&:]{1,32}?)\s+(?P<op2><|>)\s+(?P<r2>[A-Za-z0-9_\.\(\)\[\]\*&:]{1,32})"
)
LITERAL_RES: list[tuple[str, re.Pattern]] = [
    ("str", re.compile(r'\bbr?(#+)"(?P<v>.*?)"\1', re.S)),
    ("str", re.compile(r'\bbr?"(?P<v>[^"\\]*)"')),
    ("str", re.compile(r'"(?P<v>(?:[^"\\\n]|\\.)*)"')),
    ("char", re.compile(r"b?'(?P<v>\\.|[^'\\\n])'")),
    ("hex", re.compile(r"\b0x(?P<v>[0-9a-fA-F][0-9a-fA-F_]*)(?:[ui](?:8|16|32|64|128|size))?\b")),
    ("oct", re.compile(r"\b0o(?P<v>[0-7][0-7_]*)(?:[ui](?:8|16|32|64|128|size))?\b")),
    ("bin", re.compile(r"\b0b(?P<v>[01][01_]*)(?:[ui](?:8|16|32|64|128|size))?\b")),
    ("float", re.compile(r"(?<![\w.])(?P<v>\d[\d_]*\.\d[\d_]*(?:[eE][+-]?\d+)?)(?:f32|f64)?(?![\w.])")),
    ("int", re.compile(r"(?<![\w.])(?P<v>\d[\d_]*)(?:[ui](?:8|16|32|64|128|size))?(?![\w.])")),
    ("bool", re.compile(r"\b(?P<v>true|false)\b")),
]
ERROR_TOKENS: list[tuple[str, re.Pattern]] = [
    ("Err(", re.compile(r"\bErr\s*\(")),
    ("Ok(", re.compile(r"\bOk\s*\(")),
    ("None", re.compile(r"\bNone\b")),
    ("?", re.compile(r"\?(?=\s*[;,)\].]|\s*$)", re.M)),
    ("panic!", re.compile(r"\bpanic!")),
    ("unreachable!", re.compile(r"\bunreachable!")),
    ("todo!", re.compile(r"\b(?:todo|unimplemented)!")),
    ("unwrap(", re.compile(r"\.unwrap\s*\(")),
    ("expect(", re.compile(r"\.expect\s*\(")),
    ("unwrap_or", re.compile(r"\.unwrap_or(?:_else|_default)?\s*\(")),
    ("ok_or", re.compile(r"\.ok_or(?:_else)?\s*\(")),
    ("bail!", re.compile(r"\b(?:bail|ensure|anyhow)!")),
    ("assert!", re.compile(r"\b(?:assert|assert_eq|assert_ne|debug_assert)\w*!")),
]
IO_TOKENS: list[tuple[str, re.Pattern]] = [
    ("fs:open", re.compile(r"\b(?:File::open|File::create|OpenOptions|fs::read|fs::write|fs::read_to_string|fs::copy|fs::create_dir|fs::read_dir)\b")),
    ("fs:delete", re.compile(r"\bfs::(?:remove_file|remove_dir|remove_dir_all|rename)\b")),
    ("fs:sync", re.compile(r"\.(?:sync_all|sync_data|flush)\s*\(")),
    ("fs:mmap", re.compile(r"\b(?:Mmap|MmapMut|mmap)\b")),
    ("net:socket", re.compile(r"\b(?:TcpStream|TcpListener|UdpSocket|UnixStream|UnixListener)\b")),
    ("net:client", re.compile(r"\b(?:reqwest|hyper::Client|ureq|isahc)\b")),
    ("net:tokio", re.compile(r"\btokio::net\b")),
    ("proc:exec", re.compile(r"\b(?:Command::new|process::Command|process::exit)\b")),
    ("env:read", re.compile(r"\benv::(?:var|vars|var_os|args)\b")),
    ("time:now", re.compile(r"\b(?:SystemTime::now|Instant::now|Utc::now|Local::now)\b")),
    ("rand", re.compile(r"\b(?:thread_rng|rand::|random\s*\(|OsRng)\b")),
    ("thread", re.compile(r"\b(?:thread::spawn|tokio::spawn|thread::sleep|sleep\s*\()")),
    ("unsafe:ffi", re.compile(r"\b(?:libc::|transmute|from_utf8_unchecked|get_unchecked|from_raw)\b")),
    ("sql", re.compile(r"\b(?:query|query_as|execute|prepare)\s*\(")),
]

BIND_RES = [
    re.compile(r"\blet\s+(?:mut\s+)?(?P<n>[A-Za-z_]\w*)\s*[:=]"),
    re.compile(r"\blet\s+(?:Some|Ok|Err)\s*\(\s*(?:mut\s+)?(?P<n>[A-Za-z_]\w*)\s*\)"),
    re.compile(r"\bfor\s+(?:mut\s+)?(?P<n>[A-Za-z_]\w*)\s+in\b"),
    re.compile(r"\blet\s+(?:mut\s+)?\((?P<n>[^)]*)\)"),
    re.compile(r"\|\s*(?P<n>[A-Za-z_]\w*)\s*[|,]"),
]
RESERVED = {
    "self", "Self", "mut", "ref", "if", "else", "match", "for", "while", "loop", "return",
    "let", "fn", "pub", "impl", "struct", "enum", "const", "static", "use", "crate", "super",
    "true", "false", "None", "Some", "Ok", "Err", "as", "in", "move", "where", "async", "await",
}


def depth_at(code: str) -> list[int]:
    """Brace depth at every offset, so a control token can be reported with its nesting."""
    depths = [0] * (len(code) + 1)
    d = 0
    for i, ch in enumerate(code):
        if ch == "{":
            d += 1
        depths[i] = d
        if ch == "}":
            d -= 1
            depths[i] = d + 1
    depths[len(code)] = d
    return depths


def normalise_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def normalise_int(kind: str, raw: str) -> str:
    t = raw.replace("_", "")
    try:
        if kind == "hex":
            return str(int(t, 16))
        if kind == "oct":
            return str(int(t, 8))
        if kind == "bin":
            return str(int(t, 2))
        if kind == "int":
            return str(int(t, 10))
        if kind == "float":
            return repr(float(t))
    except ValueError:
        return t
    return t


def collect_bindings(signature: str, body: str) -> list[str]:
    """Local names in binding order: parameters first, then `let`/`for`/closure bindings."""
    names: list[str] = []
    for n in signature_param_names(signature):
        if n not in names:
            names.append(n)
    hits: list[tuple[int, str]] = []
    for rx in BIND_RES:
        for m in rx.finditer(body):
            hits.append((m.start(), m.group(0)))
    for _, chunk in sorted(hits):
        for ident in re.findall(r"[A-Za-z_]\w*", chunk.split("=", 1)[0]):
            if ident in RESERVED or ident in names:
                continue
            if re.match(r"^(?:let|for|in|mut|ref)$", ident):
                continue
            names.append(ident)
    return names


def rename_locals(text: str, names: list[str]) -> str:
    """`_v1.._vn` in binding order. Field and path accesses (`self.used`, `Mod::used`)
    are left alone, so renaming a local never changes the meaning of a field name."""
    out = text
    for i, n in enumerate(names, start=1):
        out = re.sub(rf"(?<![\w.:]){re.escape(n)}\b(?!\s*:(?!:))", f"_v{i}", out)
    return out


def signature_param_names(signature: str) -> list[str]:
    p = signature.find("(")
    if p < 0:
        return []
    end = match_paren(signature, p)
    inner = signature[p + 1 : end - 1]
    names: list[str] = []
    depth = 0
    cur = ""
    pieces: list[str] = []
    for ch in inner:
        if ch in "([<{":
            depth += 1
        elif ch in ")]>}":
            depth -= 1
        if ch == "," and depth == 0:
            pieces.append(cur)
            cur = ""
        else:
            cur += ch
    pieces.append(cur)
    for piece in pieces:
        piece = piece.strip()
        if not piece or piece.lstrip("&").lstrip() in ("self", "mut self"):
            continue
        lhs = piece.split(":", 1)[0]
        for ident in re.findall(r"[A-Za-z_]\w*", lhs):
            if ident in ("mut", "ref", "self"):
                continue
            names.append(ident)
    return names


def normalised_signature(name: str, signature: str, keep_name: bool) -> str:
    """`fn name(T, T) -> R`: parameter NAMES dropped (they are locals), types kept."""
    p = signature.find("(")
    if p < 0:
        return f"fn {name if keep_name else '_'}()"
    end = match_paren(signature, p)
    inner = signature[p + 1 : end - 1]
    ret = signature[end:]
    ret = ret[: ret.find("{")] if "{" in ret else ret
    ret = normalise_ws(ret.strip().rstrip("{").strip())
    types: list[str] = []
    depth = 0
    cur = ""
    pieces: list[str] = []
    for ch in inner:
        if ch in "([<{":
            depth += 1
        elif ch in ")]>}":
            depth -= 1
        if ch == "," and depth == 0:
            pieces.append(cur)
            cur = ""
        else:
            cur += ch
    pieces.append(cur)
    for piece in pieces:
        piece = normalise_ws(piece)
        if not piece:
            continue
        if piece.lstrip("&").lstrip().startswith("self") or piece in ("self", "&self", "&mut self"):
            types.append("self")
            continue
        types.append(normalise_ws(piece.split(":", 1)[1]) if ":" in piece else piece)
    return f"fn {name if keep_name else '_'}({', '.join(types)}) {ret}".strip()


def strip_tail_return(body: str) -> str:
    """`{ … return x; }` and `{ … x }` are the same program; make them the same text."""
    return re.sub(r"\breturn\s+([^;{}]*);\s*\}\s*$", r"\1 }", body.strip())


def fingerprint(signature: str, code_body: str, lit_body: str) -> dict:
    """The behavioural fingerprint of one function body. Pure; this is the unit under test."""
    code_body = strip_tail_return(code_body)
    names = collect_bindings(signature, code_body)
    norm = rename_locals(code_body, names)

    depths = depth_at(norm)
    control = [
        f"{normalise_ws(m.group(0))}@{depths[m.start()]}"
        for m in CONTROL_RE.finditer(norm)
    ]
    arms = sorted(normalise_ws(m.group(1)) for m in ARM_RE.finditer(norm))

    comparisons: list[str] = []
    for m in CMP_RE.finditer(norm):
        if m.group("op"):
            l, op, r = m.group("l"), m.group("op"), m.group("r")
        else:
            l, op, r = m.group("l2"), m.group("op2"), m.group("r2")
        comparisons.append(f"{normalise_ws(l)} {op} {normalise_ws(r)}")

    constants: list[str] = []
    consumed: list[tuple[int, int]] = []
    for kind, rx in LITERAL_RES:
        for m in rx.finditer(lit_body):
            st, en = m.span()
            if any(not (en <= cs or st >= ce) for cs, ce in consumed):
                continue
            consumed.append((st, en))
            v = m.group("v")
            if kind in ("int", "hex", "oct", "bin"):
                # One constant, however it is spelled: 1000 == 1_000 == 0x3e8 == 0o1750.
                constants.append(f"int:{normalise_int(kind, v)}")
            elif kind == "float":
                constants.append(f"float:{normalise_int(kind, v)}")
            else:
                constants.append(f"{kind}:{v}")

    errors = [name for name, rx in ERROR_TOKENS for _ in rx.finditer(norm)]
    ios = [name for name, rx in IO_TOKENS for _ in rx.finditer(norm)]

    return {
        "control": control,
        "match_arms": arms,
        "comparisons": sorted(comparisons),
        "constants": sorted(constants),
        "errors": sorted(errors),
        "io": sorted(ios),
        "locals": len(names),
    }


# --------------------------------------------------------------------------- parsing a module


class Function:
    __slots__ = ("path", "name", "qual", "is_pub", "signature", "norm_sig", "fp", "line")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class Module:
    def __init__(self, rel: str, src: str, partial: bool = False):
        self.rel = rel
        self.partial = partial
        self.code = scrub(src, literals=True)
        self.lit = scrub(src, literals=False)
        self.functions: list[Function] = []
        self.types: dict[str, list[str]] = {}
        self.consts: dict[str, str] = {}
        self.uses: set[str] = set()
        self._parse()

    def _impls(self) -> list[tuple[int, int, str]]:
        out = []
        for m in re.finditer(r"\bimpl\b([^{;]*)\{", self.code):
            head = m.group(1)
            name = head.split(" for ", 1)[1] if " for " in head else head
            name = re.sub(r"<[^>]*>", "", name).strip().strip("&")
            name = name.split()[-1] if name.split() else "impl"
            out.append((m.start(), match_brace(self.code, m.end() - 1), name))
        return out

    def _parse(self) -> None:
        impls = self._impls()
        for m in re.finditer(r"\buse\s+([^;]+);", self.code):
            self.uses.add(normalise_ws(m.group(1)))
        for m in re.finditer(r"\b(?:pub\s+(?:\([^)]*\)\s*)?)?(?:struct|enum)\s+([A-Za-z_]\w*)[^{;]*\{", self.code):
            end = match_brace(self.code, self.code.find("{", m.end() - 1))
            inner = self.code[self.code.find("{", m.end() - 1) + 1 : end - 1]
            members = []
            depth = 0
            cur = ""
            for ch in inner:
                if ch in "([<{":
                    depth += 1
                elif ch in ")]>}":
                    depth -= 1
                if ch == "," and depth == 0:
                    members.append(cur)
                    cur = ""
                else:
                    cur += ch
            members.append(cur)
            self.types[m.group(1)] = sorted(
                normalise_ws(x) for x in members if normalise_ws(x)
            )
        for m in re.finditer(r"\b(?:pub\s+(?:\([^)]*\)\s*)?)?(?:const|static)\s+(?:mut\s+)?([A-Z_][A-Z0-9_]*)\s*:[^=]*=\s*([^;]+);", self.lit):
            self.consts[m.group(1)] = normalise_ws(m.group(2))

        for m in re.finditer(r"\bfn\s+([A-Za-z_]\w*)", self.code):
            name = m.group(1)
            p = self.code.find("(", m.end())
            if p < 0:
                continue
            sig_end = match_paren(self.code, p)
            j = sig_end
            while j < len(self.code) and self.code[j] not in "{;":
                j += 1
            if j >= len(self.code) or self.code[j] == ";":
                continue
            body_start, body_end = j, match_brace(self.code, j)
            signature = normalise_ws(self.code[m.start() : body_start])
            line_start = self.code.rfind("\n", 0, m.start()) + 1
            is_pub = bool(re.search(r"\bpub\b", self.code[line_start : m.start()]))
            qual = name
            best = None
            for s, e, iname in impls:
                if s <= m.start() < e and (best is None or s > best[0]):
                    best = (s, iname)
            if best:
                qual = f"{best[1]}::{name}"
            self.functions.append(
                Function(
                    path=self.rel,
                    name=name,
                    qual=qual,
                    is_pub=is_pub,
                    signature=signature,
                    norm_sig=normalised_signature(name, signature, keep_name=True),
                    fp=fingerprint(signature, self.code[body_start:body_end], self.lit[body_start:body_end]),
                    line=self.code.count("\n", 0, m.start()) + 1,
                )
            )

    def module_fingerprint(self) -> dict:
        agg = {k: [] for k in ("control", "match_arms", "comparisons", "constants", "errors", "io")}
        for f in self.functions:
            for k in agg:
                agg[k].extend(f.fp[k])
        for k in agg:
            agg[k] = sorted(agg[k])
        return agg


# --------------------------------------------------------------------------- loading sides


def parse_patch_new_side(diff: str) -> dict[str, tuple[str, bool]]:
    """path -> (reconstructed new-side text, partial?). Added plus context lines."""
    files: dict[str, list[tuple[int, str]]] = {}
    starts: dict[str, int] = {}
    path = None
    newno = 0
    in_hunk = False
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            p = raw[4:].strip().split("\t")[0]
            if p.startswith("b/"):
                p = p[2:]
            path = None if p == "/dev/null" else p
            if path is not None:
                files.setdefault(path, [])
            in_hunk = False
            continue
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if m:
            newno = int(m.group(1))
            in_hunk = True
            if path is not None:
                starts.setdefault(path, newno)
            continue
        if not in_hunk or path is None:
            continue
        if raw.startswith("\\"):
            continue
        if raw.startswith("+"):
            files[path].append((newno, raw[1:]))
            newno += 1
        elif raw.startswith("-"):
            continue
        else:
            files[path].append((newno, raw[1:] if raw else ""))
            newno += 1
    out: dict[str, tuple[str, bool]] = {}
    for p, numbered in files.items():
        if not numbered:
            continue
        gaps = any(b[0] != a[0] + 1 for a, b in zip(numbered, numbered[1:]))
        partial = gaps or starts.get(p, 1) > 1
        out[p] = ("\n".join(t for _, t in numbered), partial)
    return out


def load_tree(root: str, glob: str) -> dict[str, tuple[str, bool]]:
    out: dict[str, tuple[str, bool]] = {}
    base = Path(root)
    if not base.exists():
        raise SystemExit(f"ERROR   {CHECK} :: tree {root} does not exist")
    for p in sorted(base.rglob(glob)):
        if ".git" in p.parts or "target" in p.parts:
            continue
        try:
            out[str(p.relative_to(base))] = (p.read_text(errors="replace"), False)
        except OSError as e:
            print(f"INFO    {CHECK} :: cannot read {p}: {e}")
    return out


def build_modules(sources: dict[str, tuple[str, bool]], ignore: str | None) -> dict[str, Module]:
    mods: dict[str, Module] = {}
    for rel, (text, partial) in sources.items():
        if ignore and re.search(ignore, rel):
            continue
        mods[rel] = Module(rel, text, partial)
    return mods


# --------------------------------------------------------------------------- comparison


class Report:
    def __init__(self) -> None:
        self.divergences: list[dict] = []
        self.cosmetic: list[dict] = []

    def diverge(self, dimension: str, where: str, base: object, twin: object, detail: str) -> None:
        self.divergences.append({
            "dimension": dimension, "symbol": where,
            "base": base, "twin": twin, "detail": detail,
        })

    def cosmetically(self, kind: str, where: str, detail: str) -> None:
        self.cosmetic.append({"kind": kind, "symbol": where, "detail": detail})


def multiset_delta(a: list, b: list) -> tuple[list, list]:
    ca, cb = Counter(a), Counter(b)
    only_a = sorted((ca - cb).elements())
    only_b = sorted((cb - ca).elements())
    return only_a, only_b


def compare_fingerprints(where: str, base: dict, twin: dict, rep: Report, dims: tuple[str, ...]) -> None:
    for dim in dims:
        if dim not in base or dim not in twin:
            continue
        if dim == "control":
            if base["control"] != twin["control"]:
                only_a, only_b = multiset_delta(base["control"], twin["control"])
                rep.diverge(
                    "control", where, base["control"], twin["control"],
                    "control-flow structure differs"
                    + (f" (base only: {only_a}; twin only: {only_b})" if (only_a or only_b)
                       else " only in ORDER — same tokens, different sequence, so the branches run in a different order"),
                )
            continue
        only_a, only_b = multiset_delta(base[dim], twin[dim])
        if only_a or only_b:
            rep.diverge(dim, where, only_a, only_b, f"{dim} differ")


def pair_private(base_fns: list[Function], twin_fns: list[Function], rep: Report) -> list[tuple[Function, Function]]:
    """Pair private functions by name, then structurally. A structural pair is a rename,
    which is cosmetic; what is left over is a real difference in what exists."""
    pairs: list[tuple[Function, Function]] = []
    tw = {f.name: f for f in twin_fns}
    unmatched_base = []
    for f in base_fns:
        g = tw.pop(f.name, None)
        if g is not None:
            pairs.append((f, g))
        else:
            unmatched_base.append(f)
    leftovers = list(tw.values())
    for f in list(unmatched_base):
        for g in list(leftovers):
            same_shape = normalised_signature(f.name, f.signature, keep_name=False) == \
                normalised_signature(g.name, g.signature, keep_name=False)
            if same_shape and all(f.fp[d] == g.fp[d] for d in ("control", "comparisons", "constants", "errors", "io")):
                pairs.append((f, g))
                rep.cosmetically("private-rename", f"{f.path}::{f.qual}",
                                 f"paired structurally with twin's `{g.qual}`: private name differs, "
                                 "signature shape and fingerprint are identical")
                unmatched_base.remove(f)
                leftovers.remove(g)
                break
    for f in unmatched_base:
        rep.diverge("items", f"{f.path}::{f.qual}", "present", "absent",
                    "a private function exists in base with no counterpart in twin, by name or by structure")
    for g in leftovers:
        rep.diverge("items", f"{g.path}::{g.qual}", "absent", "present",
                    "a private function exists in twin with no counterpart in base, by name or by structure")
    return pairs


def compare_modules(base: Module, twin: Module, rep: Report, args) -> None:
    where_file = base.rel
    if base.partial or twin.partial:
        rep.cosmetically("partial", where_file,
                         "reconstructed from a partial patch: only the hunks' new side was available, "
                         "so absence of a divergence is weaker evidence here")

    if args.mode == "module":
        compare_fingerprints(f"{where_file} <module>", base.module_fingerprint(), twin.module_fingerprint(),
                             rep, tuple(d for d in DIMENSIONS if d not in ("signature", "fields")))
    else:
        bpub = {f.qual: f for f in base.functions if f.is_pub}
        tpub = {f.qual: f for f in twin.functions if f.is_pub}
        for qual in sorted(set(bpub) | set(tpub)):
            b, t = bpub.get(qual), tpub.get(qual)
            if b is None:
                rep.diverge("items", f"{where_file}::{qual}", "absent", "present",
                            "public function present only in twin: the two sides expose a different API")
                continue
            if t is None:
                rep.diverge("items", f"{where_file}::{qual}", "present", "absent",
                            "public function present only in base: the two sides expose a different API")
                continue
            if b.norm_sig != t.norm_sig:
                rep.diverge("signature", f"{where_file}::{qual}", b.norm_sig, t.norm_sig,
                            "public signature differs (arity, parameter types or return type)")
            compare_fingerprints(f"{where_file}::{qual}", b.fp, t.fp, rep,
                                 tuple(d for d in DIMENSIONS if d not in ("signature", "fields")))
        for b, t in pair_private([f for f in base.functions if not f.is_pub],
                                 [f for f in twin.functions if not f.is_pub], rep):
            if normalised_signature(b.name, b.signature, keep_name=False) != \
                    normalised_signature(t.name, t.signature, keep_name=False):
                rep.diverge("signature", f"{where_file}::{b.qual}",
                            normalised_signature(b.name, b.signature, keep_name=False),
                            normalised_signature(t.name, t.signature, keep_name=False),
                            "private signature shape differs")
            compare_fingerprints(f"{where_file}::{b.qual}", b.fp, t.fp, rep,
                                 tuple(d for d in DIMENSIONS if d not in ("signature", "fields")))

    for name in sorted(set(base.types) | set(twin.types)):
        bt, tt = base.types.get(name), twin.types.get(name)
        if bt is None or tt is None:
            rep.diverge("items", f"{where_file}::{name}", "present" if bt else "absent",
                        "present" if tt else "absent", "a struct/enum exists on one side only")
        elif bt != tt:
            only_a, only_b = multiset_delta(bt, tt)
            rep.diverge("fields", f"{where_file}::{name}", only_a, only_b,
                        "the members of this struct/enum differ")
    for name in sorted(set(base.consts) | set(twin.consts)):
        bc, tc = base.consts.get(name), twin.consts.get(name)
        if bc != tc:
            rep.diverge("constants", f"{where_file}::{name}", bc, tc,
                        "a named constant differs between the twins")
    if base.uses != twin.uses and args.compare_imports:
        only_a, only_b = multiset_delta(sorted(base.uses), sorted(twin.uses))
        rep.diverge("items", f"{where_file} <use>", only_a, only_b,
                    "the imports differ (--no-compare-imports to treat this as cosmetic)")
    elif base.uses != twin.uses:
        rep.cosmetically("imports", where_file, "import lists differ; not compared")


def compare_sides(base: dict[str, Module], twin: dict[str, Module], rep: Report, args) -> None:
    for rel in sorted(set(base) | set(twin)):
        b, t = base.get(rel), twin.get(rel)
        if b is None or t is None:
            if args.ignore_missing_files:
                rep.cosmetically("file-missing", rel, "present on one side only; ignored by request")
                continue
            rep.diverge("items", rel, "present" if b else "absent", "present" if t else "absent",
                        "a file exists on one side only: the two implementations do not cover the same files")
            continue
        compare_modules(b, t, rep, args)


# --------------------------------------------------------------------------- main


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="twin_divergence.py",
        description="Compare two independent implementations of one spec and report BEHAVIOURAL differences.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit 1 means the twins disagree about what the program does; read the dimensions.",
    )
    p.add_argument("--base-patch", help="unified diff from the first model (or - for stdin)")
    p.add_argument("--twin-patch", help="unified diff from the second model")
    p.add_argument("--base-tree", help="built/checked-out tree from the first model")
    p.add_argument("--twin-tree", help="built/checked-out tree from the second model")
    p.add_argument("--glob", default="*.rs", help="files to read from a tree (default *.rs)")
    p.add_argument("--mode", choices=["function", "module"], default="function",
                   help="compare per function (default) or per file; module mode survives a "
                        "different helper decomposition")
    p.add_argument("--ignore-paths", default=r"(^|/)(tests?|benches|fuzz|testdata|fixtures)(/|$)",
                   help="regex of paths not compared (default: test and fixture paths)")
    p.add_argument("--ignore-missing-files", action="store_true",
                   help="do not report a file that exists on one side only")
    p.add_argument("--compare-imports", action="store_true",
                   help="treat a difference in `use` lines as behavioural (off by default: it is "
                        "usually a style difference)")
    p.add_argument("--only-dimension", action="append", default=[], choices=list(DIMENSIONS),
                   help="report only this dimension; repeatable")
    p.add_argument("--max-report", type=int, default=200, help="divergences printed before the rest are summarised")
    p.add_argument("--format", choices=["text", "json"], default="text", help="stdout format (default text)")
    p.add_argument("--json", dest="json_out", default=None, help="also write the machine-readable report here")
    p.add_argument("--self-test", action="store_true", help="run the built-in testdata cases and exit")
    args = p.parse_args(argv)

    if args.self_test:
        return self_test()

    have_patches = bool(args.base_patch and args.twin_patch)
    have_trees = bool(args.base_tree and args.twin_tree)
    if have_patches == have_trees:
        p.error("give either --base-patch and --twin-patch, or --base-tree and --twin-tree")

    if have_patches:
        base_src = parse_patch_new_side(
            sys.stdin.read() if args.base_patch == "-" else Path(args.base_patch).read_text(errors="replace")
        )
        twin_src = parse_patch_new_side(Path(args.twin_patch).read_text(errors="replace"))
        sides = ("base-patch " + args.base_patch, "twin-patch " + args.twin_patch)
    else:
        base_src = load_tree(args.base_tree, args.glob)
        twin_src = load_tree(args.twin_tree, args.glob)
        sides = ("base-tree " + args.base_tree, "twin-tree " + args.twin_tree)

    base_mods = build_modules(base_src, args.ignore_paths)
    twin_mods = build_modules(twin_src, args.ignore_paths)

    rep = Report()
    compare_sides(base_mods, twin_mods, rep, args)
    divergences = rep.divergences
    if args.only_dimension:
        divergences = [d for d in divergences if d["dimension"] in args.only_dimension]

    by_dim = Counter(d["dimension"] for d in divergences)
    payload = {
        "check": CHECK,
        "base": sides[0],
        "twin": sides[1],
        "mode": args.mode,
        "files_compared": len(set(base_mods) & set(twin_mods)),
        "functions_compared": sum(len(m.functions) for m in base_mods.values()),
        "by_dimension": dict(by_dim),
        "divergences": divergences,
        "cosmetic": rep.cosmetic,
        "verdict": "diverged" if divergences else "agree",
    }

    if args.format == "json":
        print(json.dumps(payload, indent=2, default=str))
    else:
        for c in rep.cosmetic:
            print(f"INFO    {CHECK}.cosmetic.{c['kind']} {c['symbol']} :: {c['detail']}")
        for d in divergences[: args.max_report]:
            print(f"FINDING {CHECK}.{d['dimension']} {d['symbol']} :: {d['detail']}")
            print(f"        base: {d['base']}")
            print(f"        twin: {d['twin']}")
        if len(divergences) > args.max_report:
            print(f"INFO    {CHECK} :: {len(divergences) - args.max_report} further divergence(s) not printed "
                  f"(--max-report)")
        print(f"INFO    {CHECK} :: {payload['files_compared']} file(s), "
              f"{payload['functions_compared']} base function(s), mode={args.mode}")
        if divergences:
            print("HINT    " + CHECK + " :: a divergence is not proof of sabotage — it is a question for the "
                  "spec: the two models read the same words and built different programs, so either the spec "
                  "is ambiguous or one of them is wrong. Fix the spec, or pick the twin that matches it.")
        print(f"-- {CHECK}: {len(divergences)} behavioural divergence(s) "
              f"({', '.join(f'{k}={v}' for k, v in sorted(by_dim.items())) or 'none'}), "
              f"{len(rep.cosmetic)} cosmetic note(s)")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2, default=str))
    return 1 if divergences else 0


# --------------------------------------------------------------------------- self-test

TESTDATA = Path(__file__).resolve().parent / "testdata"


def self_test() -> int:
    cases = [
        (["--base-patch", str(TESTDATA / "twin_base.patch"),
          "--twin-patch", str(TESTDATA / "twin_divergent.patch")], 1, "divergent twin"),
        (["--base-patch", str(TESTDATA / "twin_base.patch"),
          "--twin-patch", str(TESTDATA / "twin_cosmetic.patch")], 0, "cosmetic twin"),
    ]
    bad = 0
    for argv, want, label in cases:
        missing = [a for a in argv if a.endswith(".patch") and not Path(a).is_file()]
        if missing:
            print(f"ERROR   {CHECK}.self-test :: missing testdata {missing}")
            bad += 1
            continue
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(argv + ["--format", "json"])
        ok = rc == want
        print(f"{'PASS' if ok else 'FAIL'}    {CHECK}.self-test {label} :: exit {rc}, want {want}")
        if not ok:
            print(buf.getvalue())
        bad += 0 if ok else 1
    print(f"-- {CHECK}.self-test: {len(cases) - bad}/{len(cases)} case(s) as expected")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
