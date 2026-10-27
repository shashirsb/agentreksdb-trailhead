#!/usr/bin/env python3
# ruff: noqa
"""comment_consistency.py — flag code whose comments, names or docs misrepresent what it does.

SABOTAGE CLASS
--------------
The hypocrite commit. The code and the story told about the code disagree, and
review reads the story. This is the shape of the UMN "hypocrite commits" work on
the Linux kernel and of most real malicious pull requests: the diff is small, the
doc comment is reassuring, the function is called `verify_signature`, and the
body returns `true`. A human reviewer skims the comment and the name and agrees;
a model reviewer summarises the comment and agrees louder.

Nothing here calls a model. These are static heuristics over a diff, which is
the point: a model asked "does this comment match this code?" can be talked out
of its answer by the comment. A regex cannot be flattered.

WHAT IT LOOKS FOR
-----------------
  claim.no-branch              the doc comment's first sentence says the function
                               validates / checks / verifies / authorizes / rejects,
                               and the body contains no conditional, no `?`, no
                               early return, no assertion — it cannot reject anything
  name.no-input-branch         the function NAME contains verify/check/validate/
                               authorize/authenticate/is_/has_/can_/allow/permit,
                               it takes parameters, and the body never branches on
                               any of them (the always-true ACL)
  claim.impossible-error       the doc promises an error / failure / `None` return on
                               some path, and either the body builds no error at all
                               or the signature has no way to return one
  claim.doc-contradicts-body   the doc names a mechanism (fsync, quorum, timeout,
                               signature, …) the body neither calls nor mentions
  marker.temporary             "temporary", "for now", "will be removed", "debug only",
                               "revert before merge" — on production source. A marker
                               that says the code is not meant to survive, in a commit
                               that makes it survive
  negation.enabled             the comment says must not / never / do not X, and code
                               next to it switches X on (`skip_x = true`, `allow_x(…)`)
  negation.disabled            the comment says must / always X, and code next to it
                               switches X off
  doc.deleted-with-code-change a hunk deletes doc-comment lines while changing the code
                               under them, and does not put the docs back. The next
                               reviewer has no statement of intent left to compare against

Only functions the diff actually touches are judged, so an unrelated old
function with a sloppy comment is not this check's business.

FALSE POSITIVES, HONESTLY
-------------------------
Comment prose is not a formal language and this check is guessing at intent.
The mitigations, in order:
 1. The validate-claim rule reads only the FIRST SENTENCE of the doc, and only
    fires on a verb in claim position. "Called by the validator" is not a claim.
 2. tests/, benches/, fuzz/, testdata/, examples/ are skipped by default. A
    `// temporary` in a fixture is honest.
 3. Severities are graded and `--fail-on` defaults to `medium`. The two `high`
    rules (`claim.no-branch`, `name.no-input-branch`, `negation.*`) are the ones
    with almost no honest explanation in database source.
 4. `--allow-file` takes the same path-glob + regex pairs as obfuscation.py.
A doc comment that genuinely describes a different layer than its body — "see
the module docs for the validation rules" — should say so in words the first
sentence can carry, which is also better documentation.

HONEST LIMITS — THIS IS NOT A RUST PARSER
-----------------------------------------
Like invariants.py there is no `syn` here. Functions are found by matching a
signature and brace-counting the body, over the NEW side of the diff (added plus
context lines). With `git diff -U0` there is no context, so a function whose body
the hunk only partially covers is marked truncated and judged conservatively:
truncated bodies are never reported for a missing branch, because the branch may
be in a line the diff did not show. Pass `-U5` (or more) for the strongest
reading, or `--tree` to let the check read the whole function from the head tree.

HOW IT CAN BE EVADED
--------------------
* Write a branch that does nothing: `if token.is_empty() { /* ok */ }` satisfies
  every branch heuristic here and validates nothing. This check proves a comment
  is *consistent in shape* with its body, never that the body is correct.
* Say nothing. A function with no doc comment makes no claim to contradict, so
  deleting the doc and shipping the backdoor scores one `doc.deleted-*` finding
  instead of a `claim.*` one — which is why that rule exists, and why review
  should treat an undocumented change to an auth path as the weaker position.
* Make the claim vague: "Handles the token." Nothing is promised.
* Put the lie in the PR description and nothing in the source. Pass the PR body
  with `--pr-body` so it is scanned like a comment; a lie told only in review
  comments on GitHub is outside any file this check can read.
* Satisfy the negation heuristic by not naming the thing: comment "never skip
  the check" with code that sets a numeric mode constant whose meaning is "skip".

EXIT CODES
----------
  0  nothing at or above --fail-on
  1  at least one finding at or above --fail-on
  2  usage or internal error

EXAMPLES
--------
  git diff -U5 base...head | ./comment_consistency.py --diff -
  ./comment_consistency.py --diff d.patch --tree ../.. --fail-on high
  ./comment_consistency.py --git-range origin/main...HEAD --pr-body pr.md --format json
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path

CHECK = "comment_consistency"
SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

TEST_PATH_RE = re.compile(r"(^|/)(tests?|benches|fuzz|sim|testdata|fixtures|examples|vendor)(/|$)")

# --------------------------------------------------------------------------- vocabulary

# A validation claim, and only in CLAIM POSITION: the verb has to open the first
# sentence of the doc comment, which is the rustdoc convention ("Validates the …").
# Anchoring it here is what keeps "the borrow checker enforces that" out of the report:
# the subject of that sentence is not the function.
CLAIM_VERB_RE = re.compile(
    r"(?i)^(?:this\s+(?:function|helper|method|fn|routine)\s+|"
    r"(?:a|the)\s+helper\s+(?:that|which)\s+|it\s+)?"
    r"(?P<verb>validat(?:e|es)|verif(?:y|ies)|check(?:s)?|ensur(?:e|es)|assert(?:s)?|"
    r"authori[sz](?:e|es)|authenticat(?:e|es)|guard(?:s)?|reject(?:s)?|enforc(?:e|es)|"
    r"sanitis(?:e|es)|sanitiz(?:e|es)|refus(?:e|es)|permit(?:s)?|den(?:y|ies))\b"
)
# Wording that promises a failure path.
ERROR_CLAIM_RE = re.compile(
    r"(?i)(returns?\s+(?:an?\s+)?err(?:or)?|returns?\s+`?Err|errors?\s+(?:if|when|on)|"
    r"fail(?:s|ing)?\s+(?:if|when|with|on)|returns?\s+`?None|panics?\s+(?:if|when)|"
    r"bails?\s+(?:out|if|when)|rejects?\s+(?:if|when|with)|is\s+an\s+error)"
)
TEMP_MARKER_RE = re.compile(
    r"(?i)\b(temporar(?:y|ily)|will\s+be\s+removed|to\s+be\s+removed|remove\s+(?:this\s+)?before|"
    r"revert\s+before|for\s+now|place-?holder|stop-?gap|interim|debug(?:ging)?\s+only|"
    r"do\s+not\s+ship|not\s+for\s+production|disable[d]?\s+for\s+(?:now|testing)|"
    r"(?:TODO|FIXME|XXX|HACK)\b[^\n]{0,40}\b(remove|revert|restore|re-?enable))\b"
)
NEGATION_RE = re.compile(
    r"(?i)\b(must\s+not|must\s+never|may\s+not|should\s+not|shouldn'?t|should\s+never|"
    r"do\s+not|does\s+not|don'?t|doesn'?t|never|cannot|can'?t|is\s+not\s+allowed|"
    r"are\s+not\s+allowed|under\s+no\s+circumstances|no\s+longer)\b"
)
OBLIGATION_RE = re.compile(
    r"(?i)\b(must|must\s+always|always|shall|has\s+to|have\s+to|needs?\s+to|is\s+required\s+to|"
    r"is\s+mandatory)\b"
)
# Mechanisms a doc comment can name that the body should then contain.
MECHANISMS: list[tuple[str, str]] = [
    ("fsync", r"(?i)\b(fsync|sync_all|sync_data|fdatasync|flush(?:es|ed)?)\b"),
    ("quorum", r"(?i)\bquorum\b"),
    ("timeout", r"(?i)\b(timeout|deadline|time_?out)\b"),
    ("signature", r"(?i)\b(signature|verify_sig|sign(?:ed|ing)?)\b"),
    ("checksum", r"(?i)\b(checksum|crc|digest|hash)\b"),
    ("retry", r"(?i)\bretr(?:y|ies|ying)\b"),
    ("rate limit", r"(?i)\brate[_ ]?limit\w*\b"),
    ("permission check", r"(?i)\b(permission|authori[sz]|require_user|require_auth|acl)\w*\b"),
]

STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "be", "is", "are", "was", "were", "been", "being",
    "this", "that", "these", "those", "it", "its", "to", "for", "of", "in", "on", "at", "by",
    "with", "without", "from", "into", "as", "any", "all", "not", "no", "we", "you", "they",
    "when", "while", "if", "then", "than", "so", "because", "call", "called", "calls", "ever",
    "here", "there", "which", "who", "what", "how", "why", "ever", "even", "only", "also",
    "ever", "yet", "still", "more", "most", "less", "least", "other", "same", "such", "own",
    "function", "method", "caller", "callers", "code", "value", "values", "field", "fields",
    "used", "use", "uses", "using", "see", "note", "safety", "panics", "errors", "returns",
}

# --------------------------------------------------------------------------- code shape

FN_SIG_RE = re.compile(
    r"^\s*(?P<pub>pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:(?:async|const|unsafe|extern\s+\"[^\"]*\")\s+)*"
    r"fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
DOC_LINE_RE = re.compile(r"^\s*(///|//!|//|/\*|\*/|\*(?!\w))")
STRICT_DOC_LINE_RE = re.compile(r"^\s*(///|//!|/\*\*)")
BLOCK_COMMENT_BODY_RE = re.compile(r"^\s*(\*|/\*|\*/)")

BRANCH_RE = re.compile(r"(?:^|[^\w.])(?:if|match|while|loop|for)\b")
TRY_RE = re.compile(r"\?\s*(?:[;,)\]]|\.|$)", re.M)
RETURN_RE = re.compile(r"\breturn\b")
CMP_RE = re.compile(r"==|!=|<=|>=|&&|\|\|")
ASSERT_RE = re.compile(r"\b(?:assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|ensure|bail)!")
PRED_RE = re.compile(r"\.(?:is_[a-z_]+|contains|contains_key|starts_with|ends_with|eq_ignore_ascii_case)\s*\(")
ERRPATH_RE = re.compile(
    r"\bErr\s*\(|\breturn\s+Err\b|\bbail!|\banyhow!|\bpanic!|\bunreachable!|\btodo!|"
    r"\bunimplemented!|\.ok_or|\.ok_or_else|\breturn\s+None\b|\?\s*(?:[;,)\]]|\.)"
)
RESULTY_RE = re.compile(r"->\s*[^{;]*\b(?:Result|Option|anyhow::Result|io::Result)\b|->\s*!")
TRIVIAL_BODY_RE = re.compile(r"^\s*\{\s*(?:true|false|Ok\s*\(\s*\(\s*\)\s*\)|Ok\s*\(\s*[A-Za-z0-9_.]+\s*\)|\(\s*\))?\s*\}\s*$")
CONDITION_SEG_RE = re.compile(r"\b(?:if|while|match)\b([^{;]*)")


def shannon_words(text: str) -> list[str]:
    return [w for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)]


def strip_code_comments(text: str) -> str:
    """Blank out // and /* */ comments and the CONTENTS of string/char literals.

    Length and newlines are preserved so offsets and line numbers still line up.
    Without this, a comment that mentions `if` makes a branch-less body look like it
    branches — which is exactly the disguise this check is about.
    """
    out = list(text)
    i, n = 0, len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if c == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue
        m = re.match(r'(?:b?r)(#*)"', text[i : i + 16])
        if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            close = '"' + m.group(1)
            j = text.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            blank(i + m.end(), j - len(close))
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i + 1, j - 1)
            i = j
            continue
        i += 1
    return "".join(out)


def first_sentence(doc: str) -> str:
    """The first sentence of a doc comment, markers and markdown stripped."""
    text = " ".join(
        re.sub(r"^\s*(?:///|//!|//|/\*\*|/\*|\*/|\*)\s?", "", ln) for ln in doc.splitlines()
    ).strip()
    text = re.sub(r"`([^`]*)`", r"\1", text)
    m = re.search(r"(?<![A-Z])\.(?:\s|$)", text)
    return (text[: m.start()] if m else text).strip()


def doc_text(doc: str) -> str:
    return " ".join(
        re.sub(r"^\s*(?:///|//!|//|/\*\*|/\*|\*/|\*)\s?", "", ln) for ln in doc.splitlines()
    ).strip()


# --------------------------------------------------------------------------- diff parsing


class Line:
    __slots__ = ("origin", "new_line", "old_line", "text")

    def __init__(self, origin: str, new_line: int, old_line: int, text: str):
        self.origin, self.new_line, self.old_line, self.text = origin, new_line, old_line, text


class Hunk:
    __slots__ = ("path", "new_start", "old_start", "lines", "header")

    def __init__(self, path: str, new_start: int, old_start: int, header: str):
        self.path, self.new_start, self.old_start, self.header = path, new_start, old_start, header
        self.lines: list[Line] = []

    @property
    def added(self) -> list[Line]:
        return [l for l in self.lines if l.origin == "+"]

    @property
    def removed(self) -> list[Line]:
        return [l for l in self.lines if l.origin == "-"]

    @property
    def new_side(self) -> list[Line]:
        return [l for l in self.lines if l.origin in "+ "]


class FileDiff:
    __slots__ = ("path", "hunks")

    def __init__(self, path: str):
        self.path = path
        self.hunks: list[Hunk] = []


def parse_unified_diff(diff: str) -> list[FileDiff]:
    """Unified diff -> per-file hunks that keep BOTH sides and both line numberings.

    literal_triggers.py and obfuscation.py only need added lines; this check needs the
    new side with its context (to see a whole function body) and the removed side (to
    see a deleted doc comment), so the parser is a little bigger here.
    """
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    hunk: Hunk | None = None
    newno = oldno = 0

    for raw in diff.splitlines():
        if raw.startswith("diff --git"):
            hunk = None
            continue
        if raw.startswith("+++ "):
            p = raw[4:].strip().split("\t")[0]
            if p.startswith("b/"):
                p = p[2:]
            p = "<dev-null>" if p == "/dev/null" else p
            cur = FileDiff(p)
            files.append(cur)
            hunk = None
            continue
        if raw.startswith("--- ") or raw.startswith("index ") or raw.startswith("old mode") \
                or raw.startswith("new mode") or raw.startswith("similarity ") \
                or raw.startswith("rename ") or raw.startswith("Binary files"):
            continue
        m = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$", raw)
        if m:
            if cur is None:
                cur = FileDiff("<unknown>")
                files.append(cur)
            oldno, newno = int(m.group(1)), int(m.group(2))
            hunk = Hunk(cur.path, newno, oldno, m.group(3).strip())
            cur.hunks.append(hunk)
            continue
        if hunk is None:
            continue
        if raw.startswith("\\"):
            continue
        if raw.startswith("+"):
            hunk.lines.append(Line("+", newno, 0, raw[1:]))
            newno += 1
        elif raw.startswith("-"):
            hunk.lines.append(Line("-", 0, oldno, raw[1:]))
            oldno += 1
        else:
            hunk.lines.append(Line(" ", newno, oldno, raw[1:] if raw else ""))
            newno += 1
            oldno += 1
    return files


def git_diff(rng: str, repo: str | None, context: int) -> str:
    p = subprocess.run(
        ["git", "diff", f"-U{context}", "--no-color", "-M", rng],
        cwd=repo, capture_output=True, text=True, errors="replace",
    )
    if p.returncode != 0:
        raise SystemExit(f"ERROR   {CHECK} :: git diff failed: {p.stderr.strip()}")
    return p.stdout


# --------------------------------------------------------------------------- function recovery


class Fn:
    __slots__ = ("path", "name", "line", "doc", "doc_line", "signature", "body", "is_pub",
                 "truncated", "touched", "source")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    @property
    def params(self) -> list[str]:
        return signature_params(self.signature)


def signature_params(signature: str) -> list[str]:
    """Parameter NAMES from a signature. Destructuring extractors (axum's
    `State(st): State<AppState>`) contribute the inner binding, which is what the
    body actually uses."""
    p = signature.find("(")
    if p < 0:
        return []
    depth, end = 0, len(signature)
    for i in range(p, len(signature)):
        if signature[i] in "([<{":
            depth += 1
        elif signature[i] in ")]>}":
            depth -= 1
            if depth == 0:
                end = i
                break
    inner = signature[p + 1 : end]
    out: list[str] = []
    depth = 0
    cur = ""
    for ch in inner:
        if ch in "([<{":
            depth += 1
        elif ch in ")]>}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    names: list[str] = []
    for piece in out:
        piece = piece.strip()
        if not piece or piece.startswith("&") or piece in ("self", "&self", "&mut self", "mut self"):
            continue
        lhs = piece.split(":", 1)[0]
        for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", lhs):
            if ident in ("mut", "ref", "self"):
                continue
            names.append(ident)
    return names


def segments(lines: list[Line]) -> list[list[Line]]:
    """Maximal runs of new-side lines with consecutive line numbers."""
    out: list[list[Line]] = []
    run: list[Line] = []
    for l in lines:
        if run and l.new_line != run[-1].new_line + 1:
            out.append(run)
            run = []
        run.append(l)
    if run:
        out.append(run)
    return out


def recover_functions(path: str, lines: list[Line], source: str = "diff") -> list[Fn]:
    """Functions visible in a run of new-side lines, with their doc comment and body.

    `truncated` is set when the body's braces never balance inside what we can see; a
    truncated body is judged conservatively (see judge_fn).
    """
    fns: list[Fn] = []
    for seg in segments(lines):
        texts = [l.text for l in seg]
        for i, text in enumerate(texts):
            m = FN_SIG_RE.match(text)
            if not m:
                continue
            # doc block: contiguous comment lines immediately above
            j = i - 1
            while j >= 0 and (DOC_LINE_RE.match(texts[j]) or re.match(r"^\s*#!?\[", texts[j])):
                j -= 1
            doc_lines = [t for t in texts[j + 1 : i] if DOC_LINE_RE.match(t)]
            # signature: from here to the opening brace
            sig_parts: list[str] = []
            k = i
            brace_at = -1
            while k < len(texts):
                sig_parts.append(texts[k])
                b = strip_code_comments(texts[k]).find("{")
                if b >= 0:
                    brace_at = k
                    break
                if ";" in strip_code_comments(texts[k]) and "(" not in texts[k]:
                    break
                k += 1
            if brace_at < 0:
                continue
            signature = re.sub(r"\s+", " ", " ".join(sig_parts)).strip()
            # body: brace-match from the opening brace onward
            joined = strip_code_comments("\n".join(texts[brace_at:]))
            start = joined.find("{")
            depth, end = 0, -1
            for idx in range(start, len(joined)):
                if joined[idx] == "{":
                    depth += 1
                elif joined[idx] == "}":
                    depth -= 1
                    if depth == 0:
                        end = idx + 1
                        break
            truncated = end < 0
            body = joined[start:] if truncated else joined[start:end]
            body_last = brace_at + body.count("\n")
            touched = any(l.origin == "+" for l in seg[j + 1 : min(body_last + 1, len(seg))])
            fns.append(
                Fn(
                    path=path,
                    name=m.group("name"),
                    line=seg[i].new_line,
                    doc="\n".join(doc_lines),
                    doc_line=seg[j + 1].new_line if doc_lines else seg[i].new_line,
                    signature=signature,
                    body=body,
                    is_pub=bool(m.group("pub")),
                    truncated=truncated,
                    touched=touched,
                    source=source,
                )
            )
    return fns


def functions_from_tree(path: str, tree: str, names: set[str]) -> list[Fn]:
    """Read whole functions out of the head tree, for the names a truncated diff showed.

    Gives the check a complete body when the diff was produced with -U0.
    """
    f = Path(tree) / path
    if not f.is_file():
        return []
    try:
        raw = f.read_text(errors="replace")
    except OSError:
        return []
    lines = [Line(" ", n + 1, n + 1, t) for n, t in enumerate(raw.splitlines())]
    return [fn for fn in recover_functions(path, lines, source="tree") if fn.name in names]


# --------------------------------------------------------------------------- body facts


def has_conditional(body: str) -> bool:
    return bool(
        BRANCH_RE.search(body)
        or TRY_RE.search(body)
        or RETURN_RE.search(body)
        or CMP_RE.search(body)
        or ASSERT_RE.search(body)
        or PRED_RE.search(body)
    )


def has_error_path(body: str) -> bool:
    return bool(ERRPATH_RE.search(body))


def condition_segments(body: str) -> list[str]:
    """Text the control flow actually decides on, plus any line carrying a comparison
    or a `?`. Used to ask whether a function branches on ITS OWN INPUT."""
    segs = [m.group(1) for m in CONDITION_SEG_RE.finditer(body)]
    for ln in body.splitlines():
        if CMP_RE.search(ln) or TRY_RE.search(ln) or PRED_RE.search(ln) or ASSERT_RE.search(ln) \
                or RETURN_RE.search(ln):
            segs.append(ln)
    return segs


def branches_on_input(fn: Fn) -> bool:
    params = [p for p in fn.params if p not in ("_",)]
    if not params:
        return True  # nothing to branch on; the rule does not apply
    segs = condition_segments(fn.body)
    if not segs:
        return False
    joined = "\n".join(segs)
    present = set(shannon_words(joined))
    return any(p in present for p in params)


def negation_objects(sentence: str, phrase_end: int) -> list[str]:
    """Content words after a negation / obligation phrase, as the thing being forbidden."""
    tail = sentence[phrase_end : phrase_end + 120]
    tail = re.split(r"[.;]", tail)[0]
    out = []
    for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
        lw = w.lower()
        if lw in STOPWORDS or len(lw) < 3:
            continue
        out.append(lw)
        if len(out) >= 4:
            break
    return out


ENABLE_TEMPLATES = [
    r"\b{w}\w*\s*[:=]\s*(?:true|Some|1)\b",
    r"\b(?:set_|enable_|allow_|force_|unlock_)?{w}\w*\s*\(\s*(?:true|1)\s*\)",
    r"\b(?:skip|bypass|disable|ignore|allow|unchecked|without)_?{w}\w*",
    r"\b{w}\w*_(?:skipped|bypassed|disabled|off)\b",
]
DISABLE_TEMPLATES = [
    r"\b\w*{w}\w*\s*[:=]\s*false\b",
    r"\b(?:set_|disable_)?{w}\w*\s*\(\s*(?:false|0)\s*\)",
    r"\b(?:skip|bypass|disable)_?{w}\w*",
]

# The obligation direction ("must always fsync") only looks at words that name a
# mechanism. Without this filter, an honest "callers must pass a prefix" next to
# `let prefix = None;` is a finding, and a gate that noisy gets routed around.
MECHANISM_WORD_RE = re.compile(
    r"(?i)^(?:fsync|fdatasync|sync|synced|flush|flushed|durable|durability|checksum|crc|digest|"
    r"signature|signed|sign|verify|verified|verification|validate|validated|validation|check|"
    r"checked|checks|quorum|majority|timeout|deadline|retry|retries|limit|limits|bound|bounds|"
    r"cap|capped|auth|authn|authz|authorize|authorise|authorization|authorisation|authenticate|"
    r"permission|permissions|acl|guard|guarded|encrypt|encrypted|encryption|tls|ssl|cert|"
    r"certificate|audit|redact|redacted|mask|masked|fence|fencing|barrier|strict|require|"
    r"required|enforced|enforce)$"
)


def enabling_match(word: str, text: str, templates: list[str]) -> str | None:
    w = re.escape(word)
    for t in templates:
        m = re.search(t.format(w=w), text, re.I)
        if m:
            return m.group(0)
    return None


# --------------------------------------------------------------------------- allowlist


def load_allowlist(path: str | None) -> list[tuple[str, re.Pattern]]:
    """Same format as obfuscation.py: `<path-glob><TAB or 2+ spaces><regex>`."""
    if not path:
        return []
    out: list[tuple[str, re.Pattern]] = []
    for raw in Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"\t+|\s{2,}", line, maxsplit=1)
        out.append((parts[0], re.compile(parts[1]) if len(parts) > 1 else re.compile(r".")))
    return out


def allowed(path: str, text: str, allow: list[tuple[str, re.Pattern]]) -> bool:
    return any(fnmatch(path, glob) and rx.search(text) for glob, rx in allow)


# --------------------------------------------------------------------------- judgement


def finding(rule: str, sev: str, path: str, line: int, symbol: str, detail: str, sample: str) -> dict:
    return {
        "rule": rule, "severity": sev, "file": path, "line": line,
        "symbol": symbol, "detail": detail, "sample": sample.strip()[:200],
    }


def judge_fn(fn: Fn, args) -> list[dict]:
    """Everything this check can say about one function. Pure: no IO, no globals."""
    out: list[dict] = []
    doc1 = first_sentence(fn.doc)
    docall = doc_text(fn.doc)
    body = fn.body
    cond = has_conditional(body)

    # --- claim.no-branch ----------------------------------------------------
    claim = CLAIM_VERB_RE.match(doc1)
    if claim and not fn.truncated and not cond:
        out.append(finding(
            "claim.no-branch", "high", fn.path, fn.line, fn.name,
            f"doc says “{doc1[:90]}” — a “{claim.group('verb')}” claim — but the body of `{fn.name}` has no "
            "conditional, no `?`, no early return and no assertion, so there is no input it can "
            "reject. The comment describes a check the code does not perform.",
            body[:160],
        ))

    # --- name.no-input-branch ----------------------------------------------
    nm = re.search(r"(?i)(verify|verif|check|validate|valid|authori[sz]e|authenticate|is_|has_|can_|"
                   r"allow|permit|ensure|assert|guard)", fn.name)
    if nm and not fn.truncated and fn.params and not branches_on_input(fn):
        trivial = bool(TRIVIAL_BODY_RE.match(body.strip()))
        out.append(finding(
            "name.no-input-branch", "high", fn.path, fn.line, fn.name,
            f"`{fn.name}` is named as a check (`{nm.group(0)}`) and takes "
            f"{', '.join(fn.params)}, but no conditional in the body mentions any parameter"
            + (" — the body is a constant answer" if trivial else "")
            + ". A check that does not read its input always returns the same verdict.",
            body[:160],
        ))

    # --- claim.impossible-error --------------------------------------------
    ec = ERROR_CLAIM_RE.search(docall)
    if ec and not fn.truncated:
        resultish = bool(RESULTY_RE.search(fn.signature))
        if not resultish:
            out.append(finding(
                "claim.impossible-error", "medium", fn.path, fn.line, fn.name,
                f"doc promises “{ec.group(0)}” but the signature `{fn.signature[:110]}` returns no "
                "Result/Option, so that path cannot exist.",
                fn.signature[:160],
            ))
        elif not has_error_path(body):
            out.append(finding(
                "claim.impossible-error", "medium", fn.path, fn.line, fn.name,
                f"doc promises “{ec.group(0)}” but the body constructs no error at all (no `Err(`, "
                "no `?`, no `bail!`, no `panic!`): the documented failure path is unreachable.",
                body[:160],
            ))

    # --- claim.doc-contradicts-body ----------------------------------------
    for label, rx in MECHANISMS:
        if re.search(rx, docall) and not re.search(rx, body) and not fn.truncated:
            if not re.search(rx, fn.signature):
                out.append(finding(
                    "claim.doc-contradicts-body", "medium", fn.path, fn.line, fn.name,
                    f"doc names “{label}” but nothing in the body of `{fn.name}` refers to it. "
                    "Either the mechanism was removed and the doc was not, or the doc is describing "
                    "a guarantee this code does not provide.",
                    doc1[:160],
                ))
                break

    # --- negation.enabled / negation.disabled ------------------------------
    out.extend(judge_negations(fn.path, fn.line, fn.name, fn.doc, body))
    return out


def judge_negations(path: str, line: int, symbol: str, doc: str, code: str) -> list[dict]:
    """A comment that forbids a thing, next to code that switches that thing on."""
    out: list[dict] = []
    text = doc_text(doc)
    for sentence in re.split(r"(?<=[.;])\s+", text):
        for rx, templates, rule, word in (
            (NEGATION_RE, ENABLE_TEMPLATES, "negation.enabled", "forbids"),
            (OBLIGATION_RE, DISABLE_TEMPLATES, "negation.disabled", "requires"),
        ):
            m = rx.search(sentence)
            if not m:
                continue
            objects = negation_objects(sentence, m.end())
            if rule == "negation.disabled":
                objects = [o for o in objects if MECHANISM_WORD_RE.match(o)]
            for obj in objects:
                hit = enabling_match(obj, code, templates)
                if hit:
                    out.append(finding(
                        rule, "high", path, line, symbol,
                        f"the comment {word} it (“{sentence.strip()[:100]}”) and the code next to it "
                        f"contains `{hit}` — the comment and the code disagree about “{obj}”.",
                        hit,
                    ))
                    return out
    return out


def judge_hunk_docs(h: Hunk, args) -> list[dict]:
    """A hunk that deletes documentation while changing the code it documented."""
    rem_doc = [l for l in h.removed if STRICT_DOC_LINE_RE.match(l.text) or BLOCK_COMMENT_BODY_RE.match(l.text)]
    add_doc = [l for l in h.added if STRICT_DOC_LINE_RE.match(l.text) or BLOCK_COMMENT_BODY_RE.match(l.text)]
    add_code = [l for l in h.added if l.text.strip() and not DOC_LINE_RE.match(l.text)]
    rem_code = [l for l in h.removed if l.text.strip() and not DOC_LINE_RE.match(l.text)]
    if len(rem_doc) - len(add_doc) < args.min_deleted_doc_lines:
        return []
    if not add_code or not rem_code:
        return []  # pure deletion of a function, or pure doc edit: a different rule's business
    return [finding(
        "doc.deleted-with-code-change", "medium", h.path, h.new_start, h.header or "<hunk>",
        f"{len(rem_doc)} doc-comment line(s) removed and {len(add_doc)} added, while the code in the "
        f"same hunk changed ({len(add_code)} added / {len(rem_code)} removed non-comment line(s)). "
        "The statement of intent a reviewer would compare the new code against is gone.",
        (rem_doc[0].text if rem_doc else "").strip(),
    )]


def judge_temp_markers(path: str, lines: list[Line]) -> list[dict]:
    out: list[dict] = []
    for l in lines:
        if not DOC_LINE_RE.match(l.text):
            # also catch a trailing comment on a code line
            idx = strip_code_comments(l.text)
            if len(idx) == len(l.text) and "//" not in l.text and "/*" not in l.text:
                continue
        m = TEMP_MARKER_RE.search(l.text)
        if m:
            out.append(finding(
                "marker.temporary", "medium", path, l.new_line, "<comment>",
                f"comment marks this code as not meant to survive (“{m.group(0)}”), but the commit "
                "ships it. Either it is permanent and the comment is false, or it is temporary and "
                "it needs an owner and a removal date.",
                l.text,
            ))
    return out


def judge_pr_body(text: str, fns: list[Fn], args) -> list[dict]:
    """The PR description is a comment with a wider audience. Same claims, same test:
    a description that promises a mechanism no changed function contains."""
    out: list[dict] = []
    all_bodies = "\n".join(f.body for f in fns) + "\n".join(f.signature for f in fns)
    for label, rx in MECHANISMS:
        if re.search(rx, text) and fns and not re.search(rx, all_bodies):
            out.append(finding(
                "pr.claim-unsupported", "medium", "<pr-body>", 0, "<pr>",
                f"the PR description names “{label}” but no function this diff touches refers to it.",
                next((ln for ln in text.splitlines() if re.search(rx, ln)), "")[:160],
            ))
    for sentence in re.split(r"(?<=[.;!])\s+", text):
        m = NEGATION_RE.search(sentence)
        if not m:
            continue
        for obj in negation_objects(sentence, m.end()):
            hit = enabling_match(obj, all_bodies, ENABLE_TEMPLATES)
            if hit:
                out.append(finding(
                    "pr.negation-enabled", "high", "<pr-body>", 0, "<pr>",
                    f"the PR description says “{sentence.strip()[:100]}” and the diff contains "
                    f"`{hit}`.", hit,
                ))
                break
    if TEMP_MARKER_RE.search(text):
        m = TEMP_MARKER_RE.search(text)
        out.append(finding(
            "pr.temporary", "low", "<pr-body>", 0, "<pr>",
            f"the PR description calls this change temporary (“{m.group(0)}”); nothing in the repo "
            "makes that true.", m.group(0),
        ))
    return out


# --------------------------------------------------------------------------- driver


def analyse(files: list[FileDiff], args, allow: list[tuple[str, re.Pattern]]) -> tuple[list[dict], list[Fn], int]:
    findings: list[dict] = []
    all_fns: list[Fn] = []
    skipped = 0
    for fd in files:
        if fd.path == "<dev-null>":
            continue
        if not args.include_tests and TEST_PATH_RE.search(fd.path):
            skipped += 1
            continue
        if args.path_regex and not re.search(args.path_regex, fd.path):
            continue
        if args.lang_regex and not re.search(args.lang_regex, fd.path):
            continue

        new_side = [l for h in fd.hunks for l in h.new_side]
        fns = [f for f in recover_functions(fd.path, new_side) if f.touched]
        if args.tree:
            truncated = {f.name for f in fns if f.truncated}
            if truncated:
                whole = functions_from_tree(fd.path, args.tree, truncated)
                by_name = {f.name: f for f in whole}
                fns = [by_name.get(f.name, f) if f.truncated else f for f in fns]
        all_fns.extend(fns)

        for f in fns:
            for fi in judge_fn(f, args):
                if allowed(fd.path, fi["sample"], allow):
                    continue
                findings.append(fi)
        for h in fd.hunks:
            findings.extend(judge_hunk_docs(h, args))
            findings.extend(
                fi for fi in judge_temp_markers(fd.path, h.added)
                if not allowed(fd.path, fi["sample"], allow)
            )
        # Negation mismatches between an added comment and the code beside it, even when
        # the comment is not attached to a function.
        for h in fd.hunks:
            side = h.new_side
            for idx, l in enumerate(side):
                if l.origin != "+" or not DOC_LINE_RE.match(l.text):
                    continue
                window = "\n".join(
                    x.text for x in side[max(0, idx - 1) : idx + 1 + args.negation_window]
                    if not DOC_LINE_RE.match(x.text)
                )
                for fi in judge_negations(fd.path, l.new_line, "<comment>", l.text, window):
                    if not allowed(fd.path, fi["sample"], allow):
                        findings.append(fi)

    # de-duplicate: the same rule on the same line, reported by two paths
    seen: set[tuple] = set()
    uniq: list[dict] = []
    for f in findings:
        k = (f["rule"], f["file"], f["line"], f["detail"][:60])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    return uniq, all_fns, skipped


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="comment_consistency.py",
        description="Flag code whose comments, doc strings, names or PR description misrepresent it.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit 1 means a comment and the code under it disagree; read the finding and decide "
               "which one is lying.",
    )
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("--diff", help="unified diff file, or - for stdin")
    src.add_argument("--git-range", help="e.g. origin/main...HEAD (runs git diff for you)")
    p.add_argument("--repo", default=None, help="repository directory for --git-range")
    p.add_argument("--context", type=int, default=5, help="context lines for --git-range (default 5)")
    p.add_argument("--tree", default=None, help="head checkout; used to read whole bodies the diff truncated")
    p.add_argument("--pr-body", default=None, help="file holding the PR description, scanned like a comment")
    p.add_argument("--negation-window", type=int, default=6,
                   help="lines after a comment that count as 'adjacent code' (default 6)")
    p.add_argument("--min-deleted-doc-lines", type=int, default=2,
                   help="net doc lines a hunk must delete before doc.deleted-with-code-change fires (default 2)")
    p.add_argument("--allow-file", default=None, help="allowlist file (path-glob + regex per line)")
    p.add_argument("--include-tests", action="store_true", help="also scan tests/, testdata/, examples/")
    p.add_argument("--path-regex", default=None, help="only scan files whose path matches this regex")
    p.add_argument("--lang-regex", default=r"\.rs$", help="file extensions to treat as code (default \\.rs$)")
    p.add_argument("--fail-on", choices=["low", "medium", "high"], default="medium",
                   help="lowest severity that fails (default medium)")
    p.add_argument("--format", choices=["text", "json"], default="text", help="stdout format (default text)")
    p.add_argument("--json", dest="json_out", default=None, help="also write the machine-readable report here")
    p.add_argument("--self-test", action="store_true", help="run the built-in testdata cases and exit")
    args = p.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.diff and not args.git_range:
        p.error("one of --diff, --git-range or --self-test is required")

    if args.diff:
        diff = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text(errors="replace")
    else:
        diff = git_diff(args.git_range, args.repo, args.context)

    allow = load_allowlist(args.allow_file)
    files = parse_unified_diff(diff)
    findings, fns, skipped = analyse(files, args, allow)

    if args.pr_body:
        findings.extend(judge_pr_body(Path(args.pr_body).read_text(errors="replace"), fns, args))

    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"], f["rule"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    payload = {
        "check": CHECK,
        "files_changed": len([f for f in files if f.path != "<dev-null>"]),
        "functions_judged": len(fns),
        "counts": counts,
        "findings": findings,
    }

    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        for f in findings:
            level = {"high": "FINDING", "medium": "WARN   ", "low": "INFO   "}[f["severity"]]
            print(f"{level} {CHECK}.{f['rule']} {f['file']}:{f['line']} [{f['severity']}] "
                  f"{f['symbol']} :: {f['detail']} | {f['sample']}")
        print(f"INFO    {CHECK} :: {len(fns)} changed function(s) judged "
              f"({skipped} test-path file(s) skipped)")
        print(f"-- {CHECK}: {counts['high']} high, {counts['medium']} medium, {counts['low']} low")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2))

    threshold = SEV_ORDER[args.fail_on]
    return 1 if any(SEV_ORDER[f["severity"]] >= threshold for f in findings) else 0


# --------------------------------------------------------------------------- self-test

TESTDATA = Path(__file__).resolve().parent / "testdata"


def self_test() -> int:
    """Run the check over its own testdata and assert the exit codes CI depends on."""
    cases = [
        ("comment_consistency_sabotage.diff", 1),
        ("comment_consistency_clean.diff", 0),
    ]
    bad = 0
    for name, want in cases:
        path = TESTDATA / name
        if not path.is_file():
            print(f"ERROR   {CHECK}.self-test :: missing testdata {path}")
            bad += 1
            continue
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--diff", str(path), "--format", "json"])
        ok = rc == want
        print(f"{'PASS' if ok else 'FAIL'}    {CHECK}.self-test {name} :: exit {rc}, want {want}")
        bad += 0 if ok else 1
    print(f"-- {CHECK}.self-test: {len(cases) - bad}/{len(cases)} case(s) as expected")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
