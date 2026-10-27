#!/usr/bin/env python3
# ruff: noqa
"""honeytokens.py — plant fake credentials in the build environment, then prove nothing read them.

SABOTAGE CLASS
--------------
Secret reading and exfiltration. A planted bug that harvests credentials does
not need to send them anywhere interesting to be useful: printing them into a
build log, embedding them in a test fixture, writing them into an artifact, or
posting them to a host that looks like a package mirror all work. Source-level
rules catch `env::var("AWS_SECRET_ACCESS_KEY")` when it is spelled that way;
they do not catch a loop over `std::env::vars()`, a read of /proc/self/environ,
a glob over $HOME, or a dependency doing it on the code's behalf.

So instead of looking for the read, this check looks for the *value*. It plants
credentials that look completely real but are worth nothing — an AWS-style key
pair, a bearer token, a JWT, a PEM-shaped private key blob, a Postgres URL, a
.netrc and an IMDS (169.254.169.254) stand-in — and then greps everything the
build produced for them: build logs, test output, the resulting diff, generated
artifacts, and a pcap if the job captured one. Any appearance means something
read a secret it was never asked to read. There is no benign explanation: the
values are unique to the run and nothing legitimate knows them.

Each token has a high-entropy `needle`. --verify searches for the needle raw and
re-encoded (base64 std/urlsafe, hex, reversed, sha256) so the obvious laundering
does not get past it. Findings print a redacted prefix, never the token.

HOW IT CAN BE EVADED
--------------------
* Encode the value in a way not tried here: encrypt it, compress it, split it
  across lines or fields, encode it in timing or in request ordering, or ship it
  as a DNS query (add a DNS-query log to --scan if the runner has one).
* Exfiltrate later: read the secret now, stash it in a long-lived artifact or
  cache, and send it from a different job. Scan the cache, and re-run --verify
  against published artifacts.
* Read a secret this check did not plant. Plant one in every shape the real
  pipeline has (see TRAILHEAD WIRING below) — an unplanted shape is unmonitored.
* Behave only outside CI (no honeytokens present, no ptrace, real hostname).
  env_invariance.py is the counterpart for that.
* Note the inverse false positive: a *legitimate* tool that echoes the whole
  environment (set -x, `env` in a debug step, a verbose docker build) will trip
  this. That is why --plant writes the token names into the state file and
  --verify reports which file matched: triage is reading one line of the log.

TRAILHEAD WIRING (GitHub Actions)
---------------------------------
  - name: plant honeytokens
    run: |
      python3 gates/checks/honeytokens.py --plant \
        --state "$RUNNER_TEMP/ht.json" \
        --env-file "$RUNNER_TEMP/ht.env" \
        --secret-dir "$HOME/.fake-creds" \
        --metadata-config "$RUNNER_TEMP/imds.json" \
        --github-env   # exports the token names into $GITHUB_ENV for later steps
  - name: build and test (logs captured)
    run: |
      set -o pipefail
      cargo nextest run 2>&1 | tee "$RUNNER_TEMP/test.log"
  - name: verify honeytokens
    if: always()
    run: |
      git diff -U0 "$BASE...$HEAD" > "$RUNNER_TEMP/head.patch"
      python3 gates/checks/honeytokens.py --verify \
        --state "$RUNNER_TEMP/ht.json" \
        --request-log "$RUNNER_TEMP/imds.log" \
        --scan "$RUNNER_TEMP/test.log" --scan "$RUNNER_TEMP/head.patch" \
        --scan target/debug --scan "$RUNNER_TEMP/capture.pcap"
Make the verify step a required check: a hit is a BLOCK, not advice. Add the
state file to .gitignore and never upload it as an artifact.

EXIT CODES
----------
  0  planted successfully / nothing found
  1  a honeytoken appeared somewhere it should not
  2  usage or internal error

EXAMPLES
--------
  ./honeytokens.py --plant --state ht.json --env-file ht.env --secret-dir ./creds
  ./honeytokens.py --verify --state ht.json --scan build.log --scan ./artifacts
  ./honeytokens.py --serve 127.0.0.1:8169 --state ht.json --request-log imds.log
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import string
import sys
from pathlib import Path

CHECK = "honeytokens"
CHUNK = 1 << 20

ALNUM = string.ascii_letters + string.digits
UPPER_NUM = string.ascii_uppercase + string.digits
B64CHARS = ALNUM + "+/"


def rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


# --------------------------------------------------------------------------- generation


def generate(tag: str) -> dict:
    """Realistic-looking, worthless credentials. `needle` is what --verify hunts for."""
    akid = "AKIA" + rand(16, UPPER_NUM)
    secret = rand(40, B64CHARS)
    bearer = f"thk_{tag}_" + rand(32)
    jwt_payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "honeytoken", "scope": "admin", "jti": rand(16)}).encode()
    ).decode().rstrip("=")
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + jwt_payload + "." + rand(43, ALNUM + "-_")
    pem_body = "\n".join(rand(64, B64CHARS) for _ in range(6))
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + pem_body
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    dbpass = rand(24)
    db_url = f"postgres://trailhead_ro:{dbpass}@db-honeypot.internal:5432/agentreksdb?sslmode=require"
    imds_token = rand(56)

    return {
        "tag": tag,
        "tokens": [
            {"name": "AWS_ACCESS_KEY_ID", "needle": akid, "value": akid, "shape": "aws-access-key-id"},
            {"name": "AWS_SECRET_ACCESS_KEY", "needle": secret, "value": secret, "shape": "aws-secret"},
            {"name": "TRAILHEAD_API_TOKEN", "needle": bearer, "value": bearer, "shape": "bearer"},
            {"name": "SERVICE_JWT", "needle": jwt_payload, "value": jwt, "shape": "jwt"},
            {"name": "SSH_PRIVATE_KEY", "needle": pem_body.splitlines()[0], "value": pem, "shape": "private-key"},
            {"name": "DATABASE_URL", "needle": dbpass, "value": db_url, "shape": "database-url"},
            {"name": "IMDS_SESSION_TOKEN", "needle": imds_token, "value": imds_token, "shape": "imds-token"},
        ],
    }


# --------------------------------------------------------------------------- planting


def plant(args) -> int:
    tag = args.tag or rand(6).lower()
    state = generate(tag)
    tokens = {t["name"]: t for t in state["tokens"]}
    written: list[str] = []

    if args.env_file:
        p = Path(args.env_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Planted by gates/checks/honeytokens.py — every value here is fake and unique to this run.",
            "# If any of these strings appears in a log, an artifact or the diff, something read it.",
        ]
        for name, t in tokens.items():
            if t["shape"] == "private-key":
                continue  # a multi-line PEM does not belong in a dotenv file
            lines.append(f"{name}={t['value']}")
        p.write_text("\n".join(lines) + "\n")
        os.chmod(p, 0o600)
        written.append(str(p))

    if args.secret_dir:
        d = Path(args.secret_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / "credentials").write_text(
            "[default]\n"
            f"aws_access_key_id = {tokens['AWS_ACCESS_KEY_ID']['value']}\n"
            f"aws_secret_access_key = {tokens['AWS_SECRET_ACCESS_KEY']['value']}\n"
        )
        (d / "id_ed25519").write_text(tokens["SSH_PRIVATE_KEY"]["value"])
        (d / ".netrc").write_text(
            f"machine api.trailhead.invalid login honeytoken password {tokens['TRAILHEAD_API_TOKEN']['value']}\n"
        )
        (d / "pgpass").write_text(
            f"db-honeypot.internal:5432:agentreksdb:trailhead_ro:{tokens['DATABASE_URL']['needle']}\n"
        )
        for f in ("credentials", "id_ed25519", ".netrc", "pgpass"):
            os.chmod(d / f, 0o600)
            written.append(str(d / f))

    if args.metadata_config:
        p = Path(args.metadata_config)
        p.parent.mkdir(parents=True, exist_ok=True)
        host, _, port = (args.serve or "127.0.0.1:8169").partition(":")
        cfg = {
            "_comment": (
                "Fake instance-metadata service. Point the sandbox's 169.254.169.254 at this "
                "host:port (iptables REDIRECT, or an /etc/hosts entry plus a listener) and run "
                "honeytokens.py --serve. Any request logged here is code probing for cloud credentials."
            ),
            "listen": {"host": host, "port": int(port or 8169)},
            "redirect_from": "169.254.169.254:80",
            "routes": {
                "/latest/api/token": tokens["IMDS_SESSION_TOKEN"]["value"],
                "/latest/meta-data/iam/security-credentials/": "trailhead-honeypot-role",
                "/latest/meta-data/iam/security-credentials/trailhead-honeypot-role": {
                    "Code": "Success",
                    "Type": "AWS-HMAC",
                    "AccessKeyId": tokens["AWS_ACCESS_KEY_ID"]["value"],
                    "SecretAccessKey": tokens["AWS_SECRET_ACCESS_KEY"]["value"],
                    "Token": tokens["IMDS_SESSION_TOKEN"]["value"],
                    "Expiration": "2099-01-01T00:00:00Z",
                },
                "/computeMetadata/v1/instance/service-accounts/default/token": {
                    "access_token": tokens["TRAILHEAD_API_TOKEN"]["value"],
                    "expires_in": 3599,
                    "token_type": "Bearer",
                },
            },
        }
        p.write_text(json.dumps(cfg, indent=2))
        written.append(str(p))

    state["planted_files"] = written
    sp = Path(args.state)
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps(state, indent=2))
    os.chmod(sp, 0o600)

    if args.github_env and os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a") as fh:
            for name, t in tokens.items():
                if t["shape"] != "private-key":
                    fh.write(f"{name}={t['value']}\n")
        print(f"INFO    {CHECK} :: exported {len(tokens) - 1} token(s) into $GITHUB_ENV")

    for name, t in tokens.items():
        print(f"INFO    {CHECK} :: planted {name} ({t['shape']}) needle={redact(t['needle'])}")
    for w in written:
        print(f"INFO    {CHECK} :: wrote {w}")
    print(f"INFO    {CHECK} :: state {sp} (secret — .gitignore it, never upload it)")
    print(f"-- {CHECK}: planted {len(tokens)} token(s) in {len(written)} file(s)")
    return 0


def redact(needle: str) -> str:
    return f"{needle[:6]}…<{len(needle)} chars>"


# --------------------------------------------------------------------------- verification


def variants(needle: str) -> list[tuple[str, bytes]]:
    """The needle plus the cheap launderings of it."""
    raw = needle.encode()
    out = [("raw", raw)]
    out.append(("base64", base64.b64encode(raw).rstrip(b"=")))
    out.append(("base64url", base64.urlsafe_b64encode(raw).rstrip(b"=")))
    out.append(("hex", raw.hex().encode()))
    out.append(("HEX", raw.hex().upper().encode()))
    out.append(("reversed", raw[::-1]))
    out.append(("sha256", hashlib.sha256(raw).hexdigest().encode()))
    seen = set()
    uniq = []
    for label, b in out:
        if b in seen or len(b) < 8:
            continue
        seen.add(b)
        uniq.append((label, b))
    return uniq


def scan_file(path: Path, needles: list[tuple[str, str, bytes]], max_bytes: int) -> list[dict]:
    """needles: (token_name, encoding, bytes). Chunked so a pcap or a binary is fine."""
    hits: list[dict] = []
    longest = max((len(n[2]) for n in needles), default=1)
    try:
        size = path.stat().st_size
    except OSError:
        return hits
    if max_bytes and size > max_bytes:
        return [{"file": str(path), "token": "-", "encoding": "-", "offset": -1,
                 "note": f"skipped: {size} bytes > --max-bytes {max_bytes}"}]
    try:
        with path.open("rb") as fh:
            base = 0
            carry = b""
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                buf = carry + chunk
                for name, enc, nb in needles:
                    start = 0
                    while True:
                        i = buf.find(nb, start)
                        if i < 0:
                            break
                        off = base - len(carry) + i
                        hits.append({"file": str(path), "token": name, "encoding": enc,
                                     "offset": off, "needle": redact(nb.decode("latin-1"))})
                        start = i + 1
                base += len(chunk)
                carry = buf[-(longest - 1):] if longest > 1 else b""
    except OSError as e:
        hits.append({"file": str(path), "token": "-", "encoding": "-", "offset": -1,
                     "note": f"unreadable: {e}"})
    return hits


def verify(args) -> int:
    state = json.loads(Path(args.state).read_text())
    planted = {os.path.realpath(p) for p in state.get("planted_files", [])}
    planted.add(os.path.realpath(args.state))

    needles: list[tuple[str, str, bytes]] = []
    for t in state["tokens"]:
        for enc, b in variants(t["needle"]):
            if enc == "raw" or not args.raw_only:
                needles.append((t["name"], enc, b))

    exclude_res = [re.compile(r) for r in args.exclude]
    targets: list[Path] = []
    for s in args.scan:
        p = Path(s)
        if not p.exists():
            print(f"INFO    {CHECK} :: --scan {s} does not exist; skipping")
            continue
        if p.is_dir():
            targets.extend(q for q in p.rglob("*") if q.is_file())
        else:
            targets.append(p)

    findings: list[dict] = []
    scanned = 0

    # A request to the fake metadata service never carries a token value, so scanning its log for
    # needles finds nothing: the request IS the finding. Check it separately.
    if args.request_log and Path(args.request_log).exists():
        for i, probe in enumerate(Path(args.request_log).read_text(errors="replace").splitlines()):
            if not probe.strip():
                continue
            findings.append({"file": args.request_log, "token": "IMDS_PROBE", "encoding": "request",
                             "offset": i + 1, "needle": probe.strip()[:160]})
            print(
                f"FINDING {CHECK}.imds-probe {args.request_log}:{i + 1} :: something asked the "
                f"instance-metadata service for cloud credentials: {probe.strip()[:160]}"
            )

    for t in targets:
        rp = os.path.realpath(t)
        if rp in planted and not args.include_planted:
            continue
        if any(rx.search(str(t)) for rx in exclude_res):
            continue
        scanned += 1
        for h in scan_file(t, needles, args.max_bytes):
            if "note" in h:
                print(f"INFO    {CHECK} :: {h['file']}: {h['note']}")
                continue
            findings.append(h)
            print(
                f"FINDING {CHECK}.token-appeared {h['file']}@{h['offset']} :: "
                f"honeytoken {h['token']} appeared ({h['encoding']} encoding, {h['needle']}). "
                "Nothing legitimate knows this value: code read a credential it was not given."
            )

    print(f"-- {CHECK}: {len(findings)} appearance(s) across {scanned} scanned file(s)")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps({"check": CHECK, "scanned": scanned, "findings": findings}, indent=2)
        )
    return 1 if findings else 0


# --------------------------------------------------------------------------- fake IMDS


def serve(args) -> int:
    """Minimal IMDS-shaped responder. Every request is logged; a request IS the finding."""
    import http.server
    import socketserver

    state = json.loads(Path(args.state).read_text())
    cfg_routes = {t["name"]: t["value"] for t in state["tokens"]}
    host, _, port = args.serve.partition(":")
    log_path = Path(args.request_log) if args.request_log else None

    hits = [0]

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _log_hit(self) -> None:
            hits[0] += 1
            line = f"{self.command} {self.path} from {self.client_address[0]} ua={self.headers.get('User-Agent', '-')}"
            print(f"FINDING {CHECK}.imds-probe {self.path} :: {line}")
            if log_path:
                with log_path.open("a") as fh:
                    fh.write(line + "\n")

        def do_GET(self) -> None:  # noqa: N802
            self._log_hit()
            body = json.dumps(
                {
                    "Code": "Success",
                    "AccessKeyId": cfg_routes["AWS_ACCESS_KEY_ID"],
                    "SecretAccessKey": cfg_routes["AWS_SECRET_ACCESS_KEY"],
                    "Token": cfg_routes["IMDS_SESSION_TOKEN"],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_PUT = do_GET
        do_POST = do_GET

        def log_message(self, *a) -> None:  # silence the default stderr spam
            return

    with socketserver.TCPServer((host, int(port or 8169)), Handler) as srv:
        print(f"INFO    {CHECK} :: fake IMDS on {host}:{port or 8169}; Ctrl-C to stop")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
    print(f"-- {CHECK}: {hits[0]} metadata probe(s)")
    return 1 if hits[0] else 0


# --------------------------------------------------------------------------- cli


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="honeytokens.py",
        description="Plant fake credentials, then prove nothing in the build read them.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plant", action="store_true", help="generate tokens and write them into the environment")
    mode.add_argument("--verify", action="store_true", help="scan logs/artifacts/diffs for the planted values")
    mode.add_argument("--serve", metavar="HOST:PORT", help="run the fake instance-metadata responder")
    default_state = str(
        Path(os.environ.get("RUNNER_TEMP", os.environ.get("TMPDIR", "."))) / "honeytokens-state.json"
    )
    p.add_argument("--state", default=default_state, help=f"state file holding the token values (default: {default_state})")
    p.add_argument("--tag", default=None, help="short tag embedded in the bearer token (default: random)")
    # plant
    p.add_argument("--env-file", default=None, help="dotenv file to write the tokens into")
    p.add_argument("--secret-dir", default=None, help="directory to write credentials/id_ed25519/.netrc/pgpass into")
    p.add_argument("--metadata-config", default=None, help="write the fake-IMDS config JSON here")
    p.add_argument("--github-env", action="store_true", help="also append the tokens to $GITHUB_ENV")
    # verify
    p.add_argument("--scan", action="append", default=[], help="file or directory to scan; repeatable")
    p.add_argument("--exclude", action="append", default=[r"/\.git/"], help="regex of paths to skip; repeatable")
    p.add_argument("--include-planted", action="store_true", help="also scan the files --plant wrote (they contain the tokens by design)")
    p.add_argument("--raw-only", action="store_true", help="search only the literal value, no encoded variants")
    p.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024, help="skip files larger than this (0 = no limit)")
    p.add_argument("--json", dest="json_out", default=None, help="write a machine-readable report here")
    # serve / verify
    p.add_argument("--request-log", default=None,
                   help="--serve: append fake-IMDS requests here. --verify: every line in it is a finding "
                        "(a metadata request carries no token value, so the request itself is the signal).")
    args = p.parse_args(argv)

    if args.plant:
        return plant(args)
    if args.serve:
        if not Path(args.state).exists():
            p.error(f"--serve needs an existing --state file (run --plant first); {args.state} not found")
        return serve(args)
    if not Path(args.state).exists():
        p.error(f"--verify needs the --state file written by --plant; {args.state} not found")
    if not args.scan:
        p.error("--verify needs at least one --scan path")
    return verify(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(2)
