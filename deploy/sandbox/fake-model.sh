#!/usr/bin/env bash
# A deterministic stand-in for the pinned model, used by scripts/e2e.sh and local demos.
# It makes a real, compiling change to the test app (shashirsb/agentreksdb-trailhead-helloworld) so the
# command driver, diff-policy and tests can be exercised without an API key. It never calls a model.
#   FAKE_MODEL_REPO   path or URL of the test app to clone (default: the public GitHub repo)
# Behaviour by spec title: contains "socket" -> adds a network call (diff-policy must block it);
# otherwise adds a `farewell` function with tests.
set -euo pipefail
RUN="$TRAILHEAD_RUN_DIR"; OUT="$RUN/out"; mkdir -p "$OUT"
SRC="${FAKE_MODEL_REPO:-https://github.com/shashirsb/agentreksdb-trailhead-helloworld.git}"
git clone --quiet "$SRC" "$RUN/repo"
cd "$RUN/repo"
git rev-parse HEAD > "$OUT/base"
echo "fake-model" > "$OUT/image_digest"
TITLE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("title") or "")' "$RUN/spec.json")
log() { printf '{"type":"assistant","driver":"fake-model","text":%s}\n' "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1")" >> "$OUT/transcript.jsonl"; }
log "Implementing: $TITLE"
case "$(echo "$TITLE" | tr '[:upper:]' '[:lower:]')" in
  *socket*)
    cat >> src/lib.rs <<'RS'

/// Report a greeting to a remote collector.
pub fn report(addr: &str) -> std::io::Result<()> {
    let _s = std::net::TcpStream::connect(addr)?;
    Ok(())
}
RS
    ;;
  *)
    python3 - <<'PY'
p = "src/lib.rs"
s = open(p).read()
fn = '''
/// Say goodbye by name. Blank names fall back to "trekker".
pub fn farewell(name: &str) -> String {
    let name = name.trim();
    let name = if name.is_empty() { "trekker" } else { name };
    format!("Goodbye, {name}! See you at the next camp.")
}
'''
tests = '''
    #[test]
    fn farewell_by_name() {
        assert_eq!(farewell("Shashi"), "Goodbye, Shashi! See you at the next camp.");
    }

    #[test]
    fn blank_farewell_falls_back() {
        assert_eq!(farewell(""), "Goodbye, trekker! See you at the next camp.");
    }
}
'''
s = s.replace("\n#[cfg(test)]", fn + "\n#[cfg(test)]", 1)
s = s.rstrip()
assert s.endswith("}")
s = s[:-1].rstrip() + "\n" + tests
open(p, "w").write(s)
PY
    ;;
esac
if cargo test --quiet >> "$OUT/cargo.log" 2>&1; then log "cargo test passed"; else log "cargo test FAILED"; fi
printf '{"type":"result","driver":"fake-model","total_cost_usd":0.12}\n' >> "$OUT/transcript.jsonl"
echo 0.12 > "$OUT/cost_usd"
git add -A
git diff --cached --binary > "$OUT/patch"
