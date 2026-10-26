#!/usr/bin/env bash
# Generation run for ONE intent. Run this INSIDE the isolated sandbox (Firecracker microVM or, for
# small deployments, a locked-down container): no keys on disk, egress only to the model API through
# the key-injecting proxy, vendored crates. The worker calls it with TRAILHEAD_SANDBOX=command and
#   TRAILHEAD_SANDBOX_COMMAND="deploy/sandbox/launch.sh"  (which boots the sandbox and runs this file)
#
# Inputs (env): TRAILHEAD_RUN_DIR (contains spec.json, prompt.md, out/), TRAILHEAD_MODEL_ID,
#   TRAILHEAD_MAX_BUDGET_USD, TRAILHEAD_ALLOWED_TOOLS, TRAILHEAD_TARGET_REPO
# Outputs in $TRAILHEAD_RUN_DIR/out: base, patch, transcript.jsonl, cost_usd, image_digest
set -euo pipefail
RUN="$TRAILHEAD_RUN_DIR"
OUT="$RUN/out"
mkdir -p "$OUT"

# launch.sh clones the target repo on the host side; the sandbox itself has no route to GitHub.
[ -d "$RUN/repo/.git" ] || git clone --quiet --depth 1 "https://github.com/${TRAILHEAD_TARGET_REPO}.git" "$RUN/repo"
cd "$RUN/repo"
git rev-parse HEAD > "$OUT/base"
echo "${TRAILHEAD_SANDBOX_IMAGE_DIGEST:-unknown}" > "$OUT/image_digest"

IFS=',' read -r -a TOOLS <<< "$TRAILHEAD_ALLOWED_TOOLS"
# Headless Claude Agent SDK: one dated model ID, a hard budget, a fixed tool allow-list, no prompts.
claude -p --bare \
  --model "$TRAILHEAD_MODEL_ID" \
  --max-budget-usd "$TRAILHEAD_MAX_BUDGET_USD" \
  --allowedTools "${TOOLS[@]}" \
  --permission-mode dontAsk \
  --output-format stream-json --verbose \
  < "$RUN/prompt.md" > "$OUT/transcript.jsonl"

# Cost as reported by the harness (client-side estimate; reconciled against the provider invoice monthly).
python3 - "$OUT/transcript.jsonl" > "$OUT/cost_usd" <<'PY'
import json, sys
cost = 0.0
for line in open(sys.argv[1]):
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    if ev.get("type") == "result":
        cost = float(ev.get("total_cost_usd") or 0)
print(cost)
PY

git add -A
git diff --cached --binary > "$OUT/patch"
