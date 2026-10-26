#!/usr/bin/env bash
# Host side of one generation run (TRAILHEAD_SANDBOX_COMMAND).
#
# 1. Clone the target repo into a HOST-ONLY directory and record the base commit there.
# 2. Copy the working tree into the run directory and start run.sh in a locked-down container whose
#    only network is `trailhead-sandbox` (internal, no internet), where `trailhead model-proxy` is the
#    single reachable host. The container gets the proxy token, never the real API key.
# 3. After it exits, rebuild the patch on the host: copy the sandbox's files (not its .git, which the
#    model could have tampered with) over the pristine checkout and diff against the recorded base.
#    The sandbox's own out/base and out/patch are ignored.
#
# This Docker profile is the small-deployment default. For untrusted public traffic, replace the
# `docker run` with a Firecracker microVM (one kernel per run); the contract is the same.
set -euo pipefail
RUN="$TRAILHEAD_RUN_DIR"
HOST="${RUN}.host"
IMAGE="${TRAILHEAD_SANDBOX_IMAGE:-ghcr.io/shashirsb/agentreksdb-trailhead-sandbox:main}"
: "${TRAILHEAD_PROXY_TOKEN:?set TRAILHEAD_PROXY_TOKEN}"

mkdir -p "$HOST" "$RUN/out"
git clone --quiet --depth 1 "https://github.com/${TRAILHEAD_TARGET_REPO}.git" "$HOST/pristine"
BASE=$(git -C "$HOST/pristine" rev-parse HEAD)
cp -a "$HOST/pristine" "$RUN/repo"
DIGEST=$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || echo "$IMAGE")

set +e
docker run --rm \
  --network trailhead-sandbox \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 4096 \
  --cpus "${TRAILHEAD_SANDBOX_CPUS:-2}" --memory "${TRAILHEAD_SANDBOX_MEMORY:-3g}" \
  --read-only --tmpfs /tmp:exec,size=4g --tmpfs /home/sandbox:size=1g \
  -v "$RUN:/run/trailhead" \
  -e TRAILHEAD_RUN_DIR=/run/trailhead \
  -e TRAILHEAD_MODEL_ID -e TRAILHEAD_MAX_BUDGET_USD -e TRAILHEAD_ALLOWED_TOOLS -e TRAILHEAD_TARGET_REPO \
  -e TRAILHEAD_SANDBOX_IMAGE_DIGEST="$DIGEST" \
  -e ANTHROPIC_BASE_URL=http://model-proxy:8888 \
  -e ANTHROPIC_API_KEY="$TRAILHEAD_PROXY_TOKEN" \
  -e CARGO_NET_OFFLINE=true \
  "$IMAGE" /opt/trailhead/run.sh
STATUS=$?
set -e

# Rebuild the patch on the host from files only (deletions included: clear the tree first).
find "$HOST/pristine" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
( cd "$RUN/repo" && tar --exclude=./.git -cf - . ) | ( cd "$HOST/pristine" && tar -xf - )
( cd "$HOST/pristine" && git add -A && git diff --cached --binary ) > "$RUN/out/patch"
echo "$BASE" > "$RUN/out/base"
echo "$DIGEST" > "$RUN/out/image_digest"
rm -rf "$HOST"
exit $STATUS
