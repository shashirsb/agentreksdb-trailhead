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
# Dependencies: the sandbox has no internet, so the host downloads every crate in the target's Cargo.lock
# first (a separate, networked container that runs no project code: `cargo fetch` executes no build
# scripts) into a persistent cache, and copies the downloaded archives into the run. The lockfile is the
# one on main, and diff-policy blocks dependency changes, so the copy is always sufficient.
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

WS="${TRAILHEAD_WORKSPACE_DIR:-.}"
# Must live under the runs directory: it is the only host path the Trailhead container shares with the
# Docker daemon at the same location, so both `docker run -v` and the copy below see the same files.
CACHE="${TRAILHEAD_CARGO_CACHE:-$(dirname "$RUN")/.cargo-cache}"
mkdir -p "$CACHE" "$RUN/cargo/registry"
if [ -f "$HOST/pristine/$WS/Cargo.lock" ]; then
  docker run --rm -u 0 --network bridge --cap-drop ALL --cap-add DAC_OVERRIDE --security-opt no-new-privileges \
    -v "$HOST/pristine:/src:ro" -v "$CACHE:/cargo" -e CARGO_HOME=/cargo \
    --entrypoint cargo "$IMAGE" fetch --locked --manifest-path "/src/$WS/Cargo.toml" >/dev/null
  # Archives and index only (~80 MB for AgentreksDB); the sandbox unpacks them into its own copy,
  # so nothing it does can touch the shared cache.
  cp -a "$CACHE/registry/cache" "$CACHE/registry/index" "$RUN/cargo/registry/"
  [ -d "$CACHE/git" ] && cp -a "$CACHE/git" "$RUN/cargo/" || true
fi
# The sandbox runs as an unprivileged user; let it write the run directory (and nothing else on the host).
chmod -R a+rwX "$RUN"
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
  -e CARGO_HOME=/run/trailhead/cargo \
  -e TRAILHEAD_WORKSPACE_DIR="$WS" \
  -e ANTHROPIC_MODEL="$TRAILHEAD_MODEL_ID" \
  -e ANTHROPIC_SMALL_FAST_MODEL="$TRAILHEAD_MODEL_ID" \
  -e ANTHROPIC_DEFAULT_HAIKU_MODEL="$TRAILHEAD_MODEL_ID" \
  -e CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  -e DISABLE_AUTOUPDATER=1 \
  "$IMAGE" /opt/trailhead/run.sh
STATUS=$?
set -e

# Rebuild the patch on the host from files only (deletions included: clear the tree first).
find "$HOST/pristine" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
( cd "$RUN/repo" && tar --exclude=./.git -cf - . ) | ( cd "$HOST/pristine" && tar -xf - )
( cd "$HOST/pristine" && git add -A && git diff --cached --binary ) > "$RUN/out/patch"
echo "$BASE" > "$RUN/out/base"
echo "$DIGEST" > "$RUN/out/image_digest"
# Keep the outputs (patch, transcript, cost); drop the bulky build state.
rm -rf "$HOST" "$RUN/cargo" "$RUN/repo"
exit $STATUS
