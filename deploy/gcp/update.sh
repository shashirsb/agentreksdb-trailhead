#!/bin/bash
# Auto-deploy for development: runs every 2 minutes from cron on the Trailhead VM.
# Pulls the repo (compose file, Caddyfile, website, these scripts) and the latest images published by
# .github/workflows/images.yml, then lets Docker Compose recreate only what changed. A push to main is
# live about 10 minutes later (image build + next tick). Database migrations run when the server starts.
set -euo pipefail
exec 9>/var/lock/trailhead-update.lock
flock -n 9 || exit 0
log() { echo "$(date -u +%FT%TZ) $*" >> /var/log/trailhead-update.log; }

cd /opt/trailhead
before=$(git rev-parse HEAD)
# This checkout is a mirror of main, never a place anyone commits, so the only honest answer to
# "the remote moved somewhere my history cannot reach" is to take the remote's word for it.
#
# It used to `exit 1` instead, and that wedged the deploy for half an hour: a commit was pushed,
# this VM pulled it, the message was then corrected and force-pushed, and from that moment every
# run died on the pull and never reached the image step. The site kept serving the old build with
# nothing obviously broken, which is the worst way for a deploy to fail. A rewritten or rolled-back
# main is rare but entirely normal, and a deployment machine should survive one unattended.
git fetch -q origin main || { log "git fetch failed"; exit 1; }
if ! git merge-base --is-ancestor HEAD origin/main 2>/dev/null; then
  log "main is not a fast-forward from $before (rewritten or rolled back); resetting to origin/main"
  git reset -q --hard origin/main || { log "reset failed"; exit 1; }
else
  git merge -q --ff-only origin/main || { log "ff merge failed"; exit 1; }
fi
after=$(git rev-parse HEAD)

cd deploy/prod
set -a; . ./.env; set +a
SANDBOX_IMAGE="${TRAILHEAD_SANDBOX_IMAGE:-ghcr.io/shashirsb/agentreksdb-trailhead-sandbox:main}"
ids_before=$(docker compose --env-file .env images -q 2>/dev/null | sort | tr '\n' ' ')
docker pull -q "$SANDBOX_IMAGE" >/dev/null 2>&1 || log "sandbox image pull failed"
docker compose --env-file .env pull -q 2>/dev/null || { log "image pull failed"; exit 1; }
docker compose --env-file .env up -d --remove-orphans >/dev/null 2>&1
ids_after=$(docker compose --env-file .env images -q 2>/dev/null | sort | tr '\n' ' ')

if [ "$before" != "$after" ]; then
  # Caddyfile or website changed: reload Caddy in place (no downtime).
  docker compose --env-file .env exec -T caddy caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1 || true
  log "repo $before -> $after"
fi
[ "$ids_before" != "$ids_after" ] && log "images updated: $ids_after"
docker image prune -f >/dev/null 2>&1 || true
