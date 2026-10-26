#!/bin/bash
# VM bootstrap for Trailhead on Google Compute Engine. Runs as root on every boot (startup-script
# metadata) and is safe to re-run. Reads its settings from instance metadata and its secrets from
# Secret Manager; nothing secret is stored in metadata.
set -euo pipefail
exec > >(tee -a /var/log/trailhead-startup.log) 2>&1
echo "=== trailhead startup $(date -u +%FT%TZ)"

MD=http://metadata.google.internal/computeMetadata/v1
md() { curl -fsS -H Metadata-Flavor:Google "$MD/$1"; }
attr() { md "instance/attributes/$1"; }
REPO=$(attr trailhead-repo)
BUCKET=$(attr backup-bucket)
PROJECT=$(md project/project-id)
token() { md instance/service-accounts/default/token | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])'; }

# 1 GB of RAM on e2-micro: add 4 GB of swap once.
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh

if [ -d /opt/trailhead/.git ]; then
  git -C /opt/trailhead pull --ff-only --quiet
else
  git clone --quiet "https://github.com/$REPO.git" /opt/trailhead
fi

secret() {
  curl -fsS -H "Authorization: Bearer $(token)" \
    "https://secretmanager.googleapis.com/v1/projects/$PROJECT/secrets/$1/versions/latest:access" |
    python3 -c 'import json,sys,base64;sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)["payload"]["data"]))'
}
cd /opt/trailhead/deploy/prod
umask 077
secret trailhead-env > .env
secret trailhead-app-pem > app.pem
umask 022
mkdir -p /var/lib/trailhead/runs /var/backups/trailhead

# Prebuilt images (published by .github/workflows/images.yml); build locally only as a fallback.
set -a; . ./.env; set +a
SANDBOX_IMAGE="${TRAILHEAD_SANDBOX_IMAGE:-ghcr.io/shashirsb/agentreksdb-trailhead-sandbox:main}"
# Never compile on a 1 GB VM: if the images are not downloadable yet (e.g. still private on ghcr.io),
# wait and retry so the server comes up by itself as soon as they are made public.
until docker pull -q "$SANDBOX_IMAGE" && docker compose --env-file .env pull -q; do
  echo "images not downloadable yet; make the ghcr.io packages public. Retrying in 60 s."
  sleep 60
done
docker compose --env-file .env up -d --remove-orphans

# Nightly database backup to Cloud Storage (the public ledger must never be lost).
cat > /usr/local/bin/trailhead-backup <<BACKUP
#!/bin/bash
set -euo pipefail
f=/var/backups/trailhead/trailhead-\$(date -u +%F).sql.gz
cd /opt/trailhead/deploy/prod && docker compose exec -T db pg_dump -U postgres trailhead | gzip > "\$f"
tok=\$(curl -fsS -H Metadata-Flavor:Google $MD/instance/service-accounts/default/token | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
curl -fsS -X POST -H "Authorization: Bearer \$tok" -H "Content-Type: application/gzip" --data-binary @"\$f" \
  "https://storage.googleapis.com/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=\$(basename "\$f")" > /dev/null
find /var/backups/trailhead -name 'trailhead-*.sql.gz' -mtime +7 -delete
BACKUP
chmod 755 /usr/local/bin/trailhead-backup
echo '20 3 * * * root /usr/local/bin/trailhead-backup >> /var/log/trailhead-backup.log 2>&1' > /etc/cron.d/trailhead-backup
echo "=== trailhead up"
