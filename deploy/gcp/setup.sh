#!/usr/bin/env bash
# One-shot setup of Trailhead on Google Cloud (free-tier e2-micro) + GitHub, run from your Mac:
#
#   git clone https://github.com/shashirsb/agentreksdb-trailhead && cd agentreksdb-trailhead
#   bash deploy/gcp/setup.sh
#
# Needs: gcloud (brew install --cask google-cloud-sdk), gh (brew install gh), openssl, python3, curl, dig.
# Safe to re-run: state (generated secrets, the GitHub App) is kept in ~/.trailhead-setup (mode 700) and
# every cloud resource is created only if missing.
#
# The two steps it cannot do for you, it opens in your browser: clicking "Create GitHub App" and
# "Install". GoDaddy DNS is the one manual step: it prints the record and waits for it.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-agentreks-trailhead}"
REGION="${REGION:-us-west1}"              # free tier: us-west1, us-central1 or us-east1
ZONE="${ZONE:-${REGION}-b}"
DOMAIN="${DOMAIN:-trailhead.agentreksdb.com}"
APEX="${APEX:-agentreksdb.com}"
SITE="${SITE:-www.$APEX}"
OWNER="${OWNER:-shashirsb}"
TRAILHEAD_REPO="$OWNER/agentreksdb-trailhead"
TARGET_REPO="${TARGET_REPO:-$OWNER/agentreksdb-trailhead-helloworld}"
APP_NAME="${APP_NAME:-agentreks-trailhead}"
VM=trailhead
STATE="$HOME/.trailhead-setup"
HERE="$(cd "$(dirname "$0")" && pwd)"

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { printf '   \033[32m✓\033[0m %s\n' "$*"; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "missing '$1' ($2)"; }
openurl() { if command -v open >/dev/null; then open "$1"; elif command -v xdg-open >/dev/null; then xdg-open "$1"; else echo "   Open: $1"; fi; }
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d$2)" "$1"; }
keep() { # keep NAME COMMAND...  -> generate once, reuse afterwards
  local f="$STATE/$1"; [ -s "$f" ] || { shift; "$@" > "$f"; chmod 600 "$f"; }; cat "$f"; }

need gcloud "brew install --cask google-cloud-sdk"
need gh "brew install gh"
need openssl ""; need python3 ""; need curl ""; need dig ""
mkdir -p "$STATE" && chmod 700 "$STATE"

bold "0. Sign-ins"
gh auth status >/dev/null 2>&1 || gh auth login -s repo,workflow
ok "GitHub CLI signed in as $(gh api user -q .login)"
[ -n "$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null)" ] || gcloud auth login
ok "gcloud signed in as $(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1)"

bold "1. Trailhead repo must be public (servers download it; the charter makes it open source anyway)"
if [ "$(gh repo view "$TRAILHEAD_REPO" --json visibility -q .visibility)" != "PUBLIC" ]; then
  read -r -p "   Make $TRAILHEAD_REPO public now? [y/N] " yn
  [ "$yn" = "y" ] || die "the server cannot download a private repo; re-run when ready"
  gh repo edit "$TRAILHEAD_REPO" --visibility public --accept-visibility-change-consequences
fi
ok "$TRAILHEAD_REPO is public"

# The VM downloads prebuilt images. GitHub keeps a package private if it was first published while the
# repo was private, even after the repo goes public, so check anonymous pull access explicitly.
public_image() {
  local tok
  tok=$(curl -fsS "https://ghcr.io/token?scope=repository:$OWNER/$1:pull" 2>/dev/null |
        python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' 2>/dev/null) || return 1
  [ -n "$tok" ] && curl -fsS -o /dev/null -H "Authorization: Bearer $tok" \
    -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
    "https://ghcr.io/v2/$OWNER/$1/manifests/main"
}
for img in agentreksdb-trailhead agentreksdb-trailhead-sandbox; do
  until public_image "$img"; do
    echo "   The image $img is not public yet. Open this page, scroll to 'Change visibility', choose Public:"
    echo "     https://github.com/users/$OWNER/packages/container/$img/settings"
    openurl "https://github.com/users/$OWNER/packages/container/$img/settings"
    read -r -p "   Press Enter when done... " _
  done
done
ok "server images are public (the VM downloads them; nothing compiles on the VM)"

bold "2. GitHub App ($APP_NAME)"
if [ ! -s "$STATE/app.json" ]; then
  manifest=$(python3 - "$APP_NAME" "$DOMAIN" "$TRAILHEAD_REPO" <<'PY'
import json, sys
name, domain, repo = sys.argv[1:]
print(json.dumps({
  "name": name,
  "url": f"https://github.com/{repo}",
  "description": "Trailhead: the only identity that opens pull requests for AI-generated AgentreksDB code.",
  "hook_attributes": {"url": f"https://{domain}/api/webhooks/github", "active": True},
  "redirect_url": f"https://github.com/{repo}",
  "callback_urls": [f"https://{domain}/auth/github/callback"],
  "public": False,
  "default_permissions": {"contents": "write", "pull_requests": "write", "issues": "write",
                          "actions": "write", "checks": "read", "metadata": "read"},
  "default_events": ["pull_request", "check_run"],
}))
PY
)
  page="$STATE/create-app.html"
  python3 - "$manifest" "$page" <<'PY'
import html, sys
manifest, out = sys.argv[1:]
open(out, "w").write(f"""<!doctype html><meta charset=utf-8><title>Create Trailhead GitHub App</title>
<body style="font-family:system-ui;max-width:640px;margin:40px auto">
<h2>Create the Trailhead GitHub App</h2>
<p>Click the button, then <b>Create GitHub App</b> on GitHub. GitHub will send you to the
agentreksdb-trailhead repo page; copy the <code>code=...</code> value from the address bar into the terminal.</p>
<form action="https://github.com/settings/apps/new" method="post">
<input type="hidden" name="manifest" value="{html.escape(manifest, quote=True)}">
<button style="font-size:18px;padding:10px 20px">Continue to GitHub</button></form></body>""")
PY
  openurl "file://$page"
  read -r -p "   Paste the code from the address bar (after code=): " CODE
  CODE="${CODE##*code=}"; CODE="${CODE%%&*}"
  gh api -X POST "/app-manifests/$CODE/conversions" > "$STATE/app.json"
  chmod 600 "$STATE/app.json"
fi
APP_ID=$(json "$STATE/app.json" '["id"]')
APP_SLUG=$(json "$STATE/app.json" '["slug"]')
CLIENT_ID=$(json "$STATE/app.json" '["client_id"]')
CLIENT_SECRET=$(json "$STATE/app.json" '["client_secret"]')
WEBHOOK_SECRET=$(json "$STATE/app.json" '["webhook_secret"]')
[ -s "$STATE/app.pem" ] || { json "$STATE/app.json" '["pem"]' > "$STATE/app.pem"; chmod 600 "$STATE/app.pem"; }
BOT_LOGIN="${APP_SLUG}[bot]"
ok "App $APP_SLUG (id $APP_ID)"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
app_jwt() {
  local now; now=$(date +%s)
  local h p; h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  p=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' $((now-60)) $((now+540)) "$APP_ID" | b64url)
  printf '%s.%s.%s' "$h" "$p" "$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$STATE/app.pem" -binary | b64url)"
}
find_installation() {
  curl -fsS -H "Authorization: Bearer $(app_jwt)" -H "Accept: application/vnd.github+json" https://api.github.com/app/installations |
    python3 -c "import json,sys; print(next((str(i['id']) for i in json.load(sys.stdin) if i['account']['login'].lower()=='$OWNER'.lower()), ''))"
}
INSTALLATION_ID=$(find_installation)
if [ -z "$INSTALLATION_ID" ]; then
  echo "   Install the App on: $(basename "$TRAILHEAD_REPO") and $(basename "$TARGET_REPO") (Only select repositories)."
  openurl "https://github.com/apps/$APP_SLUG/installations/new"
  for _ in $(seq 1 120); do INSTALLATION_ID=$(find_installation); [ -n "$INSTALLATION_ID" ] && break; sleep 5; done
  [ -n "$INSTALLATION_ID" ] || die "App not installed yet; install it and re-run"
fi
ok "installed (installation $INSTALLATION_ID)"

bold "3. Secrets"
if [ ! -s "$STATE/anthropic" ]; then
  read -r -s -p "   Anthropic API key (input hidden; console.anthropic.com → API keys): " AK; echo
  [ -n "$AK" ] || die "an Anthropic key is required for code generation"
  printf '%s' "$AK" > "$STATE/anthropic"; chmod 600 "$STATE/anthropic"; unset AK
fi
PG_PASS=$(keep postgres openssl rand -hex 24)
TICK_TOKEN=$(keep tick openssl rand -hex 32)
PROXY_TOKEN=$(keep proxy openssl rand -hex 32)
LEDGER_KEY=$(keep ledger openssl rand -hex 32)      # ed25519 seed; the public key is pinned in step 9
GOV_ID=$(gh api "users/$OWNER" -q .id)
ok "generated (kept in $STATE)"

bold "4. GitHub repo settings"
gh secret set TRAILHEAD_APP_PRIVATE_KEY -R "$TRAILHEAD_REPO" < "$STATE/app.pem"
for kv in "TRAILHEAD_APP_ID=$APP_ID" "TRAILHEAD_URL=https://$DOMAIN" "TRAILHEAD_TARGET_REPO=$TARGET_REPO" \
          "TRAILHEAD_TARGET_REPO_NAME=$(basename "$TARGET_REPO")" "TRAILHEAD_BOT_LOGIN=$BOT_LOGIN"; do
  gh variable set "${kv%%=*}" -R "$TRAILHEAD_REPO" --body "${kv#*=}"
done
ws="agentreksdb"; [[ "$TARGET_REPO" == *helloworld ]] && ws="."
for kv in "WORKSPACE_DIR=$ws" "TRAILHEAD_URL=https://$DOMAIN" "TRAILHEAD_BOT_LOGIN=$BOT_LOGIN"; do
  gh variable set "${kv%%=*}" -R "$TARGET_REPO" --body "${kv#*=}"
done
printf '%s' "$TICK_TOKEN" | gh secret set TRAILHEAD_TICK_TOKEN -R "$TARGET_REPO"
ok "secrets and variables set on both repos"

bold "5. Google Cloud project $PROJECT_ID"
gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1 || gcloud projects create "$PROJECT_ID" --name="Agentreks Trailhead"
gcloud config set project "$PROJECT_ID" >/dev/null
if [ "$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingEnabled)')" != "True" ]; then
  BAS=$(gcloud billing accounts list --filter=open=true --format='value(name)')   # (macOS bash 3: no mapfile)
  [ -n "$BAS" ] || die "no open billing account: create one at console.cloud.google.com/billing"
  BA=$(printf '%s\n' "$BAS" | head -1)
  if [ "$(printf '%s\n' "$BAS" | wc -l | tr -d ' ')" -gt 1 ]; then
    gcloud billing accounts list --filter=open=true
    read -r -p "   Billing account to use [${BA}]: " pick; BA="${pick:-$BA}"
  fi
  gcloud billing projects link "$PROJECT_ID" --billing-account="$BA" >/dev/null
fi
BA=$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingAccountName)' | sed 's#billingAccounts/##')
gcloud services enable compute.googleapis.com secretmanager.googleapis.com billingbudgets.googleapis.com storage.googleapis.com >/dev/null
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
# The budget must be in the billing account's own currency (an INR account rejects "10USD").
CURRENCY=$(gcloud billing accounts describe "$BA" --format='value(currencyCode)' 2>/dev/null || echo USD)
case "$CURRENCY" in
  USD) BUDGET="10USD" ;;
  INR) BUDGET="1000INR" ;;
  EUR) BUDGET="10EUR" ;;
  GBP) BUDGET="10GBP" ;;
  *)   BUDGET="" ;;
esac
if gcloud billing budgets list --billing-account="$BA" --format='value(displayName)' 2>/dev/null | grep -qx "Trailhead"; then
  ok "project and billing (budget alert already exists)"
elif [ -n "$BUDGET" ] && gcloud billing budgets create --billing-account="$BA" --display-name="Trailhead" --budget-amount="$BUDGET" \
    --filter-projects="projects/$PROJECT_NUMBER" \
    --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0 >/dev/null; then
  ok "project, billing and a $BUDGET/month budget alert"
else
  # A missing alert must not block the deployment; tell the user how to add it by hand.
  printf '   \033[33m!\033[0m could not create the budget alert automatically (billing currency: %s).\n' "$CURRENCY"
  echo "     Add one in the console: Billing → Budgets & alerts → Create budget, about \$10/month, alerts at 50/90/100%."
fi

gcloud compute addresses describe trailhead-ip --region="$REGION" >/dev/null 2>&1 ||
  gcloud compute addresses create trailhead-ip --region="$REGION" >/dev/null
IP=$(gcloud compute addresses describe trailhead-ip --region="$REGION" --format='value(address)')
gcloud compute firewall-rules describe trailhead-web >/dev/null 2>&1 ||
  gcloud compute firewall-rules create trailhead-web --allow=tcp:80,tcp:443 --target-tags=trailhead >/dev/null
ok "static IP $IP, firewall 80/443"

SA="trailhead-vm@$PROJECT_ID.iam.gserviceaccount.com"
gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 ||
  gcloud iam service-accounts create trailhead-vm --display-name="Trailhead VM" >/dev/null
BUCKET="$PROJECT_ID-backups"
gcloud storage buckets describe "gs://$BUCKET" >/dev/null 2>&1 ||
  gcloud storage buckets create "gs://$BUCKET" --location="$REGION" --uniform-bucket-level-access >/dev/null
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member="serviceAccount:$SA" --role=roles/storage.objectCreator >/dev/null

ENV_FILE="$STATE/server.env"
umask 077
cat > "$ENV_FILE" <<ENV
TRAILHEAD_DOMAIN=$DOMAIN
SITE_DOMAIN=$SITE
APEX_DOMAIN=$APEX
POSTGRES_PASSWORD=$PG_PASS
TRAILHEAD_GOVERNORS=$OWNER
TRAILHEAD_GOVERNOR_IDS=$GOV_ID
TRAILHEAD_TARGET_REPO=$TARGET_REPO
TRAILHEAD_REPO=$TRAILHEAD_REPO
TRAILHEAD_BOT_LOGIN=$BOT_LOGIN
GITHUB_APP_ID=$APP_ID
GITHUB_INSTALLATION_ID=$INSTALLATION_ID
GITHUB_CLIENT_ID=$CLIENT_ID
GITHUB_CLIENT_SECRET=$CLIENT_SECRET
GITHUB_WEBHOOK_SECRET=$WEBHOOK_SECRET
TRAILHEAD_TICK_TOKEN=$TICK_TOKEN
TRAILHEAD_LEDGER_KEY=$LEDGER_KEY
ANTHROPIC_API_KEY=$(cat "$STATE/anthropic")
TRAILHEAD_PROXY_TOKEN=$PROXY_TOKEN
TRAILHEAD_SANDBOX=command
TRAILHEAD_SANDBOX_COMMAND=/app/deploy/sandbox/launch.sh
TRAILHEAD_DAILY_BUDGET_CREDITS=2000
ENV
umask 022
put_secret() { # name file
  if gcloud secrets describe "$1" >/dev/null 2>&1; then
    gcloud secrets versions add "$1" --data-file="$2" >/dev/null
  else
    gcloud secrets create "$1" --replication-policy=automatic --data-file="$2" >/dev/null
  fi
  gcloud secrets add-iam-policy-binding "$1" --member="serviceAccount:$SA" --role=roles/secretmanager.secretAccessor >/dev/null
}
put_secret trailhead-env "$ENV_FILE"
put_secret trailhead-app-pem "$STATE/app.pem"
ok "secrets stored in Secret Manager (readable only by the VM's service account)"

META="trailhead-repo=$TRAILHEAD_REPO,backup-bucket=$BUCKET"
if gcloud compute instances describe "$VM" --zone="$ZONE" >/dev/null 2>&1; then
  gcloud compute instances add-metadata "$VM" --zone="$ZONE" --metadata="$META" \
    --metadata-from-file=startup-script="$HERE/startup.sh" >/dev/null
  gcloud compute instances reset "$VM" --zone="$ZONE" >/dev/null
  ok "VM updated and restarted"
else
  gcloud compute instances create "$VM" --zone="$ZONE" --machine-type=e2-micro \
    --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
    --boot-disk-size=30GB --boot-disk-type=pd-standard \
    --address="$IP" --tags=trailhead \
    --service-account="$SA" --scopes=cloud-platform \
    --metadata="$META" --metadata-from-file=startup-script="$HERE/startup.sh" >/dev/null
  ok "VM $VM (e2-micro, free tier) created"
fi

bold "6. DNS (GoDaddy, the one manual step)"
resolves() { [ "$(dig +short "$1" | tail -1)" = "$IP" ]; }
if ! { resolves "$DOMAIN" && resolves "$APEX" && resolves "$SITE"; }; then
  cat <<TXT
   GoDaddy → My Products → $APEX → DNS. Make these three records (edit if they exist; delete any other
   A record on "@" such as GoDaddy's parking address, and any "Forwarding" on the domain):
       Type A      Name @          Value $IP    TTL 600 seconds
       Type CNAME  Name www        Value @           TTL 600 seconds
       Type A      Name ${DOMAIN%%.$APEX}    Value $IP    TTL 600 seconds
   Waiting for all three to resolve...
TXT
  for _ in $(seq 1 120); do resolves "$DOMAIN" && resolves "$APEX" && resolves "$SITE" && break; sleep 30; done
  resolves "$DOMAIN" && resolves "$APEX" && resolves "$SITE" || die "DNS not resolving yet; re-run this script once it does"
fi
ok "$APEX, $SITE and $DOMAIN → $IP"

bold "7. Waiting for https://$DOMAIN (first boot installs Docker and pulls images: 5-15 minutes)"
for _ in $(seq 1 90); do curl -fsS "https://$DOMAIN/healthz" >/dev/null 2>&1 && break; sleep 20; done
curl -fsS "https://$DOMAIN/healthz" >/dev/null 2>&1 ||
  die "not up yet. Check: gcloud compute ssh $VM --zone $ZONE -- sudo tail -50 /var/log/trailhead-startup.log"
ok "Trailhead is live at https://$DOMAIN"
curl -fsS -o /dev/null "https://$SITE/" && ok "website is live at https://$SITE" || echo "   (website certificate may take another minute)"

bold "8. Pin the ledger public key (the signing workflow refuses commits without it)"
PUBKEY=$(curl -fsS "https://$DOMAIN/api/ledger/checkpoint" | python3 -c 'import json,sys;print(json.load(sys.stdin)["public_key"])')
gh variable set TRAILHEAD_LEDGER_PUBKEY -R "$TRAILHEAD_REPO" --body "$PUBKEY"
echo "$PUBKEY" > "$STATE/ledger.pub"
ok "ledger public key $PUBKEY"

bold "9. Lock the test repo's main branch with the Trailhead ruleset"
if ! gh api "repos/$TARGET_REPO/rulesets" -q '.[].name' 2>/dev/null | grep -q .; then
  read -r -p "   Apply gates/rulesets/main.json to $TARGET_REPO now (no human pushes to main after this)? [y/N] " yn
  if [ "$yn" = "y" ]; then
    # Merge queues exist only for organization-owned repos; on a personal account drop that rule
    # (Trailhead then merges directly, and every required check still applies).
    rs="$STATE/ruleset.json"
    python3 - "$HERE/../../gates/rulesets/main.json" "$rs" "$(gh api "users/$OWNER" -q .type)" <<'PY'
import json, sys
src, out, owner_type = sys.argv[1:]
r = json.load(open(src))
if owner_type != "Organization":
    r["rules"] = [x for x in r["rules"] if x["type"] != "merge_queue"]
json.dump(r, open(out, "w"), indent=2)
PY
    if gh api -X POST "repos/$TARGET_REPO/rulesets" --input "$rs" >/dev/null 2>"$STATE/ruleset.err"; then
      ok "ruleset applied"
    else
      printf '   \033[33m!\033[0m ruleset not applied: %s\n' "$(cat "$STATE/ruleset.err")"
    fi
  fi
else
  ok "a ruleset already exists"
fi

cat <<DONE

All set.
  Website:     https://$SITE
  Trailhead:   https://$DOMAIN   (sign in with GitHub as $OWNER: you are the interim governor)
  Server logs: gcloud compute ssh $VM --zone $ZONE -- 'cd /opt/trailhead/deploy/prod && sudo docker compose logs -f trailhead'
  Backups:     gs://$BUCKET (nightly)
  Re-run this script any time; it only changes what is missing or different.
DONE
