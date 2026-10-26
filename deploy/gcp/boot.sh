#!/bin/bash
# Tiny boot hook stored in the VM's startup-script metadata. It fetches the repo and runs the CURRENT
# deploy/gcp/startup.sh from it, so changes to the boot steps ship with a push, not a metadata update.
set -euo pipefail
REPO=$(curl -fsS -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/attributes/trailhead-repo)
if [ -d /opt/trailhead/.git ]; then git -C /opt/trailhead pull -q --ff-only || true; else git clone -q "https://github.com/$REPO.git" /opt/trailhead; fi
exec bash /opt/trailhead/deploy/gcp/startup.sh
