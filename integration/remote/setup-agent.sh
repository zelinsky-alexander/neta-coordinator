#!/usr/bin/env bash
set -euo pipefail

: "${AGENT_REPOSITORY:?required}"
: "${AGENT_REF:?required}"
: "${LAB_REPOSITORY:?required}"
: "${LAB_REF:?required}"
: "${COORDINATOR_PRIVATE_IP:?required}"
: "${NETA_ENROLLMENT_TOKEN:?required}"

ROOT=/opt/neta-acceptance
SRC="$ROOT/src"
CA_FILE="$ROOT/fleet-ca.crt"
mkdir -p "$SRC"
[[ -r "$CA_FILE" ]] || { echo "missing $CA_FILE" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git ca-certificates curl python3

checkout_ref() {
  local repository="$1" ref="$2" destination="$3"
  rm -rf "$destination"
  git init -q "$destination"
  git -C "$destination" remote add origin "https://github.com/${repository}.git"
  git -C "$destination" fetch --depth=1 origin "$ref"
  git -C "$destination" checkout -q --detach FETCH_HEAD
}

checkout_ref "$AGENT_REPOSITORY" "$AGENT_REF" "$SRC/agent"
checkout_ref "$LAB_REPOSITORY" "$LAB_REF" "$SRC/lab"

cd "$SRC/agent"
NETA_SKIP_GIT_UPDATE=1 ./deploy/linux/install-or-update.sh

NETA_ENROLLMENT_TOKEN="$NETA_ENROLLMENT_TOKEN" \
  ./deploy/linux/enroll.sh \
  "https://${COORDINATOR_PRIVATE_IP}:8443" \
  "$CA_FILE" \
  neta-acceptance-linux \
  fleet-acceptance

/usr/local/bin/neta-agent fleet rules-update --state-dir /var/lib/neta/identity
./deploy/linux/health-check.sh

cat >"$ROOT/revisions.txt" <<EOF
agent_repository=$AGENT_REPOSITORY
agent_ref=$AGENT_REF
agent_commit=$(git -C "$SRC/agent" rev-parse HEAD)
lab_repository=$LAB_REPOSITORY
lab_ref=$LAB_REF
lab_commit=$(git -C "$SRC/lab" rev-parse HEAD)
EOF

unset NETA_ENROLLMENT_TOKEN
echo "NETA Linux agent fresh setup and enrollment complete"
