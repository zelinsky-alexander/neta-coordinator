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
STATE_DIR=/var/lib/neta/identity
INSTALLER=/tmp/install-agent-package.sh
mkdir -p "$SRC"
[[ -r "$CA_FILE" ]] || { echo "missing $CA_FILE" >&2; exit 1; }
[[ -x "$INSTALLER" ]] || { echo "missing executable package installer: $INSTALLER" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git ca-certificates curl python3 file

checkout_ref() {
  local repository="$1" ref="$2" destination="$3"
  rm -rf "$destination"
  git init -q "$destination"
  git -C "$destination" remote add origin "https://github.com/${repository}.git"
  if ! git -C "$destination" fetch --depth=1 origin "$ref"; then
    echo "ERROR: cannot resolve selected ref '$ref' in $repository" >&2
    exit 3
  fi
  git -C "$destination" checkout -q --detach FETCH_HEAD
}

# Resolve the selected agent ref exactly, but do not build it on this machine.
checkout_ref "$AGENT_REPOSITORY" "$AGENT_REF" "$SRC/agent-ref"
AGENT_COMMIT="$(git -C "$SRC/agent-ref" rev-parse HEAD)"
SHORT_COMMIT="${AGENT_COMMIT:0:12}"
case "$(uname -m)" in
  x86_64|amd64) AGENT_ARCH=amd64 ;;
  aarch64|arm64) AGENT_ARCH=arm64 ;;
  *) echo "ERROR: unsupported agent host architecture: $(uname -m)" >&2; exit 1 ;;
esac

RELEASE_TAG="dev-${AGENT_COMMIT}"
PACKAGE_NAME="neta-agent-linux-${AGENT_ARCH}-${SHORT_COMMIT}.tar.gz"
RELEASE_BASE="https://github.com/${AGENT_REPOSITORY}/releases/download/${RELEASE_TAG}"
PACKAGE="$ROOT/$PACKAGE_NAME"
MANIFEST="$ROOT/release-manifest.json"

echo "==> Installing immutable prebuilt agent package"
echo "    repository: $AGENT_REPOSITORY"
echo "    selected ref: $AGENT_REF"
echo "    resolved commit: $AGENT_COMMIT"
echo "    release tag: $RELEASE_TAG"
echo "    architecture: $AGENT_ARCH"

if ! curl -fL --retry 3 --connect-timeout 10 -o "$MANIFEST" "$RELEASE_BASE/release-manifest.json"; then
  echo "ERROR: no published Linux package exists for selected agent commit $AGENT_COMMIT" >&2
  echo "Run 'Build Supported Agent Flavors' for $AGENT_REPOSITORY ref '$AGENT_REF' with publish_development=true, then retry acceptance." >&2
  exit 4
fi
if ! curl -fL --retry 3 --connect-timeout 10 -o "$PACKAGE" "$RELEASE_BASE/$PACKAGE_NAME"; then
  echo "ERROR: release $RELEASE_TAG does not contain $PACKAGE_NAME" >&2
  exit 4
fi

python3 - "$MANIFEST" "$PACKAGE" "$AGENT_COMMIT" "$AGENT_ARCH" <<'PY'
import hashlib, json, pathlib, sys
manifest_path, package_path, commit, arch = sys.argv[1:]
manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding='utf-8'))
if str(manifest.get('git_commit','')).lower() != commit.lower():
    raise SystemExit(f"manifest commit mismatch: {manifest.get('git_commit')} != {commit}")
name = pathlib.Path(package_path).name
match = None
for item in manifest.get('artifacts', []):
    if item.get('os') == 'linux' and item.get('arch') == arch and item.get('name') == name:
        match = item
        break
if not match:
    raise SystemExit(f"manifest has no linux/{arch} artifact named {name}")
actual = hashlib.sha256(pathlib.Path(package_path).read_bytes()).hexdigest()
expected = str(match.get('sha256','')).lower()
if not expected or actual != expected:
    raise SystemExit(f"package sha256 mismatch: actual={actual} expected={expected}")
print(f"verified package sha256={actual}")
PY

"$INSTALLER" "$PACKAGE"
checkout_ref "$LAB_REPOSITORY" "$LAB_REF" "$SRC/lab"

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"
/usr/local/bin/neta-agent fleet enroll \
  --coordinator "https://${COORDINATOR_PRIVATE_IP}:8443" \
  --fleet-id fleet-acceptance \
  --fleet-ca "$CA_FILE" \
  --token "$NETA_ENROLLMENT_TOKEN" \
  --display-name neta-acceptance-linux \
  --state-dir "$STATE_DIR"
unset NETA_ENROLLMENT_TOKEN
chmod 0700 "$STATE_DIR"
chmod 0600 "$STATE_DIR/agent.key" "$STATE_DIR/identity.conf" "$STATE_DIR/sequence"
chmod 0644 "$STATE_DIR/agent.crt" "$STATE_DIR/fleet-ca.crt"
/usr/local/bin/neta-agent fleet status --state-dir "$STATE_DIR"
/usr/local/bin/neta-agent fleet hello --state-dir "$STATE_DIR"
/usr/local/bin/neta-agent fleet heartbeat --state-dir "$STATE_DIR"
systemctl restart neta-agent.service
/usr/local/bin/neta-agent fleet rules-update --state-dir "$STATE_DIR"

systemctl is-active --quiet neta-agent.service
/usr/local/bin/neta-agent capabilities
/usr/local/bin/neta-agent fleet status --state-dir "$STATE_DIR"

cat >"$ROOT/revisions.txt" <<EOF
agent_repository=$AGENT_REPOSITORY
agent_ref=$AGENT_REF
agent_commit=$AGENT_COMMIT
agent_release_tag=$RELEASE_TAG
agent_package=$PACKAGE_NAME
lab_repository=$LAB_REPOSITORY
lab_ref=$LAB_REF
lab_commit=$(git -C "$SRC/lab" rev-parse HEAD)
EOF

echo "NETA Linux agent prebuilt-package install and enrollment complete"
