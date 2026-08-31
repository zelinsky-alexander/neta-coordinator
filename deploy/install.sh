#!/usr/bin/env sh
set -eu

fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "Docker is required. Install Docker Engine first."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2+ is required."
[ -f .env ] || fail ".env is missing. Copy .env.example to .env and configure it first."

arch=$(uname -m)
case "$arch" in
  x86_64|amd64|aarch64|arm64) ;;
  *) fail "Unsupported architecture: $arch (expected x86_64/amd64 or aarch64/arm64)" ;;
esac

avail_kb=$(df -Pk . | awk 'NR==2 {print $4}')
[ "$avail_kb" -ge 2097152 ] || fail "At least 2 GiB free disk space is required."

printf '%s\n' "Building and starting NETA Coordinator..."
docker compose --env-file .env up -d --build
printf '%s\n' "Deployment started. Run ./deploy/status.sh to verify health."
