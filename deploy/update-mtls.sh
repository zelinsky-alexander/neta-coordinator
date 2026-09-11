#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

command -v docker >/dev/null 2>&1 || fail "Docker is required."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2+ is required."
[[ -f .env ]] || fail ".env is missing."
[[ -f docker-compose.yml ]] || fail "docker-compose.yml is missing."
[[ -f docker-compose.mtls.yml ]] || fail "docker-compose.mtls.yml is missing."

for f in deploy/certs/coordinator.p12 deploy/certs/fleet-trust.p12 deploy/certs/agent-issuer.p12 deploy/certs/fleet-ca.crt; do
  [[ -r "$f" ]] || fail "required mTLS file is missing or unreadable: $f"
done

compose=(docker compose --env-file .env -f docker-compose.yml -f docker-compose.mtls.yml)

dump_coordinator_diagnostics() {
  printf '%s\n' '--- coordinator compose status ---' >&2
  "${compose[@]}" ps -a coordinator >&2 || true
  local cid
  cid="$("${compose[@]}" ps -aq coordinator 2>/dev/null | head -n1 || true)"
  if [[ -n "$cid" ]]; then
    printf '%s\n' '--- coordinator inspected environment ---' >&2
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null \
      | grep -E '^(SPRING_PROFILES_ACTIVE|NETA_REQUIRE_CLIENT_CERTIFICATE|NETA_TLS_KEY_STORE|NETA_TLS_TRUST_STORE)=' >&2 || true
  fi
  printf '%s\n' '--- coordinator recent logs ---' >&2
  "${compose[@]}" logs --tail=160 coordinator >&2 || true
}

# Fail before touching the running service if the effective Compose model does not
# contain the mTLS override. This also catches accidental edits or invocation from
# a checkout where the override is not being applied.
resolved_config="$("${compose[@]}" config)"
printf '%s\n' "$resolved_config" | grep -Eq "SPRING_PROFILES_ACTIVE:[[:space:]]+['\"]?mtls['\"]?$" \
  || fail "effective Compose configuration does not set SPRING_PROFILES_ACTIVE=mtls"
printf '%s\n' "$resolved_config" | grep -Eq "NETA_REQUIRE_CLIENT_CERTIFICATE:[[:space:]]+['\"]?true['\"]?$" \
  || fail "effective Compose configuration does not set NETA_REQUIRE_CLIENT_CERTIFICATE=true"
printf '%s\n' "$resolved_config" | grep -q 'NETA_TLS_KEY_STORE:' \
  || fail "effective Compose configuration does not contain NETA_TLS_KEY_STORE"
printf '%s\n' "$resolved_config" | grep -q 'NETA_TLS_TRUST_STORE:' \
  || fail "effective Compose configuration does not contain NETA_TLS_TRUST_STORE"

info "Updating NETA Coordinator in mTLS mode..."
# A coordinator may have previously been created from docker-compose.yml alone.
# Force recreation so an existing base-mode container cannot simply be restarted
# with stale environment/volume/healthcheck configuration. Keep PostgreSQL intact.
"${compose[@]}" up -d --build --force-recreate --no-deps coordinator

info "Waiting for coordinator container health..."
health=""
for _ in {1..30}; do
  health="$("${compose[@]}" ps --format json coordinator 2>/dev/null | grep -o '"Health":"[^"]*"' | head -n1 | cut -d'"' -f4 || true)"
  [[ "$health" == "healthy" ]] && break

  cid="$("${compose[@]}" ps -aq coordinator 2>/dev/null | head -n1 || true)"
  if [[ -n "$cid" ]]; then
    running="$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null || true)"
    restarting="$(docker inspect -f '{{.State.Restarting}}' "$cid" 2>/dev/null || true)"
    if [[ "$running" != "true" || "$restarting" == "true" ]]; then
      dump_coordinator_diagnostics
      fail "coordinator exited or is restart-looping before becoming healthy"
    fi
  fi
  sleep 2
done

if [[ "$health" != "healthy" ]]; then
  dump_coordinator_diagnostics
  fail "coordinator did not become healthy in time"
fi

cid="$("${compose[@]}" ps -q coordinator)"
[[ -n "$cid" ]] || fail "coordinator container id is unavailable after health check"

# Inspect the created container configuration rather than relying on `exec`.
# This distinguishes a missing environment override from a process that exited.
profile="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | sed -n 's/^SPRING_PROFILES_ACTIVE=//p' | head -n1)"
require_cert="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | sed -n 's/^NETA_REQUIRE_CLIENT_CERTIFICATE=//p' | head -n1)"
key_store="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | sed -n 's/^NETA_TLS_KEY_STORE=//p' | head -n1)"
trust_store="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | sed -n 's/^NETA_TLS_TRUST_STORE=//p' | head -n1)"

[[ "$profile" == "mtls" ]] || { dump_coordinator_diagnostics; fail "coordinator container configuration lacks SPRING_PROFILES_ACTIVE=mtls"; }
[[ "$require_cert" == "true" ]] || { dump_coordinator_diagnostics; fail "coordinator container configuration lacks NETA_REQUIRE_CLIENT_CERTIFICATE=true"; }
[[ -n "$key_store" ]] || { dump_coordinator_diagnostics; fail "coordinator TLS key store is not configured"; }
[[ -n "$trust_store" ]] || { dump_coordinator_diagnostics; fail "coordinator TLS trust store is not configured"; }

# Capture logs first instead of piping `docker compose logs` directly into
# `grep -q` under `set -o pipefail`. On a successful early match, grep exits and
# Docker can receive SIGPIPE, making the overall pipeline look like a failure.
recent_logs="$("${compose[@]}" logs --tail=120 coordinator 2>/dev/null || true)"
if ! grep -Eq 'Tomcat started on port 8080 \(https\)|Tomcat initialized with port 8080 \(https\)' <<<"$recent_logs"; then
  dump_coordinator_diagnostics
  fail "coordinator did not report HTTPS on container port 8080"
fi

info "mTLS deployment verified."
info "Run: ./deploy/health-check.sh"
