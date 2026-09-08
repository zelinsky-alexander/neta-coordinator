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
for _ in {1..30}; do
  health="$("${compose[@]}" ps --format json coordinator 2>/dev/null | grep -o '"Health":"[^"]*"' | head -n1 | cut -d'"' -f4 || true)"
  if [[ "$health" == "healthy" ]]; then
    break
  fi
  sleep 2
done

profile="$("${compose[@]}" exec -T coordinator printenv SPRING_PROFILES_ACTIVE 2>/dev/null || true)"
require_cert="$("${compose[@]}" exec -T coordinator printenv NETA_REQUIRE_CLIENT_CERTIFICATE 2>/dev/null || true)"
key_store="$("${compose[@]}" exec -T coordinator printenv NETA_TLS_KEY_STORE 2>/dev/null || true)"
trust_store="$("${compose[@]}" exec -T coordinator printenv NETA_TLS_TRUST_STORE 2>/dev/null || true)"

[[ "$profile" == "mtls" ]] || fail "coordinator started without SPRING_PROFILES_ACTIVE=mtls"
[[ "$require_cert" == "true" ]] || fail "coordinator started without NETA_REQUIRE_CLIENT_CERTIFICATE=true"
[[ -n "$key_store" ]] || fail "coordinator TLS key store is not configured"
[[ -n "$trust_store" ]] || fail "coordinator TLS trust store is not configured"

if ! "${compose[@]}" logs --tail=120 coordinator 2>/dev/null | grep -Eq 'Tomcat started on port 8080 \(https\)|Tomcat initialized with port 8080 \(https\)'; then
  fail "coordinator did not report HTTPS on container port 8080"
fi

info "mTLS deployment verified."
info "Run: ./deploy/health-check.sh"
