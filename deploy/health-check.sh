#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

ok=0
warn=0
fail=0

pass() { printf '[OK]   %s\n' "$*"; ok=$((ok+1)); }
warning() { printf '[WARN] %s\n' "$*"; warn=$((warn+1)); }
failed() { printf '[FAIL] %s\n' "$*"; fail=$((fail+1)); }

printf 'NETA Coordinator health check\n'
printf '=============================\n'

if ! command -v docker >/dev/null 2>&1; then
  failed "docker is not installed"
  printf '\nNETA COORDINATOR HEALTH: FAIL\n'
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  failed "Docker Compose v2+ is not available"
  printf '\nNETA COORDINATOR HEALTH: FAIL\n'
  exit 1
fi
if [[ ! -f .env ]]; then
  failed ".env is missing"
  printf '\nNETA COORDINATOR HEALTH: FAIL\n'
  exit 1
fi

compose=(docker compose --env-file .env -f docker-compose.yml -f docker-compose.mtls.yml)

postgres_state="$("${compose[@]}" ps --format json postgres 2>/dev/null || true)"
coordinator_state="$("${compose[@]}" ps --format json coordinator 2>/dev/null || true)"

if grep -q '"State":"running"' <<<"$postgres_state" && grep -q '"Health":"healthy"' <<<"$postgres_state"; then
  pass "postgres container: running and healthy"
else
  failed "postgres container is not healthy"
fi

if grep -q '"State":"running"' <<<"$coordinator_state" && grep -q '"Health":"healthy"' <<<"$coordinator_state"; then
  pass "coordinator container: running and healthy"
else
  failed "coordinator container is not healthy"
fi

profile="$("${compose[@]}" exec -T coordinator printenv SPRING_PROFILES_ACTIVE 2>/dev/null || true)"
require_cert="$("${compose[@]}" exec -T coordinator printenv NETA_REQUIRE_CLIENT_CERTIFICATE 2>/dev/null || true)"
key_store="$("${compose[@]}" exec -T coordinator printenv NETA_TLS_KEY_STORE 2>/dev/null || true)"
trust_store="$("${compose[@]}" exec -T coordinator printenv NETA_TLS_TRUST_STORE 2>/dev/null || true)"

[[ "$profile" == "mtls" ]] && pass "Spring profile: mtls" || failed "Spring profile is '${profile:-<unset>}' instead of mtls"
[[ "$require_cert" == "true" ]] && pass "client certificate requirement enabled" || failed "NETA_REQUIRE_CLIENT_CERTIFICATE is not true"
[[ -n "$key_store" ]] && pass "TLS key store configured" || failed "TLS key store is not configured"
[[ -n "$trust_store" ]] && pass "TLS trust store configured" || failed "TLS trust store is not configured"

host_port="$(grep -E '^[[:space:]]*NETA_HOST_PORT=' .env | tail -n1 | cut -d= -f2- | tr -d '\r"' || true)"
host_port="${host_port:-8080}"
ca="deploy/certs/fleet-ca.crt"

if [[ -r "$ca" ]]; then
  if curl -fsS --connect-timeout 2 --max-time 5 --cacert "$ca" "https://127.0.0.1:${host_port}/actuator/health" | grep -q '"status":"UP"'; then
    pass "HTTPS actuator health: UP on 127.0.0.1:${host_port}"
  else
    failed "HTTPS actuator health failed on 127.0.0.1:${host_port}"
  fi
else
  failed "fleet CA certificate missing: $ca"
fi

if ./neta endpoints >/tmp/neta-coordinator-endpoints.$$ 2>/tmp/neta-coordinator-endpoints-err.$$; then
  pass "operator API: endpoints query succeeded"
  if grep -Eq '[[:space:]]ONLINE[[:space:]]|[[:space:]]STALE[[:space:]]' /tmp/neta-coordinator-endpoints.$$; then
    pass "fleet liveness: at least one endpoint is ONLINE or STALE"
  elif grep -Eq '[[:space:]]OFFLINE[[:space:]]' /tmp/neta-coordinator-endpoints.$$; then
    warning "fleet liveness: all reported endpoints appear OFFLINE"
  else
    warning "fleet liveness: no active endpoint state found"
  fi
else
  failed "operator API: endpoints query failed: $(cat /tmp/neta-coordinator-endpoints-err.$$ 2>/dev/null || true)"
fi
rm -f /tmp/neta-coordinator-endpoints.$$ /tmp/neta-coordinator-endpoints-err.$$

if ./neta findings 1 >/dev/null 2>&1; then
  pass "operator API: findings query succeeded"
else
  failed "operator API: findings query failed"
fi

if ./neta storage >/tmp/neta-coordinator-storage.$$ 2>/tmp/neta-coordinator-storage-err.$$; then
  pass "operator API: storage/retention query succeeded"
  if grep -q '^Protocol retention:' /tmp/neta-coordinator-storage.$$ && grep -q '^Audit/contact retention:' /tmp/neta-coordinator-storage.$$; then
    pass "storage retention configuration is visible"
  else
    warning "storage query succeeded but retention fields were not found"
  fi
else
  failed "operator API: storage query failed: $(cat /tmp/neta-coordinator-storage-err.$$ 2>/dev/null || true)"
fi
rm -f /tmp/neta-coordinator-storage.$$ /tmp/neta-coordinator-storage-err.$$

if "${compose[@]}" logs --since=30m coordinator 2>/dev/null | grep -q 'Invalid character found in method name'; then
  warning "recent logs contain TLS-to-HTTP parsing errors; verify no plain-HTTP deployment was active"
fi

printf '\nSummary: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
if (( fail > 0 )); then
  printf 'NETA COORDINATOR HEALTH: FAIL\n'
  exit 1
elif (( warn > 0 )); then
  printf 'NETA COORDINATOR HEALTH: OK WITH WARNINGS\n'
  exit 0
else
  printf 'NETA COORDINATOR HEALTH: OK\n'
fi
