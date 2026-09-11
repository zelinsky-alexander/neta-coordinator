#!/usr/bin/env bash
set -euo pipefail

: "${COORDINATOR_REPOSITORY:?required}"
: "${COORDINATOR_REF:?required}"
: "${PORTAL_REPOSITORY:?required}"
: "${PORTAL_REF:?required}"
: "${COORDINATOR_PRIVATE_IP:?required}"

ROOT=/opt/neta-acceptance
SRC="$ROOT/src"
PKI="$ROOT/pki"
RUNTIME="$ROOT/runtime.env"
mkdir -p "$SRC" "$PKI"
chmod 0700 "$ROOT" "$PKI"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git curl openssl ca-certificates docker.io docker-compose-v2
systemctl enable --now docker

checkout_ref() {
  local repository="$1" ref="$2" destination="$3"
  rm -rf "$destination"
  git init -q "$destination"
  git -C "$destination" remote add origin "https://github.com/${repository}.git"
  git -C "$destination" fetch --depth=1 origin "$ref"
  git -C "$destination" checkout -q --detach FETCH_HEAD
}

checkout_ref "$COORDINATOR_REPOSITORY" "$COORDINATOR_REF" "$SRC/coordinator"
checkout_ref "$PORTAL_REPOSITORY" "$PORTAL_REF" "$SRC/portal"

DB_PASSWORD="$(openssl rand -hex 24)"
ENROLLMENT_TOKEN="$(openssl rand -hex 24)"
ADMIN_TOKEN="$(openssl rand -hex 24)"
PORTAL_SERVICE_TOKEN="$(openssl rand -hex 24)"
STORE_PASSWORD="$(openssl rand -hex 24)"
PORTAL_SESSION_SECRET="$(openssl rand -hex 32)"

cat >"$RUNTIME" <<EOF
ENROLLMENT_TOKEN=$ENROLLMENT_TOKEN
ADMIN_TOKEN=$ADMIN_TOKEN
PORTAL_SERVICE_TOKEN=$PORTAL_SERVICE_TOKEN
STORE_PASSWORD=$STORE_PASSWORD
EOF
chmod 0600 "$RUNTIME"

cd "$PKI"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 -subj '/CN=NETA Full Cycle Fleet CA' -keyout fleet-ca.key -out fleet-ca.crt >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes -sha256 -subj '/CN=neta-coordinator-acceptance' -keyout coordinator.key -out coordinator.csr >/dev/null 2>&1
cat >coordinator.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${COORDINATOR_PRIVATE_IP},DNS:neta-coordinator
EOF
openssl x509 -req -in coordinator.csr -CA fleet-ca.crt -CAkey fleet-ca.key -CAcreateserial -days 2 -sha256 -extfile coordinator.ext -out coordinator.crt >/dev/null 2>&1

openssl req -new -newkey rsa:3072 -nodes -sha256 -subj '/CN=NETA Acceptance Agent Issuer' -keyout agent-issuer.key -out agent-issuer.csr >/dev/null 2>&1
cat >agent-issuer.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in agent-issuer.csr -CA fleet-ca.crt -CAkey fleet-ca.key -CAcreateserial -days 2 -sha256 -extfile agent-issuer.ext -out agent-issuer.crt >/dev/null 2>&1

openssl req -new -newkey rsa:3072 -nodes -sha256 -subj '/CN=neta-portal-acceptance' -keyout portal-client.key -out portal-client.csr >/dev/null 2>&1
cat >portal-client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in portal-client.csr -CA fleet-ca.crt -CAkey fleet-ca.key -CAcreateserial -days 2 -sha256 -extfile portal-client.ext -out portal-client.crt >/dev/null 2>&1

openssl pkcs12 -export -name neta-coordinator -inkey coordinator.key -in coordinator.crt -certfile fleet-ca.crt -out coordinator.p12 -passout "pass:$STORE_PASSWORD" >/dev/null 2>&1
openssl pkcs12 -export -name neta-agent-issuer -inkey agent-issuer.key -in agent-issuer.crt -certfile fleet-ca.crt -out agent-issuer.p12 -passout "pass:$STORE_PASSWORD" >/dev/null 2>&1
openssl pkcs12 -export -nokeys -name fleet-ca -in fleet-ca.crt -out fleet-trust.p12 -passout "pass:$STORE_PASSWORD" >/dev/null 2>&1
chmod 0600 *.key *.p12
chmod 0644 *.crt

COORD="$SRC/coordinator"
mkdir -p "$COORD/deploy/certs"
install -m 0400 coordinator.p12 "$COORD/deploy/certs/coordinator.p12"
install -m 0400 agent-issuer.p12 "$COORD/deploy/certs/agent-issuer.p12"
install -m 0400 fleet-trust.p12 "$COORD/deploy/certs/fleet-trust.p12"
install -m 0644 fleet-ca.crt "$COORD/deploy/certs/fleet-ca.crt"
# The production coordinator image runs as numeric UID 10001. Bind-mounted
# private stores therefore must be owned by that UID; root-owned 0600 files are
# unreadable from the non-root container even though Docker can mount them.
chown 10001:10001 \
  "$COORD/deploy/certs/coordinator.p12" \
  "$COORD/deploy/certs/agent-issuer.p12" \
  "$COORD/deploy/certs/fleet-trust.p12"
cat >"$COORD/.env" <<EOF
NETA_FLEET_ID=fleet-acceptance
NETA_DB_NAME=neta_coordinator
NETA_DB_USER=neta
NETA_DB_PASSWORD=$DB_PASSWORD
NETA_BOOTSTRAP_ENROLLMENT_TOKEN=$ENROLLMENT_TOKEN
NETA_OPERATOR_ADMIN_TOKEN=$ADMIN_TOKEN
NETA_PORTAL_SERVICE_TOKEN=$PORTAL_SERVICE_TOKEN
NETA_REQUIRE_CLIENT_CERTIFICATE=true
# Acceptance-only exposure difference: bind coordinator to the EC2 host so the
# separately provisioned endpoint can reach it. The temporary SG limits 8443 to
# members of that SG only.
NETA_BIND_ADDRESS=0.0.0.0
NETA_HOST_PORT=8443
NETA_TLS_KEY_STORE_PASSWORD=$STORE_PASSWORD
NETA_TLS_TRUST_STORE_PASSWORD=$STORE_PASSWORD
NETA_ENROLLMENT_ISSUER_KEY_STORE_PASSWORD=$STORE_PASSWORD
EOF
chmod 0600 "$COORD/.env"
cd "$COORD"
# Use the production Compose definitions and production mTLS update path.
docker compose --env-file .env -f docker-compose.yml up -d postgres
./deploy/update-mtls.sh
./deploy/health-check.sh
for _ in {1..60}; do
  if curl -fsS --cacert "$PKI/fleet-ca.crt" "https://${COORDINATOR_PRIVATE_IP}:8443/actuator/health" | grep -q '"status":"UP"'; then break; fi
  sleep 2
done
curl -fsS --cacert "$PKI/fleet-ca.crt" "https://${COORDINATOR_PRIVATE_IP}:8443/actuator/health" >/dev/null

PORTAL="$SRC/portal"
mkdir -p "$PORTAL/secrets"
install -m 0644 "$PKI/fleet-ca.crt" "$PORTAL/secrets/coordinator-ca.pem"
install -m 0644 "$PKI/portal-client.crt" "$PORTAL/secrets/portal-client-cert.pem"
install -m 0400 "$PKI/portal-client.key" "$PORTAL/secrets/portal-client-key.pem"
# The production portal image also runs as UID 10001, so keep its private key
# non-world-readable while making it readable by the container process.
chown 10001:10001 "$PORTAL/secrets/portal-client-key.pem"
PORTAL_HASH="scrypt\$$(openssl rand -hex 16)\$$(openssl rand -hex 32)"
cat >"$PORTAL/.env" <<EOF
NETA_COORDINATOR_URL=https://${COORDINATOR_PRIVATE_IP}:8443
NETA_COORDINATOR_REQUEST_TIMEOUT_MS=5000
NETA_COORDINATOR_ADMIN_TOKEN=$ADMIN_TOKEN
NETA_COORDINATOR_PORTAL_SERVICE_TOKEN=$PORTAL_SERVICE_TOKEN
NETA_PORTAL_SERVICE_NAME=neta-portal-acceptance
NETA_COORDINATOR_CA_FILE=/run/secrets/coordinator-ca.pem
NETA_COORDINATOR_CLIENT_CERT_FILE=/run/secrets/portal-client-cert.pem
NETA_COORDINATOR_CLIENT_KEY_FILE=/run/secrets/portal-client-key.pem
NETA_COORDINATOR_ALLOW_INSECURE_HTTP=false
NETA_PORTAL_LEGACY_OPERATOR_API=false
NETA_PORTAL_USERS_JSON='[{"username":"acceptance","passwordHash":"$PORTAL_HASH","role":"ADMIN"}]'
NETA_PORTAL_SESSION_SECRET=$PORTAL_SESSION_SECRET
NETA_PORTAL_SESSION_TTL_SECONDS=28800
EOF
chmod 0600 "$PORTAL/.env"
cd "$PORTAL"
# Start only the production Portal service. The production cloudflared service is
# intentionally omitted so disposable acceptance portals are never published.
docker compose --env-file .env -f docker-compose.yml up -d --build portal
./deploy/health-check.sh

# Verify that the running topology still has the security/restart properties from
# the selected production Compose files rather than merely checking HTTP health.
POSTGRES_CID="$(docker compose -f "$COORD/docker-compose.yml" --env-file "$COORD/.env" ps -q postgres)"
COORDINATOR_CID="$(docker compose -f "$COORD/docker-compose.yml" -f "$COORD/docker-compose.mtls.yml" --env-file "$COORD/.env" ps -q coordinator)"
PORTAL_CID="$(docker compose -f "$PORTAL/docker-compose.yml" --env-file "$PORTAL/.env" ps -q portal)"
[[ -n "$POSTGRES_CID" && -n "$COORDINATOR_CID" && -n "$PORTAL_CID" ]]
[[ "$POSTGRES_CID" != "$COORDINATOR_CID" && "$COORDINATOR_CID" != "$PORTAL_CID" && "$POSTGRES_CID" != "$PORTAL_CID" ]]

check_restart() {
  local cid="$1" name="$2" policy
  policy="$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$cid")"
  [[ "$policy" == "unless-stopped" ]] || { echo "$name restart policy is $policy, expected unless-stopped" >&2; exit 1; }
}
check_restart "$POSTGRES_CID" postgres
check_restart "$COORDINATOR_CID" coordinator
check_restart "$PORTAL_CID" portal

[[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$PORTAL_CID")" == "true" ]] || { echo "portal root filesystem is not read-only" >&2; exit 1; }
docker inspect -f '{{json .HostConfig.CapDrop}}' "$PORTAL_CID" | grep -q 'ALL' || { echo "portal does not drop all Linux capabilities" >&2; exit 1; }
docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$PORTAL_CID" | grep -q 'no-new-privileges:true' || { echo "portal no-new-privileges is missing" >&2; exit 1; }

docker port "$PORTAL_CID" 8080/tcp | grep -Eq '^127\.0\.0\.1:8080$' || { echo "portal is not loopback-bound on host port 8080" >&2; exit 1; }
docker port "$COORDINATOR_CID" 8080/tcp | grep -Eq '(^0\.0\.0\.0:8443$|^\[::\]:8443$)' || { echo "coordinator is not exposed on acceptance host port 8443" >&2; exit 1; }
[[ -z "$(docker compose -f "$PORTAL/docker-compose.yml" --env-file "$PORTAL/.env" ps -q tunnel 2>/dev/null || true)" ]] || { echo "cloudflared tunnel must not run in acceptance" >&2; exit 1; }

cat >"$ROOT/production-parity.txt" <<EOF
NETA production-topology parity: PASS
postgres_container=$POSTGRES_CID
coordinator_container=$COORDINATOR_CID
portal_container=$PORTAL_CID
postgres_restart=unless-stopped
coordinator_restart=unless-stopped
portal_restart=unless-stopped
portal_read_only=true
portal_cap_drop=ALL
portal_no_new_privileges=true
portal_host_binding=127.0.0.1:8080
coordinator_host_binding=0.0.0.0:8443 (acceptance-only private-VPC reachability)
cloudflared_tunnel=not_started (intentional acceptance safety boundary)
coordinator_runtime_defaults=production Compose defaults
EOF
cat "$ROOT/production-parity.txt"

cat >"$ROOT/revisions.txt" <<EOF
coordinator_repository=$COORDINATOR_REPOSITORY
coordinator_ref=$COORDINATOR_REF
coordinator_commit=$(git -C "$COORD" rev-parse HEAD)
portal_repository=$PORTAL_REPOSITORY
portal_ref=$PORTAL_REF
portal_commit=$(git -C "$PORTAL" rev-parse HEAD)
EOF

echo "NETA coordinator + portal fresh production-parity setup complete"
