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
apt-get install -y git curl openssl ca-certificates docker.io docker-compose-v2 openjdk-21-jre-headless
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
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 \
  -subj '/CN=NETA Full Cycle Fleet CA' \
  -keyout fleet-ca.key -out fleet-ca.crt >/dev/null 2>&1

openssl req -new -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=neta-coordinator-acceptance' \
  -keyout coordinator.key -out coordinator.csr >/dev/null 2>&1
cat >coordinator.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${COORDINATOR_PRIVATE_IP},DNS:neta-coordinator
EOF
openssl x509 -req -in coordinator.csr -CA fleet-ca.crt -CAkey fleet-ca.key -CAcreateserial \
  -days 2 -sha256 -extfile coordinator.ext -out coordinator.crt >/dev/null 2>&1

openssl req -new -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=NETA Acceptance Agent Issuer' \
  -keyout agent-issuer.key -out agent-issuer.csr >/dev/null 2>&1
cat >agent-issuer.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in agent-issuer.csr -CA fleet-ca.crt -CAkey fleet-ca.key -CAcreateserial \
  -days 2 -sha256 -extfile agent-issuer.ext -out agent-issuer.crt >/dev/null 2>&1

openssl req -new -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=neta-portal-acceptance' \
  -keyout portal-client.key -out portal-client.csr >/dev/null 2>&1
cat >portal-client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in portal-client.csr -CA fleet-ca.crt -CAkey fleet-ca.key -CAcreateserial \
  -days 2 -sha256 -extfile portal-client.ext -out portal-client.crt >/dev/null 2>&1

openssl pkcs12 -export -name neta-coordinator -inkey coordinator.key -in coordinator.crt \
  -certfile fleet-ca.crt -out coordinator.p12 -passout "pass:$STORE_PASSWORD" >/dev/null 2>&1
openssl pkcs12 -export -name neta-agent-issuer -inkey agent-issuer.key -in agent-issuer.crt \
  -certfile fleet-ca.crt -out agent-issuer.p12 -passout "pass:$STORE_PASSWORD" >/dev/null 2>&1
keytool -importcert -noprompt -storetype PKCS12 -alias fleet-ca -file fleet-ca.crt \
  -keystore fleet-trust.p12 -storepass "$STORE_PASSWORD" >/dev/null 2>&1
chmod 0600 *.key *.p12
chmod 0644 *.crt

COORD="$SRC/coordinator"
mkdir -p "$COORD/deploy/certs"
install -m 0600 coordinator.p12 "$COORD/deploy/certs/coordinator.p12"
install -m 0600 agent-issuer.p12 "$COORD/deploy/certs/agent-issuer.p12"
install -m 0600 fleet-trust.p12 "$COORD/deploy/certs/fleet-trust.p12"
install -m 0644 fleet-ca.crt "$COORD/deploy/certs/fleet-ca.crt"
cat >"$COORD/.env" <<EOF
NETA_FLEET_ID=fleet-acceptance
NETA_DB_NAME=neta_coordinator
NETA_DB_USER=neta
NETA_DB_PASSWORD=$DB_PASSWORD
NETA_BOOTSTRAP_ENROLLMENT_TOKEN=$ENROLLMENT_TOKEN
NETA_OPERATOR_ADMIN_TOKEN=$ADMIN_TOKEN
NETA_PORTAL_SERVICE_TOKEN=$PORTAL_SERVICE_TOKEN
NETA_REQUIRE_CLIENT_CERTIFICATE=true
NETA_BIND_ADDRESS=0.0.0.0
NETA_HOST_PORT=8443
NETA_TLS_KEY_STORE_PASSWORD=$STORE_PASSWORD
NETA_TLS_TRUST_STORE_PASSWORD=$STORE_PASSWORD
NETA_ENROLLMENT_ISSUER_KEY_STORE_PASSWORD=$STORE_PASSWORD
NETA_AGENT_ONLINE_THRESHOLD=PT2M
NETA_AGENT_OFFLINE_THRESHOLD=PT5M
NETA_RETAIN_HEARTBEATS=true
NETA_AUDIT_HEARTBEATS=true
EOF
chmod 0600 "$COORD/.env"
cd "$COORD"
docker compose --env-file .env -f docker-compose.yml up -d postgres
./deploy/update-mtls.sh

for _ in {1..60}; do
  if curl -fsS --cacert "$PKI/fleet-ca.crt" "https://${COORDINATOR_PRIVATE_IP}:8443/actuator/health" | grep -q '"status":"UP"'; then break; fi
  sleep 2
done
curl -fsS --cacert "$PKI/fleet-ca.crt" "https://${COORDINATOR_PRIVATE_IP}:8443/actuator/health" >/dev/null

PORTAL="$SRC/portal"
mkdir -p "$PORTAL/secrets"
install -m 0644 "$PKI/fleet-ca.crt" "$PORTAL/secrets/coordinator-ca.pem"
install -m 0644 "$PKI/portal-client.crt" "$PORTAL/secrets/portal-client-cert.pem"
install -m 0600 "$PKI/portal-client.key" "$PORTAL/secrets/portal-client-key.pem"
# A syntactically valid one-off account is sufficient for health/session validation;
# the full-cycle suite never logs in or persists this credential.
PORTAL_HASH="scrypt$$(openssl rand -hex 16)$$(openssl rand -hex 32)"
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
NETA_PORTAL_USERS_JSON=[{"username":"acceptance","passwordHash":"$PORTAL_HASH","role":"ADMIN"}]
NETA_PORTAL_SESSION_SECRET=$PORTAL_SESSION_SECRET
NETA_PORTAL_SESSION_TTL_SECONDS=3600
EOF
chmod 0600 "$PORTAL/.env"
cd "$PORTAL"
docker compose --env-file .env -f docker-compose.yml up -d --build portal
./deploy/health-check.sh

cat >"$ROOT/revisions.txt" <<EOF
coordinator_repository=$COORDINATOR_REPOSITORY
coordinator_ref=$COORDINATOR_REF
coordinator_commit=$(git -C "$COORD" rev-parse HEAD)
portal_repository=$PORTAL_REPOSITORY
portal_ref=$PORTAL_REF
portal_commit=$(git -C "$PORTAL" rev-parse HEAD)
EOF

echo "NETA coordinator + portal fresh setup complete"
