#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?required}"
: "${NETA_AWS_VPC_ID:?required}"
: "${NETA_AWS_SUBNET_ID:?required}"
: "${NETA_AWS_AMI_ID:?required}"
: "${COORDINATOR_REPOSITORY:?required}"
: "${COORDINATOR_REF:?required}"
: "${PORTAL_REPOSITORY:?required}"
: "${PORTAL_REF:?required}"
: "${AGENT_REPOSITORY:?required}"
: "${AGENT_REF:?required}"
: "${LAB_REPOSITORY:?required}"
: "${LAB_REF:?required}"

COORDINATOR_INSTANCE_TYPE="${COORDINATOR_INSTANCE_TYPE:-t3.small}"
AGENT_INSTANCE_TYPE="${AGENT_INSTANCE_TYPE:-t3.small}"
LAB_SCENARIOS="${LAB_SCENARIOS:-all}"
RUN_ID="${GITHUB_RUN_ID:-local}-$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${NETA_ACCEPTANCE_OUTPUT_DIR:-$PWD/neta-full-cycle-report}"
WORK="$(mktemp -d -t neta-full-cycle-XXXXXX)"
SSH_KEY="$WORK/id_ed25519"
SG_ID=""
COORDINATOR_ID=""
AGENT_ID=""
mkdir -p "$OUT/logs" "$OUT/lab"

log(){ printf '[full-cycle] %s\n' "$*"; }
valid_repo(){ [[ "$1" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; }
valid_ref(){ [[ "$1" =~ ^[A-Za-z0-9._/-]+$ && "$1" != -* && "$1" != *..* ]]; }
for r in "$COORDINATOR_REPOSITORY" "$PORTAL_REPOSITORY" "$AGENT_REPOSITORY" "$LAB_REPOSITORY"; do valid_repo "$r" || { echo "invalid repository: $r" >&2; exit 2; }; done
for r in "$COORDINATOR_REF" "$PORTAL_REF" "$AGENT_REF" "$LAB_REF"; do valid_ref "$r" || { echo "invalid ref: $r" >&2; exit 2; }; done
[[ "$LAB_SCENARIOS" == "all" || "$LAB_SCENARIOS" =~ ^[0-9]{3}(,[0-9]{3})*$ ]] || { echo "invalid LAB_SCENARIOS" >&2; exit 2; }

cleanup() {
  set +e
  log "cleanup"
  [[ -n "$COORDINATOR_ID" ]] && aws ec2 terminate-instances --region "$AWS_REGION" --instance-ids "$COORDINATOR_ID" >/dev/null 2>&1
  [[ -n "$AGENT_ID" ]] && aws ec2 terminate-instances --region "$AWS_REGION" --instance-ids "$AGENT_ID" >/dev/null 2>&1
  ids=(); [[ -n "$COORDINATOR_ID" ]] && ids+=("$COORDINATOR_ID"); [[ -n "$AGENT_ID" ]] && ids+=("$AGENT_ID")
  ((${#ids[@]})) && aws ec2 wait instance-terminated --region "$AWS_REGION" --instance-ids "${ids[@]}" >/dev/null 2>&1
  [[ -n "$SG_ID" ]] && aws ec2 delete-security-group --region "$AWS_REGION" --group-id "$SG_ID" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ssh_opts=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=15)
ssh_host(){ ssh "${ssh_opts[@]}" "ubuntu@$1" "${@:2}"; }
scp_to(){ scp "${ssh_opts[@]}" "$1" "ubuntu@$2:$3"; }
scp_from(){ scp "${ssh_opts[@]}" "ubuntu@$1:$2" "$3"; }
scp_from_root_text(){
  local ip="$1" remote="$2" local_path="$3"
  ssh_host "$ip" "sudo cat -- '$remote'" >"$local_path"
  [[ -s "$local_path" ]] || { echo "remote file is empty or unavailable: $remote" >&2; return 1; }
}
wait_ssh(){ local ip="$1"; for _ in {1..60}; do ssh_host "$ip" true >/dev/null 2>&1 && return 0; sleep 5; done; return 1; }

resolve_ref() {
  local repository="$1" ref="$2" name="$3" dir="$WORK/resolve-$name"
  git init -q "$dir"
  git -C "$dir" remote add origin "https://github.com/${repository}.git"
  git -C "$dir" fetch -q --depth=1 origin "$ref"
  git -C "$dir" rev-parse FETCH_HEAD
}

log "resolving selected repository refs once for a reproducible run"
COORDINATOR_RESOLVED_SHA="$(resolve_ref "$COORDINATOR_REPOSITORY" "$COORDINATOR_REF" coordinator)"
PORTAL_RESOLVED_SHA="$(resolve_ref "$PORTAL_REPOSITORY" "$PORTAL_REF" portal)"
AGENT_RESOLVED_SHA="$(resolve_ref "$AGENT_REPOSITORY" "$AGENT_REF" agent)"
LAB_RESOLVED_SHA="$(resolve_ref "$LAB_REPOSITORY" "$LAB_REF" lab)"

AMI_ARCH="$(aws ec2 describe-images --region "$AWS_REGION" --image-ids "$NETA_AWS_AMI_ID" --query 'Images[0].Architecture' --output text)"
case "$AMI_ARCH" in
  x86_64) AGENT_ARCH=amd64 ;;
  arm64) AGENT_ARCH=arm64 ;;
  *) echo "unsupported AMI architecture for NETA agent acceptance: $AMI_ARCH" >&2; exit 2 ;;
esac
AGENT_SHORT_SHA="${AGENT_RESOLVED_SHA:0:12}"
AGENT_RELEASE_TAG="dev-${AGENT_RESOLVED_SHA}"
AGENT_RELEASE_BASE="https://github.com/${AGENT_REPOSITORY}/releases/download/${AGENT_RELEASE_TAG}"
AGENT_PACKAGE_NAME="neta-agent-linux-${AGENT_ARCH}-${AGENT_SHORT_SHA}.tar.gz"
log "preflighting immutable agent package for ${AGENT_RESOLVED_SHA} (${AGENT_ARCH})"
curl -fsSL --retry 3 --connect-timeout 10 -o "$WORK/release-manifest.json" "$AGENT_RELEASE_BASE/release-manifest.json"
curl -fsSIL --retry 3 --connect-timeout 10 "$AGENT_RELEASE_BASE/$AGENT_PACKAGE_NAME" >/dev/null
python3 - "$WORK/release-manifest.json" "$AGENT_RESOLVED_SHA" "$AGENT_ARCH" "$AGENT_PACKAGE_NAME" <<'PY'
import json, pathlib, sys
manifest_path, commit, arch, package = sys.argv[1:]
manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding='utf-8'))
if str(manifest.get('git_commit', '')).lower() != commit.lower():
    raise SystemExit(f"preflight manifest commit mismatch: {manifest.get('git_commit')} != {commit}")
if not any(a.get('os') == 'linux' and a.get('arch') == arch and a.get('name') == package for a in manifest.get('artifacts', [])):
    raise SystemExit(f"preflight manifest has no linux/{arch} artifact named {package}")
PY

log "creating ephemeral SSH identity"
ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY"
RUNNER_IP="$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')"
[[ "$RUNNER_IP" =~ ^[0-9a-fA-F:.]+$ ]] || { echo "cannot determine runner IP" >&2; exit 1; }

log "creating temporary security group"
SG_ID="$(aws ec2 create-security-group --region "$AWS_REGION" --vpc-id "$NETA_AWS_VPC_ID" \
  --group-name "neta-full-cycle-${RUN_ID//[^A-Za-z0-9-]/-}" --description "Temporary NETA full-cycle acceptance" \
  --query GroupId --output text)"
aws ec2 authorize-security-group-ingress --region "$AWS_REGION" --group-id "$SG_ID" --protocol tcp --port 22 --cidr "${RUNNER_IP}/32" >/dev/null
aws ec2 authorize-security-group-ingress --region "$AWS_REGION" --group-id "$SG_ID" --protocol tcp --port 8443 --source-group "$SG_ID" >/dev/null
aws ec2 authorize-security-group-ingress --region "$AWS_REGION" --group-id "$SG_ID" --protocol tcp --port 18000-18999 --source-group "$SG_ID" >/dev/null

PUBKEY="$(cat "$SSH_KEY.pub")"
cat >"$WORK/user-data.sh" <<EOF2
#!/bin/bash
set -e
install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
echo '$PUBKEY' >> /home/ubuntu/.ssh/authorized_keys
chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
chmod 0600 /home/ubuntu/.ssh/authorized_keys
EOF2

launch() {
  local name="$1" type="$2"
  aws ec2 run-instances --region "$AWS_REGION" --image-id "$NETA_AWS_AMI_ID" --instance-type "$type" \
    --subnet-id "$NETA_AWS_SUBNET_ID" --security-group-ids "$SG_ID" --associate-public-ip-address \
    --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --user-data "file://$WORK/user-data.sh" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name},{Key=Purpose,Value=NETA-full-cycle},{Key=RunId,Value=$RUN_ID}]" \
    --query 'Instances[0].InstanceId' --output text
}

log "launching fresh coordinator and Linux endpoint"
COORDINATOR_ID="$(launch neta-acceptance-coordinator "$COORDINATOR_INSTANCE_TYPE")"
AGENT_ID="$(launch neta-acceptance-agent "$AGENT_INSTANCE_TYPE")"
aws ec2 wait instance-status-ok --region "$AWS_REGION" --instance-ids "$COORDINATOR_ID" "$AGENT_ID"

instance_field(){ aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$1" --query "Reservations[0].Instances[0].$2" --output text; }
COORDINATOR_PUBLIC_IP="$(instance_field "$COORDINATOR_ID" PublicIpAddress)"
COORDINATOR_PRIVATE_IP="$(instance_field "$COORDINATOR_ID" PrivateIpAddress)"
AGENT_PUBLIC_IP="$(instance_field "$AGENT_ID" PublicIpAddress)"
AGENT_PRIVATE_IP="$(instance_field "$AGENT_ID" PrivateIpAddress)"
wait_ssh "$COORDINATOR_PUBLIC_IP"
wait_ssh "$AGENT_PUBLIC_IP"

cat >"$OUT/environment.txt" <<EOF2
run_id=$RUN_ID
aws_region=$AWS_REGION
ami_id=$NETA_AWS_AMI_ID
ami_architecture=$AMI_ARCH
coordinator_instance=$COORDINATOR_ID
coordinator_instance_type=$COORDINATOR_INSTANCE_TYPE
agent_instance=$AGENT_ID
agent_instance_type=$AGENT_INSTANCE_TYPE
coordinator_private_ip=$COORDINATOR_PRIVATE_IP
agent_private_ip=$AGENT_PRIVATE_IP
coordinator_selected_ref=$COORDINATOR_REF
coordinator_resolved_sha=$COORDINATOR_RESOLVED_SHA
portal_selected_ref=$PORTAL_REF
portal_resolved_sha=$PORTAL_RESOLVED_SHA
agent_selected_ref=$AGENT_REF
agent_resolved_sha=$AGENT_RESOLVED_SHA
lab_selected_ref=$LAB_REF
lab_resolved_sha=$LAB_RESOLVED_SHA
EOF2

SCRIPT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scp_to "$SCRIPT_ROOT/remote/setup-coordinator.sh" "$COORDINATOR_PUBLIC_IP" /tmp/setup-coordinator.sh
log "installing fresh coordinator, PostgreSQL and portal"
ssh_host "$COORDINATOR_PUBLIC_IP" \
  "sudo env COORDINATOR_REPOSITORY='$COORDINATOR_REPOSITORY' COORDINATOR_REF='$COORDINATOR_RESOLVED_SHA' PORTAL_REPOSITORY='$PORTAL_REPOSITORY' PORTAL_REF='$PORTAL_RESOLVED_SHA' COORDINATOR_PRIVATE_IP='$COORDINATOR_PRIVATE_IP' bash /tmp/setup-coordinator.sh" \
  >"$OUT/logs/coordinator-setup.log" 2>&1

# Keep the coordinator acceptance root private. Pull these small text artifacts
# through sudo over the authenticated SSH channel instead of loosening permissions.
scp_from_root_text "$COORDINATOR_PUBLIC_IP" /opt/neta-acceptance/pki/fleet-ca.crt "$WORK/fleet-ca.crt"
scp_from_root_text "$COORDINATOR_PUBLIC_IP" /opt/neta-acceptance/runtime.env "$WORK/runtime.env"
scp_from_root_text "$COORDINATOR_PUBLIC_IP" /opt/neta-acceptance/revisions.txt "$OUT/coordinator-revisions.txt"
scp_from_root_text "$COORDINATOR_PUBLIC_IP" /opt/neta-acceptance/production-parity.txt "$OUT/production-parity.txt"
chmod 0600 "$WORK/runtime.env"
# shellcheck disable=SC1090
source "$WORK/runtime.env"

scp_to "$WORK/fleet-ca.crt" "$AGENT_PUBLIC_IP" /tmp/fleet-ca.crt
scp_to "$SCRIPT_ROOT/remote/setup-agent.sh" "$AGENT_PUBLIC_IP" /tmp/setup-agent.sh
scp_to "$SCRIPT_ROOT/remote/install-agent-package.sh" "$AGENT_PUBLIC_IP" /tmp/install-agent-package.sh
ssh_host "$AGENT_PUBLIC_IP" "sudo chmod 0755 /tmp/install-agent-package.sh; sudo mkdir -p /opt/neta-acceptance && sudo mv /tmp/fleet-ca.crt /opt/neta-acceptance/fleet-ca.crt && sudo chmod 0644 /opt/neta-acceptance/fleet-ca.crt"
log "installing immutable prebuilt Linux agent package and enrolling endpoint"
ssh_host "$AGENT_PUBLIC_IP" \
  "sudo env AGENT_REPOSITORY='$AGENT_REPOSITORY' AGENT_REF='$AGENT_RESOLVED_SHA' LAB_REPOSITORY='$LAB_REPOSITORY' LAB_REF='$LAB_RESOLVED_SHA' COORDINATOR_PRIVATE_IP='$COORDINATOR_PRIVATE_IP' NETA_ENROLLMENT_TOKEN='$ENROLLMENT_TOKEN' bash /tmp/setup-agent.sh" \
  >"$OUT/logs/agent-setup.log" 2>&1
scp_from_root_text "$AGENT_PUBLIC_IP" /opt/neta-acceptance/revisions.txt "$OUT/agent-revisions.txt"

log "preparing controlled lab peers on coordinator host"
PEER_LAB=/home/ubuntu/neta-lab
ssh_host "$COORDINATOR_PUBLIC_IP" "set -e; rm -rf '$PEER_LAB'; git init -q '$PEER_LAB'; git -C '$PEER_LAB' remote add origin https://github.com/$LAB_REPOSITORY.git; git -C '$PEER_LAB' fetch --depth=1 origin '$LAB_RESOLVED_SHA'; git -C '$PEER_LAB' checkout -q --detach FETCH_HEAD"
ssh_host "$COORDINATOR_PUBLIC_IP" "sudo install -d -m 0700 -o ubuntu -g ubuntu /tmp/neta-lab-servers; sudo install -m 0644 -o ubuntu -g ubuntu /opt/neta-acceptance/pki/coordinator.crt /tmp/neta-lab-servers/server.crt; sudo install -m 0600 -o ubuntu -g ubuntu /opt/neta-acceptance/pki/coordinator.key /tmp/neta-lab-servers/server.key"
ssh_host "$COORDINATOR_PUBLIC_IP" "set -e; cd '$PEER_LAB'; \
  nohup python3 common/server/beacon_server.py --bind 0.0.0.0 --port 18080 >/tmp/neta-lab-servers/001.log 2>&1 & \
  nohup python3 common/server/beacon_server.py --bind 0.0.0.0 --port 18443 --cert /tmp/neta-lab-servers/server.crt --key /tmp/neta-lab-servers/server.key >/tmp/neta-lab-servers/002.log 2>&1 & \
  nohup python3 scenarios/003-large-download/server/large_download_server.py --bind 0.0.0.0 --port 18081 --size-mib 50 >/tmp/neta-lab-servers/003.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18447 --connections 1 --scenario NETA-LAB-007-peer >/tmp/neta-lab-servers/007.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18448 --connections 5 --scenario NETA-LAB-008-peer >/tmp/neta-lab-servers/008.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18454 --connections 100 --scenario NETA-LAB-014-peer >/tmp/neta-lab-servers/014.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18455 --connections 250 --scenario NETA-LAB-015-peer >/tmp/neta-lab-servers/015.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18457 --connections 1 --scenario NETA-LAB-017-peer >/tmp/neta-lab-servers/017.log 2>&1 & \
  sleep 2; command -v ss >/dev/null; for p in 18080 18443 18081 18447 18448 18454 18455 18457; do ss -ltn | grep -Eq ":\$p[[:space:]]" || { echo "lab peer listener missing on port \$p" >&2; cat /tmp/neta-lab-servers/*.log >&2 || true; exit 1; }; done"

log "running Linux NETA Lab command suite"
set +e
ssh_host "$AGENT_PUBLIC_IP" "sudo env NETA_LAB_TARGET_HOST='$COORDINATOR_PRIVATE_IP' NETA_LAB_SCENARIOS='$LAB_SCENARIOS' NETA_LAB_OUTPUT_DIR=/opt/neta-acceptance/lab-results bash /opt/neta-acceptance/src/lab/automation/run-linux-suite.sh --target-host '$COORDINATOR_PRIVATE_IP' --scenarios '$LAB_SCENARIOS' --output-dir /opt/neta-acceptance/lab-results" >"$OUT/logs/lab-suite.log" 2>&1
LAB_RC=$?
set -e
scp_from "$AGENT_PUBLIC_IP" /opt/neta-acceptance/lab-results/summary.tsv "$OUT/lab/summary.tsv" || true
scp_from "$AGENT_PUBLIC_IP" /opt/neta-acceptance/lab-results/summary.json "$OUT/lab/summary.json" || true

run_peer_scenario() {
  local id="$1" agent_cmd="$2" peer_cmd="$3" delay="${4:-1}" log_file="$OUT/logs/lab-$id.log"
  [[ "$LAB_SCENARIOS" == "all" || ",$LAB_SCENARIOS," == *",$id,"* ]] || return 0
  log "running peer-coordinated NETA-LAB-$id"
  set +e
  ssh_host "$AGENT_PUBLIC_IP" "$agent_cmd" >"$log_file" 2>&1 & local agent_job=$!
  sleep "$delay"
  local peer_rc=1
  for _ in {1..10}; do
    ssh_host "$COORDINATOR_PUBLIC_IP" "$peer_cmd" >>"$log_file" 2>&1
    peer_rc=$?
    ((peer_rc == 0)) && break
    sleep 1
  done
  wait "$agent_job"; local agent_rc=$?
  set -e
  if ((peer_rc != 0 || agent_rc != 0)); then echo -e "$id\tFAIL\t1\tpeer-coordinated scenario failed" >>"$OUT/lab/peer-summary.tsv"; return 1; fi
  echo -e "$id\tPASS\t0\tpeer-coordinated scenario completed" >>"$OUT/lab/peer-summary.tsv"
}
printf 'scenario\tstatus\texit_code\tnote\n' >"$OUT/lab/peer-summary.tsv"
PEER_RC=0
run_peer_scenario 016 \
  "sudo bash /opt/neta-acceptance/src/lab/scenarios/016-inbound-accepted-connection/linux/run-server.sh 0.0.0.0 18456" \
  "cd '$PEER_LAB' && python3 common/client/tcp_lab_client.py '$AGENT_PRIVATE_IP' 18456 --connections 1 --upload-bytes 1048576 --scenario NETA-LAB-016-client" || PEER_RC=1
run_peer_scenario 017 \
  "sudo bash /opt/neta-acceptance/src/lab/scenarios/017-concurrent-inbound-outbound/linux/run.sh '$COORDINATOR_PRIVATE_IP' 18457 18458" \
  "cd '$PEER_LAB' && python3 common/client/tcp_lab_client.py '$AGENT_PRIVATE_IP' 18458 --connections 1 --upload-bytes 1048576 --scenario NETA-LAB-017-inbound" || PEER_RC=1
run_peer_scenario 018 \
  "sudo bash /opt/neta-acceptance/src/lab/scenarios/018-listener-negative-control/linux/run.sh 0.0.0.0 18458 15" \
  "cd '$PEER_LAB' && python3 common/client/tcp_lab_client.py '$AGENT_PRIVATE_IP' 18458 --connections 1 --scenario NETA-LAB-018-client" \
  16 || PEER_RC=1

log "verifying fleet, restart recovery and mTLS rejection"
ssh_host "$AGENT_PUBLIC_IP" "sudo /usr/local/bin/neta-agent fleet heartbeat --state-dir /var/lib/neta/identity; sudo systemctl restart neta-agent.service; sleep 3; sudo /usr/local/bin/neta-agent fleet heartbeat --state-dir /var/lib/neta/identity" >"$OUT/logs/agent-restart.log" 2>&1
ssh_host "$COORDINATOR_PUBLIC_IP" "set -e; cd /opt/neta-acceptance/src/coordinator; sudo docker compose --env-file .env -f docker-compose.yml -f docker-compose.mtls.yml restart coordinator; for i in \$(seq 1 30); do sudo bash ./deploy/health-check.sh >/tmp/neta-coordinator-restart-health.log 2>&1 && { cat /tmp/neta-coordinator-restart-health.log; exit 0; }; sleep 2; done; cat /tmp/neta-coordinator-restart-health.log; sudo docker compose --env-file .env -f docker-compose.yml -f docker-compose.mtls.yml logs --tail=120 coordinator; exit 1" >"$OUT/logs/coordinator-restart.log" 2>&1
ssh_host "$AGENT_PUBLIC_IP" "sudo /usr/local/bin/neta-agent fleet heartbeat --state-dir /var/lib/neta/identity" >>"$OUT/logs/coordinator-restart.log" 2>&1
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/coordinator; sudo env NETA_COORDINATOR_URL=https://127.0.0.1:8443 NETA_OPERATOR_CA=/opt/neta-acceptance/pki/fleet-ca.crt bash ./neta status; sudo env NETA_COORDINATOR_URL=https://127.0.0.1:8443 NETA_OPERATOR_CA=/opt/neta-acceptance/pki/fleet-ca.crt bash ./neta endpoints; sudo env NETA_COORDINATOR_URL=https://127.0.0.1:8443 NETA_OPERATOR_CA=/opt/neta-acceptance/pki/fleet-ca.crt bash ./neta findings --limit 100" >"$OUT/logs/coordinator-state.log" 2>&1
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/portal && sudo bash ./deploy/health-check.sh" >"$OUT/logs/portal-health.log" 2>&1

# Prove the application-layer client-certificate gate specifically. Sending `{}`
# would only prove that malformed protocol input gets a 4xx because envelope
# validation happens before the client-certificate check. Use the real enrolled
# agent id and a structurally valid Heartbeat envelope, but deliberately omit the
# client certificate. The expected result is the coordinator's exact 401 reason.
AGENT_ENROLLED_ID="$(ssh_host "$AGENT_PUBLIC_IP" "sudo /usr/local/bin/neta-agent fleet status --state-dir /var/lib/neta/identity | sed -n 's/^Agent ID:[[:space:]]*//p' | head -n1")"
[[ -n "$AGENT_ENROLLED_ID" ]] || { echo "cannot determine enrolled agent id for mTLS negative control" >&2; exit 1; }
python3 - "$WORK/unauthenticated-message.json" "$AGENT_ENROLLED_ID" <<'PY'
import datetime as dt, json, pathlib, sys, uuid
out, agent_id = sys.argv[1:]
created = dt.datetime.now(dt.timezone.utc)
expires = created + dt.timedelta(seconds=60)
iso = lambda value: value.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
message = {
    "protocol": "neta-agent/1",
    "schema_version": 1,
    "message_id": f"acceptance-negative-{uuid.uuid4()}",
    "message_type": "Heartbeat",
    "agent_id": agent_id,
    "created_at": iso(created),
    "expires_at": iso(expires),
    "sequence": 0,
    "correlation_id": None,
    "payload_hash": "sha256:" + "0" * 64,
    "payload": {},
    "signature": {
        "algorithm": "acceptance-negative-control",
        "key_id": "none",
        "value": "not-used-without-client-certificate",
    },
}
pathlib.Path(out).write_text(json.dumps(message, separators=(",", ":")) + "\n", encoding="utf-8")
PY
scp_to "$WORK/unauthenticated-message.json" "$COORDINATOR_PUBLIC_IP" /tmp/neta-unauth-request.json
set +e
UNAUTH_CODE="$(ssh_host "$COORDINATOR_PUBLIC_IP" "sudo curl -sS --cacert /opt/neta-acceptance/pki/fleet-ca.crt -o /tmp/neta-unauth-body -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @/tmp/neta-unauth-request.json https://127.0.0.1:8443/api/v1/messages" 2>"$OUT/logs/unauthenticated-mtls.log")"
UNAUTH_CURL_RC=$?
UNAUTH_BODY="$(ssh_host "$COORDINATOR_PUBLIC_IP" "sudo cat /tmp/neta-unauth-body 2>/dev/null" 2>/dev/null)"
set -e
printf 'curl_rc=%s http_code=%s agent_id=%s\n%s\n' "$UNAUTH_CURL_RC" "$UNAUTH_CODE" "$AGENT_ENROLLED_ID" "$UNAUTH_BODY" >>"$OUT/logs/unauthenticated-mtls.log"
if ((UNAUTH_CURL_RC != 0)); then
  echo "negative control transport failed; client-certificate rejection was not proven" >>"$OUT/logs/unauthenticated-mtls.log"
  SECURITY_RC=1
elif [[ "$UNAUTH_CODE" == "401" ]] && grep -Fq 'client certificate is required' <<<"$UNAUTH_BODY"; then
  SECURITY_RC=0
else
  echo "negative control did not reach the expected missing-client-certificate rejection" >>"$OUT/logs/unauthenticated-mtls.log"
  SECURITY_RC=1
fi

log "collecting logs"
ssh_host "$AGENT_PUBLIC_IP" "sudo journalctl -u neta-agent.service --no-pager -n 1000" >"$OUT/logs/agent-journal.log" 2>&1 || true
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/coordinator && sudo docker compose --env-file .env -f docker-compose.yml -f docker-compose.mtls.yml logs --no-color coordinator postgres" >"$OUT/logs/coordinator.log" 2>&1 || true
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/portal && sudo docker compose --env-file .env -f docker-compose.yml logs --no-color portal" >"$OUT/logs/portal.log" 2>&1 || true
ssh_host "$COORDINATOR_PUBLIC_IP" "cat /tmp/neta-lab-servers/*.log 2>/dev/null || true" >"$OUT/logs/lab-peer-servers.log" 2>&1 || true

STATUS=PASS
((LAB_RC == 0 && PEER_RC == 0 && SECURITY_RC == 0)) || STATUS=FAIL
cat >"$OUT/ACCEPTANCE.md" <<EOF2
# NETA Full-Cycle Linux Acceptance

- Result: **$STATUS**
- Run: \`$RUN_ID\`
- AWS region: \`$AWS_REGION\`
- Coordinator: \`$COORDINATOR_REPOSITORY@$COORDINATOR_REF\` -> \`$COORDINATOR_RESOLVED_SHA\`
- Portal: \`$PORTAL_REPOSITORY@$PORTAL_REF\` -> \`$PORTAL_RESOLVED_SHA\`
- Agent: \`$AGENT_REPOSITORY@$AGENT_REF\` -> \`$AGENT_RESOLVED_SHA\`
- Lab: \`$LAB_REPOSITORY@$LAB_REF\` -> \`$LAB_RESOLVED_SHA\`
- Lab selection: \`$LAB_SCENARIOS\`

## Acceptance phases

- Fresh cloud instances provisioned: PASS
- Fresh coordinator/PostgreSQL install with ephemeral PKI: PASS
- Portal install and health validation: PASS
- Production topology parity checks: PASS
- Immutable prebuilt Linux agent package install: PASS
- Noninteractive enrollment and mTLS fleet messaging: PASS
- Centrally managed rules update: PASS
- Linux NETA Lab command suite: $([[ $LAB_RC -eq 0 ]] && echo PASS || echo FAIL)
- Peer-coordinated inbound scenarios: $([[ $PEER_RC -eq 0 ]] && echo PASS || echo FAIL)
- Agent restart/reconnect: PASS
- Coordinator restart/agent recovery: PASS
- Unauthenticated message-ingestion HTTP rejection: $([[ $SECURITY_RC -eq 0 ]] && echo PASS || echo FAIL)
- Portal post-test health: PASS

See \`production-parity.txt\`, \`lab/summary.tsv\`, \`lab/peer-summary.tsv\`, revision files, and \`logs/\` for evidence.
EOF2

python3 - "$OUT" "$STATUS" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1]); status=sys.argv[2]
result={"result":status,"files":sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file())}
(root/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
PY

cat >"$OUT/junit.xml" <<EOF2
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="neta-full-cycle-linux" tests="3" failures="$(( (LAB_RC!=0) + (PEER_RC!=0) + (SECURITY_RC!=0) ))">
  <testcase classname="neta.acceptance" name="lab-command-suite">$([[ $LAB_RC -eq 0 ]] || echo '<failure message="lab command suite failed"/>')</testcase>
  <testcase classname="neta.acceptance" name="peer-inbound-suite">$([[ $PEER_RC -eq 0 ]] || echo '<failure message="peer inbound suite failed"/>')</testcase>
  <testcase classname="neta.acceptance" name="mtls-negative-control">$([[ $SECURITY_RC -eq 0 ]] || echo '<failure message="unauthenticated ingestion was not proven rejected"/>')</testcase>
</testsuite>
EOF2

log "acceptance result: $STATUS"
[[ "$STATUS" == PASS ]]
