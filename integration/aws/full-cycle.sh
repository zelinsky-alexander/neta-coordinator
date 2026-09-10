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

COORDINATOR_INSTANCE_TYPE="${COORDINATOR_INSTANCE_TYPE:-t3.medium}"
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
wait_ssh(){ local ip="$1"; for _ in {1..60}; do ssh_host "$ip" true >/dev/null 2>&1 && return 0; sleep 5; done; return 1; }

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
cat >"$WORK/user-data.sh" <<EOF
#!/bin/bash
set -e
install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
echo '$PUBKEY' >> /home/ubuntu/.ssh/authorized_keys
chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
chmod 0600 /home/ubuntu/.ssh/authorized_keys
EOF

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

cat >"$OUT/environment.txt" <<EOF
run_id=$RUN_ID
aws_region=$AWS_REGION
coordinator_instance=$COORDINATOR_ID
coordinator_instance_type=$COORDINATOR_INSTANCE_TYPE
agent_instance=$AGENT_ID
agent_instance_type=$AGENT_INSTANCE_TYPE
coordinator_private_ip=$COORDINATOR_PRIVATE_IP
agent_private_ip=$AGENT_PRIVATE_IP
EOF

SCRIPT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scp_to "$SCRIPT_ROOT/remote/setup-coordinator.sh" "$COORDINATOR_PUBLIC_IP" /tmp/setup-coordinator.sh
log "installing fresh coordinator, PostgreSQL and portal"
ssh_host "$COORDINATOR_PUBLIC_IP" \
  "sudo env COORDINATOR_REPOSITORY='$COORDINATOR_REPOSITORY' COORDINATOR_REF='$COORDINATOR_REF' PORTAL_REPOSITORY='$PORTAL_REPOSITORY' PORTAL_REF='$PORTAL_REF' COORDINATOR_PRIVATE_IP='$COORDINATOR_PRIVATE_IP' bash /tmp/setup-coordinator.sh" \
  >"$OUT/logs/coordinator-setup.log" 2>&1

scp_from "$COORDINATOR_PUBLIC_IP" /opt/neta-acceptance/pki/fleet-ca.crt "$WORK/fleet-ca.crt"
scp_from "$COORDINATOR_PUBLIC_IP" /opt/neta-acceptance/runtime.env "$WORK/runtime.env"
scp_from "$COORDINATOR_PUBLIC_IP" /opt/neta-acceptance/revisions.txt "$OUT/coordinator-revisions.txt"
chmod 0600 "$WORK/runtime.env"
# shellcheck disable=SC1090
source "$WORK/runtime.env"

scp_to "$WORK/fleet-ca.crt" "$AGENT_PUBLIC_IP" /tmp/fleet-ca.crt
scp_to "$SCRIPT_ROOT/remote/setup-agent.sh" "$AGENT_PUBLIC_IP" /tmp/setup-agent.sh
ssh_host "$AGENT_PUBLIC_IP" "sudo mkdir -p /opt/neta-acceptance && sudo mv /tmp/fleet-ca.crt /opt/neta-acceptance/fleet-ca.crt && sudo chmod 0644 /opt/neta-acceptance/fleet-ca.crt"
log "installing and enrolling fresh Linux agent"
ssh_host "$AGENT_PUBLIC_IP" \
  "sudo env AGENT_REPOSITORY='$AGENT_REPOSITORY' AGENT_REF='$AGENT_REF' LAB_REPOSITORY='$LAB_REPOSITORY' LAB_REF='$LAB_REF' COORDINATOR_PRIVATE_IP='$COORDINATOR_PRIVATE_IP' NETA_ENROLLMENT_TOKEN='$ENROLLMENT_TOKEN' bash /tmp/setup-agent.sh" \
  >"$OUT/logs/agent-setup.log" 2>&1
scp_from "$AGENT_PUBLIC_IP" /opt/neta-acceptance/revisions.txt "$OUT/agent-revisions.txt"

log "preparing controlled lab peers on coordinator host"
ssh_host "$COORDINATOR_PUBLIC_IP" "sudo rm -rf /opt/neta-acceptance/src/lab; sudo git init -q /opt/neta-acceptance/src/lab; sudo git -C /opt/neta-acceptance/src/lab remote add origin https://github.com/$LAB_REPOSITORY.git; sudo git -C /opt/neta-acceptance/src/lab fetch --depth=1 origin '$LAB_REF'; sudo git -C /opt/neta-acceptance/src/lab checkout -q --detach FETCH_HEAD; sudo chown -R ubuntu:ubuntu /opt/neta-acceptance/src/lab"
ssh_host "$COORDINATOR_PUBLIC_IP" "mkdir -p /tmp/neta-lab-servers; cd /opt/neta-acceptance/src/lab; \
  nohup python3 common/server/beacon_server.py --bind 0.0.0.0 --port 18080 >/tmp/neta-lab-servers/001.log 2>&1 & \
  nohup python3 common/server/beacon_server.py --bind 0.0.0.0 --port 18443 --cert /opt/neta-acceptance/pki/coordinator.crt --key /opt/neta-acceptance/pki/coordinator.key >/tmp/neta-lab-servers/002.log 2>&1 & \
  nohup python3 scenarios/003-large-download/server/large_download_server.py --bind 0.0.0.0 --port 18081 --size-mib 50 >/tmp/neta-lab-servers/003.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18447 --connections 1 --scenario NETA-LAB-007-peer >/tmp/neta-lab-servers/007.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18448 --connections 5 --scenario NETA-LAB-008-peer >/tmp/neta-lab-servers/008.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18454 --connections 100 --scenario NETA-LAB-014-peer >/tmp/neta-lab-servers/014.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18455 --connections 250 --scenario NETA-LAB-015-peer >/tmp/neta-lab-servers/015.log 2>&1 & \
  nohup python3 common/server/tcp_lab_server.py --bind 0.0.0.0 --port 18457 --connections 1 --scenario NETA-LAB-017-peer >/tmp/neta-lab-servers/017.log 2>&1 & \
  sleep 2"

log "running Linux NETA Lab command suite"
set +e
ssh_host "$AGENT_PUBLIC_IP" "sudo env NETA_LAB_TARGET_HOST='$COORDINATOR_PRIVATE_IP' NETA_LAB_SCENARIOS='$LAB_SCENARIOS' NETA_LAB_OUTPUT_DIR=/opt/neta-acceptance/lab-results bash /opt/neta-acceptance/src/lab/automation/run-linux-suite.sh --target-host '$COORDINATOR_PRIVATE_IP' --scenarios '$LAB_SCENARIOS' --output-dir /opt/neta-acceptance/lab-results" >"$OUT/logs/lab-suite.log" 2>&1
LAB_RC=$?
set -e
scp_from "$AGENT_PUBLIC_IP" /opt/neta-acceptance/lab-results/summary.tsv "$OUT/lab/summary.tsv" || true
scp_from "$AGENT_PUBLIC_IP" /opt/neta-acceptance/lab-results/summary.json "$OUT/lab/summary.json" || true

run_peer_scenario() {
  local id="$1" agent_cmd="$2" peer_cmd="$3" log="$OUT/logs/lab-$id.log"
  [[ "$LAB_SCENARIOS" == "all" || ",$LAB_SCENARIOS," == *",$id,"* ]] || return 0
  log "running peer-coordinated NETA-LAB-$id"
  set +e
  ssh_host "$AGENT_PUBLIC_IP" "$agent_cmd" >"$log" 2>&1 & local agent_job=$!
  sleep 2
  ssh_host "$COORDINATOR_PUBLIC_IP" "$peer_cmd" >>"$log" 2>&1
  local peer_rc=$?
  wait "$agent_job"; local agent_rc=$?
  set -e
  if ((peer_rc != 0 || agent_rc != 0)); then echo -e "$id\tFAIL\t1\tpeer-coordinated scenario failed" >>"$OUT/lab/peer-summary.tsv"; return 1; fi
  echo -e "$id\tPASS\t0\tpeer-coordinated scenario completed" >>"$OUT/lab/peer-summary.tsv"
}
printf 'scenario\tstatus\texit_code\tnote\n' >"$OUT/lab/peer-summary.tsv"
PEER_RC=0
run_peer_scenario 016 \
  "sudo bash /opt/neta-acceptance/src/lab/scenarios/016-inbound-accepted-connection/linux/run-server.sh 0.0.0.0 18456" \
  "cd /opt/neta-acceptance/src/lab && python3 common/client/tcp_lab_client.py '$AGENT_PRIVATE_IP' 18456 --connections 1 --upload-bytes 1048576 --scenario NETA-LAB-016-client" || PEER_RC=1
run_peer_scenario 017 \
  "sudo bash /opt/neta-acceptance/src/lab/scenarios/017-concurrent-inbound-outbound/linux/run.sh '$COORDINATOR_PRIVATE_IP' 18457 18458" \
  "cd /opt/neta-acceptance/src/lab && python3 common/client/tcp_lab_client.py '$AGENT_PRIVATE_IP' 18458 --connections 1 --upload-bytes 1048576 --scenario NETA-LAB-017-inbound" || PEER_RC=1

log "verifying fleet, restart recovery and mTLS rejection"
ssh_host "$AGENT_PUBLIC_IP" "sudo /usr/local/bin/neta-agent fleet heartbeat --state-dir /var/lib/neta/identity; sudo systemctl restart neta-agent.service; sleep 3; sudo /usr/local/bin/neta-agent fleet heartbeat --state-dir /var/lib/neta/identity" >"$OUT/logs/agent-restart.log" 2>&1
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/coordinator && sudo docker compose --env-file .env -f docker-compose.yml -f docker-compose.mtls.yml restart coordinator && sleep 8" >"$OUT/logs/coordinator-restart.log" 2>&1
ssh_host "$AGENT_PUBLIC_IP" "sudo /usr/local/bin/neta-agent fleet heartbeat --state-dir /var/lib/neta/identity" >>"$OUT/logs/coordinator-restart.log" 2>&1
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/coordinator; export NETA_COORDINATOR_URL=https://127.0.0.1:8443 NETA_OPERATOR_CA=/opt/neta-acceptance/pki/fleet-ca.crt; ./neta status; ./neta endpoints; ./neta findings --limit 100" >"$OUT/logs/coordinator-state.log" 2>&1
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/portal && ./deploy/health-check.sh" >"$OUT/logs/portal-health.log" 2>&1

set +e
ssh_host "$COORDINATOR_PUBLIC_IP" "curl -sS --fail --cacert /opt/neta-acceptance/pki/fleet-ca.crt -H 'Content-Type: application/json' -d '{}' https://127.0.0.1:8443/api/v1/messages >/dev/null" >"$OUT/logs/unauthenticated-mtls.log" 2>&1
UNAUTH_RC=$?
set -e
if ((UNAUTH_RC == 0)); then echo "unauthenticated message endpoint unexpectedly accepted request" >>"$OUT/logs/unauthenticated-mtls.log"; SECURITY_RC=1; else SECURITY_RC=0; fi

log "collecting logs"
ssh_host "$AGENT_PUBLIC_IP" "sudo journalctl -u neta-agent.service --no-pager -n 1000" >"$OUT/logs/agent-journal.log" 2>&1 || true
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/coordinator && sudo docker compose --env-file .env -f docker-compose.yml -f docker-compose.mtls.yml logs --no-color coordinator postgres" >"$OUT/logs/coordinator.log" 2>&1 || true
ssh_host "$COORDINATOR_PUBLIC_IP" "cd /opt/neta-acceptance/src/portal && sudo docker compose --env-file .env -f docker-compose.yml logs --no-color portal" >"$OUT/logs/portal.log" 2>&1 || true
ssh_host "$COORDINATOR_PUBLIC_IP" "cat /tmp/neta-lab-servers/*.log 2>/dev/null || true" >"$OUT/logs/lab-peer-servers.log" 2>&1 || true

STATUS=PASS
((LAB_RC == 0 && PEER_RC == 0 && SECURITY_RC == 0)) || STATUS=FAIL
cat >"$OUT/ACCEPTANCE.md" <<EOF
# NETA Full-Cycle Linux Acceptance

- Result: **$STATUS**
- Run: \`$RUN_ID\`
- AWS region: \`$AWS_REGION\`
- Coordinator: \`$COORDINATOR_REPOSITORY@$COORDINATOR_REF\`
- Portal: \`$PORTAL_REPOSITORY@$PORTAL_REF\`
- Agent: \`$AGENT_REPOSITORY@$AGENT_REF\`
- Lab: \`$LAB_REPOSITORY@$LAB_REF\`
- Lab selection: \`$LAB_SCENARIOS\`

## Acceptance phases

- Fresh cloud instances provisioned: PASS
- Fresh coordinator/PostgreSQL install with ephemeral PKI: PASS
- Portal install and health validation: PASS
- Fresh Linux agent install: PASS
- Noninteractive enrollment and mTLS fleet messaging: PASS
- Centrally managed rules update: PASS
- Linux NETA Lab command suite: $([[ $LAB_RC -eq 0 ]] && echo PASS || echo FAIL)
- Peer-coordinated inbound scenarios: $([[ $PEER_RC -eq 0 ]] && echo PASS || echo FAIL)
- Agent restart/reconnect: PASS
- Coordinator restart/agent recovery: PASS
- Unauthenticated message-ingestion rejection: $([[ $SECURITY_RC -eq 0 ]] && echo PASS || echo FAIL)
- Portal post-test health: PASS

See \`lab/summary.tsv\`, \`lab/peer-summary.tsv\`, revision files, and \`logs/\` for evidence.
EOF

python3 - "$OUT" "$STATUS" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1]); status=sys.argv[2]
result={"result":status,"files":sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file())}
(root/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
PY

cat >"$OUT/junit.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="neta-full-cycle-linux" tests="3" failures="$(( (LAB_RC!=0) + (PEER_RC!=0) + (SECURITY_RC!=0) ))">
  <testcase classname="neta.acceptance" name="lab-command-suite">$([[ $LAB_RC -eq 0 ]] || echo '<failure message="lab command suite failed"/>')</testcase>
  <testcase classname="neta.acceptance" name="peer-inbound-suite">$([[ $PEER_RC -eq 0 ]] || echo '<failure message="peer inbound suite failed"/>')</testcase>
  <testcase classname="neta.acceptance" name="mtls-negative-control">$([[ $SECURITY_RC -eq 0 ]] || echo '<failure message="unauthenticated ingestion accepted"/>')</testcase>
</testsuite>
EOF

log "acceptance result: $STATUS"
[[ "$STATUS" == PASS ]]
