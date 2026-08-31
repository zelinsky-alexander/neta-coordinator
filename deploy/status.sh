#!/usr/bin/env sh
set -eu

echo "NETA Coordinator deployment"
echo "---------------------------"
docker compose --env-file .env ps
printf '\nCoordinator health: '
if curl -fsS http://127.0.0.1:${NETA_HOST_PORT:-8080}/actuator/health >/dev/null 2>&1; then
  echo "UP"
else
  echo "NOT READY"
fi
printf 'Disk free: '
df -h . | awk 'NR==2 {print $4}'
