UPDATE agent_upgrades u
SET status = 'FAILED',
    failed_at = COALESCE(failed_at, now()),
    failure_code = COALESCE(failure_code, 'NOTHING_TO_UPGRADE'),
    failure_message = COALESCE(failure_message, 'Retired stale no-op upgrade: agent already reported the requested target build')
FROM agents a
WHERE u.agent_id = a.agent_id
  AND u.status IN ('REQUESTED','DELIVERED','DOWNLOADING','INSTALLING','LOCAL_HEALTHY')
  AND u.from_version IS NOT DISTINCT FROM u.target_version
  AND u.from_build_id IS NOT DISTINCT FROM u.target_build_id
  AND u.from_git_commit IS NOT DISTINCT FROM u.target_git_commit
  AND u.from_artifact_sha256 IS NOT DISTINCT FROM u.artifact_sha256
  AND a.agent_version IS NOT DISTINCT FROM u.target_version
  AND a.agent_build_id IS NOT DISTINCT FROM u.target_build_id
  AND a.agent_git_commit IS NOT DISTINCT FROM u.target_git_commit
  AND a.agent_artifact_sha256 IS NOT DISTINCT FROM u.artifact_sha256;
