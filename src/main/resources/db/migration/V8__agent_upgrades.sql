CREATE TABLE agent_upgrades (
    upgrade_id uuid PRIMARY KEY,
    agent_id text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,

    from_version text,
    from_build_id text,
    from_git_commit text,
    from_artifact_sha256 text,

    source_type text NOT NULL CHECK (source_type IN ('RELEASE','GIT_REF')),
    source_ref text NOT NULL,
    source_commit text NOT NULL,

    target_version text NOT NULL,
    target_build_id text NOT NULL,
    target_git_commit text NOT NULL,
    target_os text NOT NULL,
    target_arch text NOT NULL,
    artifact_name text NOT NULL,
    artifact_url text NOT NULL,
    artifact_sha256 text NOT NULL,

    status text NOT NULL CHECK (status IN (
        'REQUESTED','DELIVERED','DOWNLOADING','INSTALLING','LOCAL_HEALTHY',
        'CONFIRMED','FAILED','ROLLED_BACK'
    )),

    requested_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    download_started_at timestamptz,
    install_started_at timestamptz,
    local_healthy_at timestamptz,
    confirmed_at timestamptz,
    failed_at timestamptz,
    rolled_back_at timestamptz,
    failure_code text,
    failure_message text,

    CONSTRAINT agent_upgrades_target_sha256_format
        CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_upgrades_from_sha256_format
        CHECK (from_artifact_sha256 IS NULL OR from_artifact_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_upgrades_source_commit_format
        CHECK (source_commit ~ '^[0-9a-f]{40}$'),
    CONSTRAINT agent_upgrades_target_commit_format
        CHECK (target_git_commit ~ '^[0-9a-f]{40}$')
);

CREATE UNIQUE INDEX agent_upgrades_one_active_per_agent_uq
    ON agent_upgrades(agent_id)
    WHERE status IN ('REQUESTED','DELIVERED','DOWNLOADING','INSTALLING','LOCAL_HEALTHY');

CREATE INDEX agent_upgrades_agent_history_idx
    ON agent_upgrades(agent_id, requested_at DESC);

CREATE INDEX agent_upgrades_status_idx
    ON agent_upgrades(status, requested_at DESC);
