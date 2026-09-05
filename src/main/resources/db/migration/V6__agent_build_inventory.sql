ALTER TABLE agents
    ADD COLUMN agent_version text,
    ADD COLUMN agent_build_id text,
    ADD COLUMN agent_git_commit text,
    ADD COLUMN agent_os text,
    ADD COLUMN agent_arch text,
    ADD COLUMN agent_artifact_sha256 text,
    ADD COLUMN agent_protocol_version integer,
    ADD COLUMN agent_schema_version integer,
    ADD COLUMN agent_features jsonb,
    ADD COLUMN build_reported_at timestamptz;

ALTER TABLE agents
    ADD CONSTRAINT agents_agent_protocol_version_nonnegative
        CHECK (agent_protocol_version IS NULL OR agent_protocol_version >= 0),
    ADD CONSTRAINT agents_agent_schema_version_nonnegative
        CHECK (agent_schema_version IS NULL OR agent_schema_version >= 0);
