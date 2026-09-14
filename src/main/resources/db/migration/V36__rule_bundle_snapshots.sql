CREATE TABLE IF NOT EXISTS agent_rule_bundle_snapshots (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    version TEXT NOT NULL,
    bundle_json JSONB NOT NULL,
    bundle_text TEXT NOT NULL,
    applied_override_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, sha256)
);

CREATE INDEX IF NOT EXISTS idx_agent_rule_bundle_snapshots_revision
    ON agent_rule_bundle_snapshots(agent_id, revision, created_at DESC);
