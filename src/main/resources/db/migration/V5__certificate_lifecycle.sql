ALTER TABLE agents
    ADD COLUMN certificate_not_before timestamptz,
    ADD COLUMN certificate_not_after timestamptz,
    ADD COLUMN certificate_registered_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN certificate_rotated_at timestamptz;

CREATE TABLE agent_certificate_history (
    id bigserial PRIMARY KEY,
    agent_id text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    certificate_sha256 text NOT NULL,
    not_before timestamptz,
    not_after timestamptz,
    activated_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    status text NOT NULL CHECK (status IN ('ACTIVE','RETIRED')),
    reason text
);

CREATE INDEX agent_certificate_history_agent_idx
    ON agent_certificate_history(agent_id, activated_at DESC);
CREATE INDEX agents_certificate_expiry_idx
    ON agents(certificate_not_after) WHERE status='ACTIVE';
