CREATE TABLE endpoint_contact_history (
    id bigserial PRIMARY KEY,
    agent_id text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    message_type text NOT NULL,
    sequence bigint NOT NULL,
    message_id text NOT NULL,
    contact_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(agent_id, sequence)
);

CREATE INDEX endpoint_contact_history_agent_time_idx
    ON endpoint_contact_history(agent_id, contact_at DESC);
CREATE INDEX endpoint_contact_history_time_idx
    ON endpoint_contact_history(contact_at DESC);
