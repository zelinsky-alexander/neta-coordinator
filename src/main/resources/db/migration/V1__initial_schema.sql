CREATE TABLE agents (
    agent_id text PRIMARY KEY,
    fleet_id text NOT NULL,
    display_name text,
    certificate_sha256 text NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
    last_sequence bigint NOT NULL DEFAULT -1,
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz
);

CREATE TABLE enrollment_tokens (
    token_id uuid PRIMARY KEY,
    fleet_id text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    consumed_by_agent_id text REFERENCES agents(agent_id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE protocol_messages (
    id bigserial PRIMARY KEY,
    agent_id text NOT NULL REFERENCES agents(agent_id),
    message_id text NOT NULL,
    protocol text NOT NULL,
    schema_version integer NOT NULL,
    message_type text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    sequence bigint NOT NULL,
    correlation_id text,
    payload_hash text NOT NULL,
    payload jsonb NOT NULL,
    signature jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(agent_id, message_id),
    UNIQUE(agent_id, sequence)
);
CREATE INDEX protocol_messages_correlation_idx ON protocol_messages(correlation_id);
CREATE INDEX protocol_messages_received_idx ON protocol_messages(received_at);

CREATE TABLE findings (
    finding_id text PRIMARY KEY,
    message_id text NOT NULL,
    agent_id text NOT NULL REFERENCES agents(agent_id),
    target_host text NOT NULL,
    target_port integer NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    observed_from timestamptz,
    observed_to timestamptz,
    changes jsonb NOT NULL,
    performance_verdict text,
    trust_verdict text,
    rule_set jsonb,
    evidence_root text,
    payload jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX findings_target_idx ON findings(target_host, target_port, received_at DESC);
CREATE INDEX findings_agent_idx ON findings(agent_id, received_at DESC);

CREATE TABLE corroboration_requests (
    request_id text PRIMARY KEY,
    finding_id text REFERENCES findings(finding_id),
    target jsonb NOT NULL,
    probes jsonb NOT NULL,
    limits jsonb NOT NULL,
    deadline timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'PENDING',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE corroboration_responses (
    id bigserial PRIMARY KEY,
    request_id text NOT NULL REFERENCES corroboration_requests(request_id),
    agent_id text NOT NULL REFERENCES agents(agent_id),
    message_id text NOT NULL,
    status text NOT NULL,
    observations jsonb NOT NULL,
    evidence_root text,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(request_id, agent_id)
);

CREATE TABLE evidence_summaries (
    id bigserial PRIMARY KEY,
    agent_id text NOT NULL REFERENCES agents(agent_id),
    message_id text NOT NULL,
    correlation_id text,
    evidence_root text,
    summary jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(agent_id, message_id)
);

CREATE TABLE audit_events (
    id bigserial PRIMARY KEY,
    event_type text NOT NULL,
    agent_id text,
    message_id text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_created_idx ON audit_events(created_at DESC);
