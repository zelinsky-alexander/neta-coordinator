CREATE SEQUENCE yarax_content_revision_seq START WITH 1;

CREATE TABLE yarax_content_bundles (
    bundle_id text PRIMARY KEY,
    revision bigint NOT NULL UNIQUE DEFAULT nextval('yarax_content_revision_seq'),
    content text NOT NULL,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    content_bytes bigint NOT NULL CHECK (content_bytes >= 0),
    status text NOT NULL DEFAULT 'AVAILABLE' CHECK (status IN ('AVAILABLE','ACTIVE','RETIRED')),
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz
);

CREATE TABLE yarax_content_desired (
    singleton smallint PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
    target_bundle_id text REFERENCES yarax_content_bundles(bundle_id),
    previous_bundle_id text REFERENCES yarax_content_bundles(bundle_id),
    rollout_percent integer NOT NULL DEFAULT 0 CHECK (rollout_percent BETWEEN 0 AND 100),
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO yarax_content_desired(singleton, rollout_percent) VALUES (1, 0)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE yarax_content_agent_state (
    agent_id text PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    installed_bundle_id text,
    active_bundle_id text,
    active_revision bigint,
    active_sha256 text,
    desired_bundle_id text,
    state text NOT NULL DEFAULT 'UNKNOWN' CHECK (state IN ('UNKNOWN','STALE','DOWNLOADING','INSTALLED','ACTIVE','APPLY_FAILED','UNSUPPORTED')),
    error text,
    last_ack_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX yarax_content_agent_state_state_idx
    ON yarax_content_agent_state(state, updated_at DESC);
CREATE INDEX yarax_content_bundles_status_idx
    ON yarax_content_bundles(status, created_at DESC);
