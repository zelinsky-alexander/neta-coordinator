CREATE TABLE yarax_runtime_releases (
    version text PRIMARY KEY,
    source_ref text NOT NULL,
    release_base_url text NOT NULL,
    priority text NOT NULL CHECK (priority IN ('NORMAL','HIGH','EMERGENCY')),
    x86_64_sha256 text NOT NULL,
    arm64_sha256 text NOT NULL,
    status text NOT NULL DEFAULT 'AVAILABLE' CHECK (status IN ('AVAILABLE','ACTIVE','RETIRED')),
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz
);

CREATE TABLE yarax_runtime_desired (
    singleton smallint PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
    target_version text REFERENCES yarax_runtime_releases(version),
    previous_version text REFERENCES yarax_runtime_releases(version),
    rollout_percent integer NOT NULL DEFAULT 0 CHECK (rollout_percent BETWEEN 0 AND 100),
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO yarax_runtime_desired(singleton, rollout_percent) VALUES (1, 0)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE yarax_agent_runtime_state (
    agent_id text PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    installed_version text,
    active_version text,
    active_sha256 text,
    desired_version text,
    state text NOT NULL DEFAULT 'UNKNOWN' CHECK (state IN ('UNKNOWN','STALE','DOWNLOADING','INSTALLED','ACTIVE','APPLY_FAILED','UNSUPPORTED')),
    error text,
    last_ack_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX yarax_agent_runtime_state_state_idx ON yarax_agent_runtime_state(state, updated_at DESC);
