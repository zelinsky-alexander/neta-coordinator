CREATE TABLE yarax_content_canary_targets (
    agent_id text PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    bundle_id text NOT NULL REFERENCES yarax_content_bundles(bundle_id) ON DELETE CASCADE,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX yarax_content_canary_targets_bundle_idx
    ON yarax_content_canary_targets(bundle_id, created_at DESC);
