-- RM3 foundation: preserve analyst false-positive feedback separately from exact
-- suppression, and introduce explicit staged policy/baseline objects. None of
-- these staged objects alter endpoint policy until a later approval/publish path
-- promotes them.

CREATE TABLE finding_feedback (
    feedback_id          bigserial PRIMARY KEY,
    finding_id_snapshot  text NOT NULL,
    agent_id             text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    finding_key          text NOT NULL,
    rule_id              text,
    subject_type         text,
    subject_id           text,
    feedback_type        text NOT NULL CHECK (feedback_type IN ('FALSE_POSITIVE')),
    requested_scope      text NOT NULL DEFAULT 'EXACT'
                         CHECK (requested_scope IN ('EXACT','ENDPOINT','GROUP','GLOBAL')),
    requested_action     text NOT NULL DEFAULT 'NONE'
                         CHECK (requested_action IN ('NONE','PROPOSE_RULE_EXCLUSION','PROPOSE_BASELINE')),
    reason               text NOT NULL,
    context_json         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX finding_feedback_agent_created_idx
    ON finding_feedback(agent_id, created_at DESC);
CREATE INDEX finding_feedback_rule_created_idx
    ON finding_feedback(rule_id, created_at DESC);

CREATE TABLE rule_overrides (
    override_id          bigserial PRIMARY KEY,
    scope_type           text NOT NULL CHECK (scope_type IN ('ENDPOINT','GROUP','GLOBAL')),
    scope_id             text,
    rule_id              text NOT NULL,
    enabled_override     boolean,
    parameters_patch     jsonb NOT NULL DEFAULT '{}'::jsonb,
    exclusions_patch     jsonb NOT NULL DEFAULT '{}'::jsonb,
    status               text NOT NULL DEFAULT 'STAGED'
                         CHECK (status IN ('STAGED','APPROVED','RETIRED')),
    source_feedback_id   bigint REFERENCES finding_feedback(feedback_id) ON DELETE SET NULL,
    reason               text NOT NULL,
    created_by           text NOT NULL DEFAULT 'operator',
    created_at           timestamptz NOT NULL DEFAULT now(),
    approved_at          timestamptz,
    CHECK ((scope_type='GLOBAL' AND scope_id IS NULL) OR
           (scope_type IN ('ENDPOINT','GROUP') AND scope_id IS NOT NULL))
);

CREATE INDEX rule_overrides_scope_idx
    ON rule_overrides(scope_type, scope_id, status, rule_id);

CREATE TABLE endpoint_learning_state (
    agent_id             text PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    mode                 text NOT NULL DEFAULT 'OFF' CHECK (mode IN ('OFF','LEARNING','REVIEW')),
    started_at           timestamptz,
    learning_until       timestamptz,
    minimum_observations integer NOT NULL DEFAULT 5 CHECK (minimum_observations > 0),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE baseline_candidates (
    candidate_id         bigserial PRIMARY KEY,
    agent_id             text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    rule_id              text,
    candidate_type       text NOT NULL,
    candidate_key        text NOT NULL,
    evidence_json        jsonb NOT NULL DEFAULT '{}'::jsonb,
    observation_count    bigint NOT NULL DEFAULT 1 CHECK (observation_count > 0),
    first_seen           timestamptz NOT NULL DEFAULT now(),
    last_seen            timestamptz NOT NULL DEFAULT now(),
    status               text NOT NULL DEFAULT 'CANDIDATE'
                         CHECK (status IN ('CANDIDATE','APPROVED','REJECTED')),
    UNIQUE(agent_id, candidate_type, candidate_key)
);

COMMENT ON TABLE finding_feedback IS
    'Analyst feedback retained independently of exact finding suppression so RM3 tuning can learn from false positives.';
COMMENT ON TABLE rule_overrides IS
    'Staged/approved GLOBAL, GROUP, or ENDPOINT rule deltas; delivery/effective-policy wiring is introduced in later RM3 slices.';
COMMENT ON TABLE endpoint_learning_state IS
    'Explicit endpoint learning lifecycle; learning never silently promotes behavior into trusted policy.';
COMMENT ON TABLE baseline_candidates IS
    'Observed baseline proposals requiring explicit approval before they can affect detection policy.';
