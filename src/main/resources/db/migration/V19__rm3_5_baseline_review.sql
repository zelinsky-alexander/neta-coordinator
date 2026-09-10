-- RM3.5: analyst-reviewed baseline promotion metadata.
-- Approved candidates are traceable to the endpoint-scoped effective policy delta
-- that implements the approved expectation. Rejected candidates never affect policy.

ALTER TABLE baseline_candidates
    ADD COLUMN IF NOT EXISTS reviewed_at timestamptz,
    ADD COLUMN IF NOT EXISTS reviewed_by text,
    ADD COLUMN IF NOT EXISTS review_reason text;

ALTER TABLE rule_overrides
    ADD COLUMN IF NOT EXISTS source_baseline_candidate_id bigint
        REFERENCES baseline_candidates(candidate_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS rule_overrides_baseline_candidate_idx
    ON rule_overrides(source_baseline_candidate_id)
    WHERE source_baseline_candidate_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS baseline_candidates_review_queue_idx
    ON baseline_candidates(agent_id, status, observation_count DESC, last_seen DESC);

COMMENT ON COLUMN rule_overrides.source_baseline_candidate_id IS
    'RM3.5 provenance link from an explicitly analyst-approved baseline candidate to its endpoint policy delta.';
