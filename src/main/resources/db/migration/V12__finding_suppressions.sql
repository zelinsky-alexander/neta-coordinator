-- Operator disposition for exact findings. The finding/evidence row is deleted;
-- only the minimal suppression key and operator reason remain so the same
-- agent finding does not immediately reappear on the next announcement.
CREATE TABLE finding_suppressions (
    suppression_id bigserial PRIMARY KEY,
    agent_id text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    finding_key text NOT NULL,
    disposition text NOT NULL CHECK (disposition IN ('SUPPRESSED','FALSE_POSITIVE')),
    reason text NOT NULL,
    rule_id text,
    subject_type text,
    subject_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(agent_id, finding_key)
);

CREATE INDEX finding_suppressions_created_idx
    ON finding_suppressions(created_at DESC);
CREATE INDEX finding_suppressions_rule_idx
    ON finding_suppressions(rule_id, created_at DESC);
