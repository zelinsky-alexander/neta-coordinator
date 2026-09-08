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

-- A disposition is an exact agent+finding-key suppression policy, not a trash
-- copy. The original finding payload is deleted. Future announcements with the
-- same exact key are still accepted at the protocol/audit layer, but do not
-- recreate an active finding row.
CREATE OR REPLACE FUNCTION neta_skip_operator_suppressed_finding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM finding_suppressions s
        WHERE s.agent_id=NEW.agent_id AND s.finding_key=NEW.finding_key
    ) THEN
        RETURN NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS findings_operator_suppression_guard ON findings;
CREATE TRIGGER findings_operator_suppression_guard
BEFORE INSERT OR UPDATE OF agent_id,finding_key ON findings
FOR EACH ROW
EXECUTE FUNCTION neta_skip_operator_suppressed_finding();
