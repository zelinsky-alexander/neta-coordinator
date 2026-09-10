-- Canonical rule identifier cleanup: drop the redundant NETA- prefix everywhere in live policy state,
-- and rename custom CUS-* identifiers to CST-*.
-- Historical payload/evidence JSON is intentionally left byte-for-byte unchanged; canonical columns and all new policy use short IDs.

UPDATE rule_definitions
SET rule_id = CASE
        WHEN rule_id LIKE 'NETA-%' THEN substring(rule_id FROM 6)
        WHEN rule_id LIKE 'CUS-%' THEN 'CST-' || substring(rule_id FROM 5)
        ELSE rule_id
    END,
    engine_rule_id = CASE
        WHEN engine_rule_id LIKE 'NETA-%' THEN substring(engine_rule_id FROM 6)
        WHEN engine_rule_id LIKE 'CUS-%' THEN 'CST-' || substring(engine_rule_id FROM 5)
        ELSE engine_rule_id
    END;

UPDATE findings
SET rule_id = CASE
        WHEN rule_id LIKE 'NETA-%' THEN substring(rule_id FROM 6)
        WHEN rule_id LIKE 'CUS-%' THEN 'CST-' || substring(rule_id FROM 5)
        ELSE rule_id
    END
WHERE rule_id IS NOT NULL;

UPDATE finding_suppressions
SET rule_id = CASE
        WHEN rule_id LIKE 'NETA-%' THEN substring(rule_id FROM 6)
        WHEN rule_id LIKE 'CUS-%' THEN 'CST-' || substring(rule_id FROM 5)
        ELSE rule_id
    END
WHERE rule_id IS NOT NULL;

UPDATE finding_feedback
SET rule_id = CASE
        WHEN rule_id LIKE 'NETA-%' THEN substring(rule_id FROM 6)
        WHEN rule_id LIKE 'CUS-%' THEN 'CST-' || substring(rule_id FROM 5)
        ELSE rule_id
    END
WHERE rule_id IS NOT NULL;

UPDATE rule_overrides
SET rule_id = CASE
        WHEN rule_id LIKE 'NETA-%' THEN substring(rule_id FROM 6)
        WHEN rule_id LIKE 'CUS-%' THEN 'CST-' || substring(rule_id FROM 5)
        ELSE rule_id
    END;

UPDATE baseline_candidates
SET rule_id = CASE
        WHEN rule_id LIKE 'NETA-%' THEN substring(rule_id FROM 6)
        WHEN rule_id LIKE 'CUS-%' THEN 'CST-' || substring(rule_id FROM 5)
        ELSE rule_id
    END
WHERE rule_id IS NOT NULL;

-- Existing published bundles contain the old identifiers and their SHA-256 covers those exact bytes.
-- Supersede them instead of mutating hashed historical policy material. RuleSetBootstrap will publish
-- a fresh short-ID bundle from the migrated catalog at startup.
UPDATE rule_sets SET status='SUPERSEDED' WHERE status='ACTIVE';
UPDATE agent_rule_state
SET desired_revision=NULL, desired_sha256=NULL,
    status=CASE WHEN status='APPLY_FAILED' THEN status ELSE 'STALE' END,
    updated_at=now();
