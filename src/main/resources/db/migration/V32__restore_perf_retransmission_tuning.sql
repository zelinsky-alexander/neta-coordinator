-- EDR-Q1 follow-up: preserve the earlier PERF-001 false-positive tuning after
-- severity reclassification created a new canonical rule revision.
--
-- PERF-001 should remain LOW under EDR-Q1, but retransmission_threshold must stay
-- aligned with NET-002 at 5 instead of regressing to the original value of 2.

INSERT INTO rule_definitions(
    rule_id, revision, origin, engine_rule_id, name, category, severity, enabled,
    parameters_json, exclusions_json, created_by)
SELECT
    rule_id,
    latest.revision + 1,
    origin,
    engine_rule_id,
    name,
    category,
    severity,
    enabled,
    jsonb_set(parameters_json, '{retransmission_threshold}', '5'::jsonb, true),
    exclusions_json,
    'system:edr-q1-perf-retune'
FROM (
    SELECT DISTINCT ON (rule_id)
           rule_id, revision, origin, engine_rule_id, name, category, severity,
           enabled, parameters_json, exclusions_json
      FROM rule_definitions
     WHERE rule_id = 'PERF-001'
     ORDER BY rule_id, revision DESC
) latest
WHERE coalesce((parameters_json->>'retransmission_threshold')::integer, 0) <> 5
ON CONFLICT (rule_id, revision) DO NOTHING;

-- Force coordinator bootstrap to publish a fresh immutable bundle on restart.
UPDATE rule_sets
   SET status='SUPERSEDED'
 WHERE status='ACTIVE'
   AND EXISTS (
       SELECT 1
         FROM jsonb_array_elements(bundle_json->'rules') rule
        WHERE rule->>'id'='PERF-001'
          AND coalesce((rule->'parameters'->>'retransmission_threshold')::integer,0) <> 5
   );

UPDATE agent_rule_state
   SET desired_revision=NULL,
       desired_sha256=NULL,
       status=CASE WHEN status='APPLY_FAILED' THEN status ELSE 'STALE' END,
       updated_at=now()
 WHERE EXISTS (
       SELECT 1 FROM rule_sets rs
        WHERE rs.status='SUPERSEDED'
          AND EXISTS (
              SELECT 1
                FROM jsonb_array_elements(rs.bundle_json->'rules') rule
               WHERE rule->>'id'='PERF-001'
                 AND coalesce((rule->'parameters'->>'retransmission_threshold')::integer,0) <> 5
          )
   );
