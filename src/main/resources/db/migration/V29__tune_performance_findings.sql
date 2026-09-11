-- Historical generic connection-assurance findings with an explicit performance
-- hypothesis were emitted by the PERF-001 assurance rule. Preserve the evidence,
-- but expose the actual rule identity so the operator can filter and bulk-manage it.
UPDATE findings
SET rule_id = 'PERF-001',
    severity = COALESCE(NULLIF(severity, ''), 'medium')
WHERE (rule_id IS NULL OR btrim(rule_id) = '')
  AND upper(COALESCE(performance_verdict, '')) IN ('DEGRADED', 'FAILED')
  AND changes::text ILIKE '%Performance hypothesis: NETWORK_PATH_DEGRADATION%';

-- PERF-001 previously treated two retransmissions as a contributing spike while
-- the dedicated NET-002 retransmission rule uses five. Align the performance rule
-- with the dedicated network rule to reduce ordinary path-jitter findings without
-- disabling performance assurance or weakening TLS/DNS/process detections.
INSERT INTO rule_definitions(
    rule_id, revision, origin, engine_rule_id, name, category, severity, enabled,
    parameters_json, exclusions_json, created_by)
SELECT
    rule_id, 2, origin, engine_rule_id, name, category, severity, enabled,
    jsonb_set(parameters_json, '{retransmission_threshold}', '5'::jsonb, true),
    exclusions_json, 'system:perf-false-positive-tuning'
FROM rule_definitions
WHERE rule_id = 'NETA-PERF-001'
ORDER BY revision DESC
LIMIT 1
ON CONFLICT (rule_id, revision) DO NOTHING;
