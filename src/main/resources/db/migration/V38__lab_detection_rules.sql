-- Production transfer-asymmetry detection used by the lab acceptance catalog.
-- The threshold remains a production rule parameter and is not keyed to a lab id.
INSERT INTO rule_definitions(
    rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,parameters_json)
VALUES (
    'NET-005',1,'DEFAULT','NET-005','High outbound transfer asymmetry',
    'network','low',true,
    '{"minimum_bytes_sent":33554432,"minimum_sent_to_received_ratio":8.0,"received_bytes_floor":65536}'::jsonb)
ON CONFLICT (rule_id,revision) DO NOTHING;

-- Force bootstrap to publish a bundle containing the new trusted engine.
UPDATE rule_sets SET status='SUPERSEDED' WHERE status='ACTIVE';
UPDATE agent_rule_state
SET desired_revision=NULL, desired_sha256=NULL,
    status=CASE WHEN status='APPLY_FAILED' THEN status ELSE 'STALE' END,
    updated_at=now();
