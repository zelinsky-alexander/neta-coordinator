-- RM2 extends the centrally managed catalog beyond process rules. Existing
-- RM1 rows remain immutable; these are new trusted evaluator definitions.
INSERT INTO rule_definitions(rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,parameters_json)
VALUES
('NETA-BEH-001',1,'DEFAULT','NETA-BEH-001','Periodic outbound connection pattern','behavior','medium',true,
 '{"minimum_connections":8,"window_ms":90000,"minimum_interval_ms":3000,"maximum_interval_ms":15000,"interval_tolerance_ratio":0.20,"minimum_regular_fraction":0.80,"recent_connection_limit":512}'::jsonb),
('NETA-NET-001',1,'DEFAULT','NETA-NET-001','Large ingress transfer','network','low',true,
 '{"minimum_bytes_received":268435456}'::jsonb),
('NETA-NET-002',1,'DEFAULT','NETA-NET-002','TCP retransmission spike','network','medium',true,
 '{"retransmission_threshold":5}'::jsonb),
('NETA-NET-003',1,'DEFAULT','NETA-NET-003','Unusual outbound destination port','network','low',false,
 '{"allowed_ports":["22","25","53","80","110","123","143","443","465","587","853","993","995","3389"]}'::jsonb),
('NETA-NET-004',1,'DEFAULT','NETA-NET-004','Rare outbound destination','network','medium',false,
 '{"maximum_prevalence":2}'::jsonb),
('NETA-DNS-001',1,'DEFAULT','NETA-DNS-001','Repeated DNS resolution failures','dns','medium',true,
 '{"minimum_failures":3}'::jsonb),
('NETA-DNS-002',1,'DEFAULT','NETA-DNS-002','DNS answer and connection mismatch','dns','medium',true,
 '{"require_remote_ip_match":true}'::jsonb),
('NETA-DNS-003',1,'DEFAULT','NETA-DNS-003','DNS answer churn','dns','low',false,
 '{"maximum_distinct_answers":12}'::jsonb),
('NETA-TLS-001',1,'DEFAULT','NETA-TLS-001','Application TLS validation failure','tls','high',true,
 '{"require_peer_authentication":true,"verification_failure_match":true}'::jsonb),
('NETA-TLS-002',1,'DEFAULT','NETA-TLS-002','TLS peer identity change','tls','high',true,
 '{"compare_spki":true,"compare_issuer":true}'::jsonb),
('NETA-ROUTE-001',1,'DEFAULT','NETA-ROUTE-001','Unexpected route gateway or interface','route','medium',false,
 '{"allowed_gateways":[],"allowed_interfaces":[]}'::jsonb);
