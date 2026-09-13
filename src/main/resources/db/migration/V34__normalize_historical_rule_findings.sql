-- EDR-Q1 cleanup: older RM2 rule findings can have the trusted rule identity encoded
-- in finding_id (FINDING-RULE-<rule-id>-...) while rule_id is NULL. The portal then
-- falls back to CONNECTION_ASSURANCE even though the observation is actually a rule
-- finding (for example NET-004). Restore the canonical rule identity from the current
-- managed rule catalog, then apply the normal Q1 severity/promotion model.

WITH recovered AS (
    SELECT f.finding_id,
           (
               SELECT ids.rule_id
                 FROM (SELECT DISTINCT rule_id FROM rule_definitions WHERE rule_id IS NOT NULL) ids
                WHERE f.finding_id LIKE 'FINDING-RULE-' || ids.rule_id || '-%'
                ORDER BY char_length(ids.rule_id) DESC
                LIMIT 1
           ) AS recovered_rule_id
      FROM findings f
     WHERE (f.rule_id IS NULL OR btrim(f.rule_id)='')
       AND f.finding_id LIKE 'FINDING-RULE-%'
)
UPDATE findings f
   SET rule_id=r.recovered_rule_id
  FROM recovered r
 WHERE f.finding_id=r.finding_id
   AND r.recovered_rule_id IS NOT NULL;

-- Re-score historical rule findings outside the live 10-minute correlation window.
-- The rule_id update above invokes the base-severity trigger, so base_severity now
-- reflects the latest centrally managed policy (e.g. NET-004 => LOW). Preserve any
-- previously persisted corroboration count as supporting historical evidence.
WITH scored AS (
    SELECT f.finding_id,
           least(100,
             CASE lower(coalesce(f.base_severity,f.severity,'medium'))
               WHEN 'critical' THEN 92
               WHEN 'high' THEN 75
               WHEN 'medium' THEN 55
               WHEN 'low' THEN 35
               WHEN 'info' THEN 20
               ELSE 55
             END
             + CASE WHEN f.evidence_root IS NOT NULL AND f.evidence_root<>'' THEN 5 ELSE 0 END
             + CASE WHEN f.rule_set IS NOT NULL THEN 5 ELSE 0 END
             + CASE WHEN f.observed_from IS NOT NULL AND f.observed_to IS NOT NULL THEN 3 ELSE 0 END
             + least(24,coalesce(f.corroboration_count,0) * 12)
           )::integer AS risk,
           least(0.99,
             CASE lower(coalesce(f.base_severity,f.severity,'medium'))
               WHEN 'critical' THEN 0.88
               WHEN 'high' THEN 0.75
               WHEN 'medium' THEN 0.58
               WHEN 'low' THEN 0.42
               WHEN 'info' THEN 0.30
               ELSE 0.58
             END
             + CASE WHEN f.evidence_root IS NOT NULL AND f.evidence_root<>'' THEN 0.05 ELSE 0 END
             + CASE WHEN f.rule_set IS NOT NULL THEN 0.04 ELSE 0 END
             + CASE WHEN f.observed_from IS NOT NULL AND f.observed_to IS NOT NULL THEN 0.03 ELSE 0 END
             + least(0.24,coalesce(f.corroboration_count,0) * 0.10)
           ) AS confidence
      FROM findings f
     WHERE f.rule_id IS NOT NULL
       AND f.finding_id LIKE 'FINDING-RULE-%'
       AND f.status IN ('ACTIVE','CANDIDATE')
       AND f.last_seen < now() - interval '10 minutes'
)
UPDATE findings f
   SET risk_score=s.risk,
       severity=CASE WHEN s.risk>=95 THEN 'critical'
                     WHEN s.risk>=75 THEN 'high'
                     WHEN s.risk>=55 THEN 'medium'
                     WHEN s.risk>=30 THEN 'low'
                     ELSE 'info' END,
       status=CASE WHEN s.risk>=55 THEN 'ACTIVE' ELSE 'CANDIDATE' END,
       confidence_score=s.confidence,
       confidence_level=CASE WHEN s.confidence>=0.80 THEN 'HIGH'
                             WHEN s.confidence>=0.60 THEN 'MEDIUM'
                             ELSE 'LOW' END,
       confidence_reasons=coalesce(f.confidence_reasons,'[]'::jsonb) || jsonb_build_array(
           'EDR-Q1 historical rule identity normalized from finding id',
           'canonical rule id: ' || f.rule_id,
           'risk score: ' || s.risk::text || '/100',
           CASE WHEN s.risk>=55 THEN 'retained as actionable finding' ELSE 'retained as correlation candidate' END)
  FROM scored s
 WHERE f.finding_id=s.finding_id;
