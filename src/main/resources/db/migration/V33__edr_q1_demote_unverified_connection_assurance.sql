-- EDR-Q1 regression fix: a generic connection-assurance observation with no attributed
-- trusted rule, UNVERIFIED trust, and no degraded/failed performance is not an actionable
-- security finding. It remains retained as low-value correlation evidence, but must not
-- reappear in the default ACTIVE Findings view merely because it has a stable evidence hash.

CREATE OR REPLACE FUNCTION neta_assign_finding_base_severity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    policy_severity text;
    generic_unverified_connection boolean;
BEGIN
    generic_unverified_connection :=
        (NEW.rule_id IS NULL OR btrim(NEW.rule_id) = '')
        AND upper(coalesce(NEW.trust_verdict,'')) = 'UNVERIFIED'
        AND upper(coalesce(NEW.performance_verdict,'')) NOT IN ('DEGRADED','FAILED')
        AND (
            NEW.finding_id LIKE 'FINDING-CONN-%'
            OR EXISTS (
                SELECT 1
                  FROM jsonb_array_elements_text(
                       CASE WHEN jsonb_typeof(NEW.changes)='array' THEN NEW.changes ELSE '[]'::jsonb END
                  ) entry
                 WHERE entry ILIKE 'Stored connection assurance observation%'
            )
        );

    IF generic_unverified_connection THEN
        NEW.base_severity := 'info';
        RETURN NEW;
    END IF;

    IF NEW.rule_id IS NOT NULL AND btrim(NEW.rule_id) <> '' THEN
        SELECT rd.severity
          INTO policy_severity
          FROM rule_definitions rd
         WHERE rd.rule_id=NEW.rule_id
         ORDER BY rd.revision DESC
         LIMIT 1;
    END IF;
    NEW.base_severity := COALESCE(policy_severity, NEW.base_severity, NULLIF(lower(NEW.severity),''), 'medium');
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS findings_edrq1_base_severity ON findings;
CREATE TRIGGER findings_edrq1_base_severity
BEFORE INSERT OR UPDATE OF rule_id,trust_verdict,performance_verdict,changes
ON findings
FOR EACH ROW EXECUTE FUNCTION neta_assign_finding_base_severity();

-- Correct already persisted rows, including older rows outside the live 10-minute
-- correlation window. These are evidence/candidates, not incidents by themselves.
WITH noisy AS (
    SELECT f.finding_id,
           least(100,
               20
               + CASE WHEN f.evidence_root IS NOT NULL AND f.evidence_root<>'' THEN 5 ELSE 0 END
               + CASE WHEN f.rule_set IS NOT NULL THEN 5 ELSE 0 END
               + CASE WHEN f.observed_from IS NOT NULL AND f.observed_to IS NOT NULL THEN 3 ELSE 0 END
           )::integer AS risk,
           least(0.99,
               0.30
               + CASE WHEN f.evidence_root IS NOT NULL AND f.evidence_root<>'' THEN 0.05 ELSE 0 END
               + CASE WHEN f.rule_set IS NOT NULL THEN 0.04 ELSE 0 END
               + CASE WHEN f.observed_from IS NOT NULL AND f.observed_to IS NOT NULL THEN 0.03 ELSE 0 END
           ) AS confidence
      FROM findings f
     WHERE (f.rule_id IS NULL OR btrim(f.rule_id)='')
       AND upper(coalesce(f.trust_verdict,''))='UNVERIFIED'
       AND upper(coalesce(f.performance_verdict,'')) NOT IN ('DEGRADED','FAILED')
       AND (
           f.finding_id LIKE 'FINDING-CONN-%'
           OR EXISTS (
               SELECT 1
                 FROM jsonb_array_elements_text(
                      CASE WHEN jsonb_typeof(f.changes)='array' THEN f.changes ELSE '[]'::jsonb END
                 ) entry
                WHERE entry ILIKE 'Stored connection assurance observation%'
           )
       )
)
UPDATE findings f
   SET base_severity='info',
       risk_score=n.risk,
       severity=CASE WHEN n.risk>=30 THEN 'low' ELSE 'info' END,
       status='CANDIDATE',
       confidence_score=n.confidence,
       confidence_level=CASE WHEN n.confidence>=0.80 THEN 'HIGH'
                             WHEN n.confidence>=0.60 THEN 'MEDIUM'
                             ELSE 'LOW' END,
       corroboration_count=0,
       corroborated_by='[]'::jsonb,
       confidence_reasons=jsonb_build_array(
           'EDR-Q1 generic connection-assurance observation retained as candidate',
           'UNVERIFIED trust alone is not a security finding',
           'no degraded or failed performance verdict',
           'risk score: ' || n.risk::text || '/100'
       )
  FROM noisy n
 WHERE f.finding_id=n.finding_id;
