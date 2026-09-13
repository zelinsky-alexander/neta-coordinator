-- EDR-Q1 follow-through: make coordinator policy authoritative for base severity even
-- while endpoints are converging on the freshly published central bundle, and classify
-- older active findings that are intentionally outside the 10-minute live refresh window.

CREATE OR REPLACE FUNCTION neta_assign_finding_base_severity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    policy_severity text;
BEGIN
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
BEFORE INSERT OR UPDATE OF rule_id
ON findings
FOR EACH ROW EXECUTE FUNCTION neta_assign_finding_base_severity();

-- Old findings do not need to remain actionable forever merely because they predate
-- Q1. Preserve previously recorded corroboration count as historical evidence, but
-- apply the same deterministic base/evidence risk model used for live findings.
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
     WHERE f.status='ACTIVE'
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
           'EDR-Q1 historical backfill applied',
           'risk score: ' || s.risk::text || '/100',
           CASE WHEN s.risk>=55 THEN 'retained as actionable finding' ELSE 'retained as correlation candidate' END)
  FROM scored s
 WHERE f.finding_id=s.finding_id;
