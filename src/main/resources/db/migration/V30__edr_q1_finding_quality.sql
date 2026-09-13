-- EDR-Q1: severity differentiation, deterministic risk scoring, and candidate promotion.
--
-- Rule severity remains a trusted evaluator input (low/medium/high). Findings gain an
-- independent five-level effective severity and risk score. Weak signals remain stored
-- as CANDIDATE so they can participate in bounded correlation without flooding the
-- default ACTIVE Findings view.

ALTER TABLE findings
    ADD COLUMN base_severity text,
    ADD COLUMN risk_score integer;

ALTER TABLE findings
    ADD CONSTRAINT findings_base_severity_values
        CHECK (base_severity IS NULL OR lower(base_severity) IN ('info','low','medium','high','critical')),
    ADD CONSTRAINT findings_effective_severity_values
        CHECK (severity IS NULL OR lower(severity) IN ('info','low','medium','high','critical')),
    ADD CONSTRAINT findings_risk_score_range
        CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100));

-- Reclassify the default catalog conservatively. Strong authenticated TLS identity
-- failures remain HIGH. Single behavioral/network anomalies become LOW candidates;
-- elevation and DNS/connection mismatch remain MEDIUM. Historical rule revisions are
-- immutable: each current DEFAULT rule receives a new revision.
WITH latest AS (
    SELECT DISTINCT ON (rule_id)
           rule_id,revision,origin,engine_rule_id,name,category,enabled,
           parameters_json,exclusions_json
      FROM rule_definitions
     WHERE origin='DEFAULT'
     ORDER BY rule_id,revision DESC
), classified AS (
    SELECT l.*,
           CASE l.rule_id
             WHEN 'TRUST-001' THEN 'high'
             WHEN 'TRUST-002' THEN 'high'
             WHEN 'TLS-001'   THEN 'high'
             WHEN 'TLS-002'   THEN 'high'
             WHEN 'PROC-003'  THEN 'medium'
             WHEN 'DNS-002'   THEN 'medium'
             ELSE 'low'
           END AS next_severity
      FROM latest l
     WHERE l.rule_id IN (
        'PERF-001','TRUST-001','TRUST-002',
        'PROC-001','PROC-002','PROC-003','PROC-004','PROC-005',
        'BEH-001','NET-001','NET-002','NET-003','NET-004',
        'DNS-001','DNS-002','DNS-003','TLS-001','TLS-002','ROUTE-001')
)
INSERT INTO rule_definitions(
    rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,
    parameters_json,exclusions_json,created_by)
SELECT rule_id,revision+1,origin,engine_rule_id,name,category,next_severity,enabled,
       parameters_json,exclusions_json,'system:edr-q1'
  FROM classified;

-- Existing findings inherit the latest trusted rule classification where possible.
-- Unattributed historical findings keep their stored severity as the base input.
UPDATE findings f
   SET base_severity=COALESCE(
       (SELECT rd.severity
          FROM rule_definitions rd
         WHERE rd.rule_id=f.rule_id
         ORDER BY rd.revision DESC
         LIMIT 1),
       NULLIF(lower(f.severity),''),
       'medium');

-- Supersede the previously hashed policy bytes. RuleSetBootstrap publishes a fresh
-- immutable bundle from the new catalog on coordinator startup.
UPDATE rule_sets SET status='SUPERSEDED' WHERE status='ACTIVE';
UPDATE agent_rule_state
   SET desired_revision=NULL,
       desired_sha256=NULL,
       status=CASE WHEN status='APPLY_FAILED' THEN status ELSE 'STALE' END,
       updated_at=now();

-- Replace RM3.7/RM4.3 confidence refresh with the EDR-Q1 model. Candidate and ACTIVE
-- findings both participate in correlation. Artifact/YARA corroboration from RM4.3 is
-- retained exactly as a separate independent signal.
CREATE OR REPLACE FUNCTION neta_refresh_finding_confidence(p_agent_id text)
RETURNS void
LANGUAGE sql
AS $$
WITH candidates AS (
    SELECT f.finding_id,
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
           + CASE WHEN f.observed_from IS NOT NULL AND f.observed_to IS NOT NULL THEN 3 ELSE 0 END AS base_risk,
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
           + CASE WHEN f.observed_from IS NOT NULL AND f.observed_to IS NOT NULL THEN 0.03 ELSE 0 END AS base_confidence,
           coalesce(r.rule_corroborators,'[]'::jsonb) AS rule_corroborators,
           coalesce(r.rule_corroboration_count,0) AS rule_corroboration_count,
           coalesce(a.artifact_corroborators,'[]'::jsonb) AS artifact_corroborators,
           coalesce(a.artifact_corroboration_count,0) AS artifact_corroboration_count
      FROM findings f
      LEFT JOIN LATERAL (
          SELECT NULLIF(btrim(substring(value FROM char_length('Process image:') + 1)), '') AS process_image
            FROM jsonb_array_elements_text(
                 CASE WHEN jsonb_typeof(f.changes)='array' THEN f.changes ELSE '[]'::jsonb END
            ) value
           WHERE value ILIKE 'Process image:%'
           LIMIT 1
      ) p ON true
      LEFT JOIN LATERAL (
          SELECT jsonb_agg(x.rule_id ORDER BY x.rule_id) AS rule_corroborators,
                 count(*)::integer AS rule_corroboration_count
            FROM (
                SELECT DISTINCT other.rule_id
                  FROM findings other
                 WHERE other.agent_id=f.agent_id
                   AND other.finding_id<>f.finding_id
                   AND other.status IN ('ACTIVE','CANDIDATE')
                   AND other.rule_id IS NOT NULL
                   AND f.rule_id IS NOT NULL
                   AND other.rule_id<>f.rule_id
                   AND other.last_seen BETWEEN f.last_seen - interval '120 seconds'
                                           AND f.last_seen + interval '120 seconds'
                   AND (
                        (f.subject_id IS NOT NULL AND other.subject_id=f.subject_id)
                        OR
                        (f.target_host IS NOT NULL AND other.target_host=f.target_host)
                   )
            ) x
      ) r ON true
      LEFT JOIN LATERAL (
          SELECT jsonb_agg(x.signal ORDER BY x.signal) AS artifact_corroborators,
                 count(*)::integer AS artifact_corroboration_count
            FROM (
                SELECT DISTINCT
                       'ARTIFACT:' || ae.provider_name || ':' ||
                       coalesce(nullif(ae.ruleset_id,''), substr(ae.ruleset_sha256,1,16)) AS signal
                  FROM artifact_evidence ae
                 WHERE ae.agent_id=f.agent_id
                   AND upper(ae.scan_state)='MATCH'
                   AND p.process_image IS NOT NULL
                   AND ae.artifact_path=p.process_image
                   AND coalesce(ae.observed_at,ae.last_seen)
                       BETWEEN f.last_seen - interval '120 seconds'
                           AND f.last_seen + interval '120 seconds'
                   AND jsonb_typeof(ae.matches)='array'
                   AND jsonb_array_length(ae.matches)>0
            ) x
      ) a ON true
     WHERE f.agent_id=p_agent_id
       AND f.status IN ('ACTIVE','CANDIDATE')
       AND f.last_seen >= now() - interval '10 minutes'
), scored AS (
    SELECT finding_id,
           least(100, base_risk + least(24,(rule_corroboration_count + artifact_corroboration_count) * 12))::integer AS risk,
           least(0.99, base_confidence + least(0.24,(rule_corroboration_count + artifact_corroboration_count) * 0.10)) AS confidence,
           rule_corroborators || artifact_corroborators AS corroborators,
           rule_corroboration_count,
           artifact_corroboration_count,
           rule_corroboration_count + artifact_corroboration_count AS corroboration_count
      FROM candidates
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
       corroboration_count=s.corroboration_count,
       corroborated_by=s.corroborators,
       confidence_reasons=jsonb_build_array(
           'EDR-Q1 deterministic risk from base rule severity and evidence quality',
           'base severity: ' || lower(coalesce(f.base_severity,'medium')),
           'risk score: ' || s.risk::text || '/100',
           CASE WHEN s.risk>=55 THEN 'promoted to actionable finding' ELSE 'retained as correlation candidate' END,
           CASE WHEN f.evidence_root IS NOT NULL AND f.evidence_root<>'' THEN 'evidence root present' ELSE 'evidence root absent' END,
           CASE WHEN f.rule_set IS NOT NULL THEN 'rule-set provenance present' ELSE 'rule-set provenance absent' END,
           CASE WHEN f.observed_from IS NOT NULL AND f.observed_to IS NOT NULL THEN 'bounded observation window present' ELSE 'observation window incomplete' END,
           CASE WHEN s.rule_corroboration_count>0
                THEN s.rule_corroboration_count::text || ' independent finding rule signal(s) corroborated within 120 seconds'
                ELSE 'no independent finding rule signal within 120 seconds' END,
           CASE WHEN s.artifact_corroboration_count>0
                THEN s.artifact_corroboration_count::text || ' matched artifact provider/ruleset signal(s) corroborated by exact process image within 120 seconds'
                ELSE 'no matched artifact signal correlated by exact process image within 120 seconds' END
       )
  FROM scored s
 WHERE f.finding_id=s.finding_id;
$$;

-- Avoid recursive refresh when the scorer changes effective severity/status itself.
DROP TRIGGER IF EXISTS findings_rm37_confidence_refresh ON findings;
CREATE TRIGGER findings_rm37_confidence_refresh
AFTER INSERT OR UPDATE OF last_seen,rule_id,subject_id,target_host,evidence_root,rule_set,base_severity
ON findings
FOR EACH ROW EXECUTE FUNCTION neta_findings_confidence_trigger();

CREATE INDEX findings_edrq1_candidate_idx
    ON findings(agent_id,last_seen DESC,rule_id,subject_id,target_host)
    WHERE status='CANDIDATE';

-- Re-score the existing fleet immediately. Historical weak rule matches become
-- candidates, while medium/high or corroborated evidence remains actionable.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT DISTINCT agent_id FROM findings WHERE status IN ('ACTIVE','CANDIDATE') LOOP
    PERFORM neta_refresh_finding_confidence(r.agent_id);
  END LOOP;
END $$;
