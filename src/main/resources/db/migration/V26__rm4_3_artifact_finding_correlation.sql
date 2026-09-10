-- RM4.3: correlate persisted artifact/YARA evidence with process/network findings.
--
-- This extends the deterministic RM3.7 confidence model without turning artifact
-- evidence into an authoritative verdict. A MATCH is one additional independent
-- corroborating signal per provider/ruleset when it is bound to the same endpoint,
-- exact process image path, and a bounded 120-second window.

CREATE INDEX IF NOT EXISTS artifact_evidence_rm43_correlation_idx
    ON artifact_evidence(agent_id, artifact_path, last_seen DESC)
    WHERE upper(scan_state) = 'MATCH';

CREATE OR REPLACE FUNCTION neta_refresh_finding_confidence(p_agent_id text)
RETURNS void
LANGUAGE sql
AS $$
WITH candidates AS (
    SELECT f.finding_id,
           CASE lower(coalesce(f.severity,'medium'))
             WHEN 'high' THEN 0.72
             WHEN 'medium' THEN 0.60
             WHEN 'low' THEN 0.50
             ELSE 0.55
           END
           + CASE WHEN f.evidence_root IS NOT NULL AND f.evidence_root<>'' THEN 0.05 ELSE 0 END
           + CASE WHEN f.rule_set IS NOT NULL THEN 0.04 ELSE 0 END
           + CASE WHEN f.observed_from IS NOT NULL AND f.observed_to IS NOT NULL THEN 0.03 ELSE 0 END AS base_score,
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
                   AND other.status='ACTIVE'
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
       AND f.status='ACTIVE'
       AND f.last_seen >= now() - interval '10 minutes'
), scored AS (
    SELECT finding_id,
           least(0.99,
                 base_score +
                 least(0.24,(rule_corroboration_count + artifact_corroboration_count) * 0.10)) AS score,
           rule_corroborators || artifact_corroborators AS corroborators,
           rule_corroboration_count,
           artifact_corroboration_count,
           rule_corroboration_count + artifact_corroboration_count AS corroboration_count
      FROM candidates
)
UPDATE findings f
   SET confidence_score=s.score,
       confidence_level=CASE WHEN s.score>=0.80 THEN 'HIGH' WHEN s.score>=0.60 THEN 'MEDIUM' ELSE 'LOW' END,
       corroboration_count=s.corroboration_count,
       corroborated_by=s.corroborators,
       confidence_reasons=jsonb_build_array(
           'deterministic base confidence from severity',
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

CREATE OR REPLACE FUNCTION neta_artifact_confidence_trigger()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF upper(NEW.scan_state)='MATCH' THEN
        PERFORM neta_refresh_finding_confidence(NEW.agent_id);
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS artifact_rm43_confidence_refresh ON artifact_evidence;
CREATE TRIGGER artifact_rm43_confidence_refresh
AFTER INSERT OR UPDATE OF artifact_path,scan_state,matches,observed_at,last_seen,observation_count
ON artifact_evidence
FOR EACH ROW EXECUTE FUNCTION neta_artifact_confidence_trigger();

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT DISTINCT agent_id FROM findings WHERE status='ACTIVE' LOOP
    PERFORM neta_refresh_finding_confidence(r.agent_id);
  END LOOP;
END $$;
