-- RM3.7: deterministic, explainable confidence and bounded multi-signal corroboration.
-- Confidence is derived only from stored finding evidence and nearby independent rule matches.

ALTER TABLE findings
    ADD COLUMN confidence_score numeric(4,3),
    ADD COLUMN confidence_level text,
    ADD COLUMN corroboration_count integer NOT NULL DEFAULT 0,
    ADD COLUMN corroborated_by jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN confidence_reasons jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE findings
    ADD CONSTRAINT findings_confidence_score_range
        CHECK (confidence_score IS NULL OR (confidence_score >= 0 AND confidence_score <= 1)),
    ADD CONSTRAINT findings_confidence_level_values
        CHECK (confidence_level IS NULL OR confidence_level IN ('LOW','MEDIUM','HIGH')),
    ADD CONSTRAINT findings_corroboration_count_nonnegative
        CHECK (corroboration_count >= 0);

CREATE INDEX findings_rm37_correlation_idx
    ON findings(agent_id,last_seen DESC,rule_id,subject_id,target_host)
    WHERE status='ACTIVE';

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
           coalesce(c.corroborators,'[]'::jsonb) AS corroborators,
           coalesce(c.corroboration_count,0) AS corroboration_count
      FROM findings f
      LEFT JOIN LATERAL (
          SELECT jsonb_agg(x.rule_id ORDER BY x.rule_id) AS corroborators,
                 count(*)::integer AS corroboration_count
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
      ) c ON true
     WHERE f.agent_id=p_agent_id
       AND f.status='ACTIVE'
       AND f.last_seen >= now() - interval '10 minutes'
), scored AS (
    SELECT finding_id,
           least(0.99,base_score + least(0.24,corroboration_count * 0.10)) AS score,
           corroborators,corroboration_count
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
           CASE WHEN s.corroboration_count>0
                THEN s.corroboration_count::text || ' independent rule signal(s) corroborated within 120 seconds'
                ELSE 'no independent corroborating rule signal within 120 seconds' END
       )
  FROM scored s
 WHERE f.finding_id=s.finding_id;
$$;

CREATE OR REPLACE FUNCTION neta_findings_confidence_trigger()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM neta_refresh_finding_confidence(NEW.agent_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER findings_rm37_confidence_refresh
AFTER INSERT OR UPDATE OF last_seen,rule_id,severity,subject_id,target_host,evidence_root,rule_set,status
ON findings
FOR EACH ROW EXECUTE FUNCTION neta_findings_confidence_trigger();

-- Backfill existing active findings deterministically.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT DISTINCT agent_id FROM findings LOOP
    PERFORM neta_refresh_finding_confidence(r.agent_id);
  END LOOP;
END $$;
