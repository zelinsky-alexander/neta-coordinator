-- RM3.4: collect repeated endpoint behavior into review-only baseline candidates.
-- Learning never suppresses a finding or changes active detection policy.

CREATE INDEX IF NOT EXISTS baseline_candidates_agent_status_count_idx
    ON baseline_candidates(agent_id, status, observation_count DESC, last_seen DESC);

CREATE OR REPLACE FUNCTION neta_collect_learning_candidate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    learning endpoint_learning_state%ROWTYPE;
    process_image text;
    parent_image text;
    remote_key text;
    evidence jsonb;
BEGIN
    SELECT * INTO learning
    FROM endpoint_learning_state
    WHERE agent_id = NEW.agent_id
      AND mode IN ('LEARNING','REVIEW')
      AND started_at IS NOT NULL
      AND (learning_until IS NULL OR learning_until >= now());

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF NEW.subject_type = 'PROCESS' AND NEW.changes IS NOT NULL AND jsonb_typeof(NEW.changes) = 'array' THEN
        SELECT substring(value FROM char_length('Process image:') + 1)
          INTO process_image
          FROM jsonb_array_elements_text(NEW.changes) value
         WHERE value ILIKE 'Process image:%'
         LIMIT 1;
        SELECT substring(value FROM char_length('Parent image:') + 1)
          INTO parent_image
          FROM jsonb_array_elements_text(NEW.changes) value
         WHERE value ILIKE 'Parent image:%'
         LIMIT 1;

        process_image := NULLIF(btrim(process_image), '');
        parent_image := NULLIF(btrim(parent_image), '');
        IF process_image IS NOT NULL THEN
            evidence := jsonb_build_object(
                'process_image', process_image,
                'parent_image', parent_image,
                'source', 'finding-observation',
                'last_finding_id', NEW.finding_id,
                'last_rule_id', NEW.rule_id
            );
            INSERT INTO baseline_candidates(agent_id, rule_id, candidate_type, candidate_key,
                                            evidence_json, observation_count, first_seen, last_seen, status)
            VALUES (NEW.agent_id, NEW.rule_id, 'PROCESS_PARENT_CHILD',
                    coalesce(parent_image, '') || '->' || process_image,
                    evidence, 1, now(), now(), 'CANDIDATE')
            ON CONFLICT(agent_id, candidate_type, candidate_key) DO UPDATE SET
                rule_id = coalesce(EXCLUDED.rule_id, baseline_candidates.rule_id),
                evidence_json = EXCLUDED.evidence_json,
                observation_count = baseline_candidates.observation_count + 1,
                last_seen = now()
            WHERE baseline_candidates.status = 'CANDIDATE';
        END IF;
    END IF;

    IF NEW.target_host IS NOT NULL AND NEW.target_host <> '' THEN
        remote_key := lower(NEW.target_host) || ':' || coalesce(NEW.target_port::text, '*');
        evidence := jsonb_build_object(
            'remote_host', NEW.target_host,
            'remote_port', NEW.target_port,
            'source', 'finding-observation',
            'last_finding_id', NEW.finding_id,
            'last_rule_id', NEW.rule_id
        );
        INSERT INTO baseline_candidates(agent_id, rule_id, candidate_type, candidate_key,
                                        evidence_json, observation_count, first_seen, last_seen, status)
        VALUES (NEW.agent_id, NEW.rule_id, 'REMOTE_DESTINATION', remote_key,
                evidence, 1, now(), now(), 'CANDIDATE')
        ON CONFLICT(agent_id, candidate_type, candidate_key) DO UPDATE SET
            rule_id = coalesce(EXCLUDED.rule_id, baseline_candidates.rule_id),
            evidence_json = EXCLUDED.evidence_json,
            observation_count = baseline_candidates.observation_count + 1,
            last_seen = now()
        WHERE baseline_candidates.status = 'CANDIDATE';
    END IF;

    IF EXISTS (
        SELECT 1 FROM baseline_candidates c
        WHERE c.agent_id = NEW.agent_id
          AND c.status = 'CANDIDATE'
          AND c.observation_count >= learning.minimum_observations
    ) THEN
        UPDATE endpoint_learning_state
           SET mode = 'REVIEW', updated_at = now()
         WHERE agent_id = NEW.agent_id AND mode = 'LEARNING';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS findings_learning_candidate_trg ON findings;
CREATE TRIGGER findings_learning_candidate_trg
AFTER INSERT OR UPDATE OF occurrence_count, last_seen ON findings
FOR EACH ROW EXECUTE FUNCTION neta_collect_learning_candidate();

COMMENT ON FUNCTION neta_collect_learning_candidate() IS
    'RM3.4 observation-only aggregation. Candidates require later analyst approval and never alter detection by themselves.';
