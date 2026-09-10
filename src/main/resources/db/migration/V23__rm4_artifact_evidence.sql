CREATE TABLE artifact_evidence (
    evidence_id          BIGSERIAL PRIMARY KEY,
    agent_id             TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    message_id           TEXT,
    artifact_sha256      TEXT NOT NULL,
    artifact_path        TEXT NOT NULL DEFAULT '',
    artifact_size        BIGINT,
    provider_name        TEXT NOT NULL,
    provider_version     TEXT NOT NULL DEFAULT '',
    ruleset_id           TEXT NOT NULL DEFAULT '',
    ruleset_sha256       TEXT NOT NULL DEFAULT '',
    scan_state           TEXT NOT NULL,
    detail               TEXT NOT NULL DEFAULT '',
    matches              JSONB NOT NULL DEFAULT '[]'::jsonb,
    observed_at          TIMESTAMPTZ,
    first_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
    observation_count    BIGINT NOT NULL DEFAULT 1,
    UNIQUE(agent_id, artifact_sha256, provider_name, ruleset_sha256)
);

CREATE INDEX idx_artifact_evidence_recent
    ON artifact_evidence(last_seen DESC);
CREATE INDEX idx_artifact_evidence_agent_recent
    ON artifact_evidence(agent_id,last_seen DESC);
CREATE INDEX idx_artifact_evidence_state
    ON artifact_evidence(scan_state,last_seen DESC);
CREATE INDEX idx_artifact_evidence_matches_gin
    ON artifact_evidence USING GIN(matches);

-- RM4.1 uses the existing NAP EvidenceSummary envelope. When an agent sends
-- summary.artifact_evidence[], project those normalized records into the
-- dedicated coordinator table without changing protocol framing.
CREATE OR REPLACE FUNCTION project_artifact_evidence_from_summary()
RETURNS trigger AS $$
DECLARE
    item JSONB;
BEGIN
    IF jsonb_typeof(NEW.summary->'artifact_evidence') <> 'array' THEN
        RETURN NEW;
    END IF;

    FOR item IN SELECT value FROM jsonb_array_elements(NEW.summary->'artifact_evidence') LOOP
        IF coalesce(item->>'artifact_sha256','') = '' OR coalesce(item->>'provider_name','') = '' THEN
            CONTINUE;
        END IF;

        INSERT INTO artifact_evidence(
            agent_id,message_id,artifact_sha256,artifact_path,artifact_size,
            provider_name,provider_version,ruleset_id,ruleset_sha256,scan_state,
            detail,matches,observed_at,first_seen,last_seen,observation_count)
        VALUES (
            NEW.agent_id,
            NEW.message_id,
            item->>'artifact_sha256',
            coalesce(item->>'artifact_path',''),
            CASE WHEN (item->>'artifact_size') ~ '^[0-9]+$' THEN (item->>'artifact_size')::bigint ELSE NULL END,
            item->>'provider_name',
            coalesce(item->>'provider_version',''),
            coalesce(item->>'ruleset_id',''),
            coalesce(item->>'ruleset_sha256',''),
            coalesce(item->>'scan_state','NOT_SCANNED'),
            coalesce(item->>'detail',''),
            CASE WHEN jsonb_typeof(item->'matches')='array' THEN item->'matches' ELSE '[]'::jsonb END,
            CASE WHEN coalesce(item->>'observed_at','') <> '' THEN (item->>'observed_at')::timestamptz ELSE NULL END,
            now(),now(),1)
        ON CONFLICT(agent_id,artifact_sha256,provider_name,ruleset_sha256) DO UPDATE SET
            message_id=EXCLUDED.message_id,
            artifact_path=EXCLUDED.artifact_path,
            artifact_size=EXCLUDED.artifact_size,
            provider_version=EXCLUDED.provider_version,
            ruleset_id=EXCLUDED.ruleset_id,
            scan_state=EXCLUDED.scan_state,
            detail=EXCLUDED.detail,
            matches=EXCLUDED.matches,
            observed_at=COALESCE(EXCLUDED.observed_at,artifact_evidence.observed_at),
            last_seen=now(),
            observation_count=artifact_evidence.observation_count+1;
    END LOOP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS evidence_summary_artifact_projection_trg ON evidence_summaries;
CREATE TRIGGER evidence_summary_artifact_projection_trg
AFTER INSERT ON evidence_summaries
FOR EACH ROW EXECUTE FUNCTION project_artifact_evidence_from_summary();
