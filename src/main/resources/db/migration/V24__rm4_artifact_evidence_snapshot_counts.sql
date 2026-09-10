CREATE OR REPLACE FUNCTION project_artifact_evidence_from_summary()
RETURNS trigger AS $$
DECLARE
    item JSONB;
    incoming_count BIGINT;
BEGIN
    IF jsonb_typeof(NEW.summary->'artifact_evidence') <> 'array' THEN
        RETURN NEW;
    END IF;

    FOR item IN SELECT value FROM jsonb_array_elements(NEW.summary->'artifact_evidence') LOOP
        IF coalesce(item->>'artifact_sha256','') = '' OR coalesce(item->>'provider_name','') = '' THEN
            CONTINUE;
        END IF;

        incoming_count := CASE
            WHEN coalesce(item->>'observation_count','') ~ '^[0-9]+$'
                THEN GREATEST((item->>'observation_count')::bigint, 1)
            ELSE 1
        END;

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
            now(),now(),incoming_count)
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
            observation_count=GREATEST(artifact_evidence.observation_count,EXCLUDED.observation_count);
    END LOOP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
