ALTER TABLE agents
    ADD COLUMN last_heartbeat_payload jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE findings
    ADD COLUMN finding_key text,
    ADD COLUMN first_seen timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_seen timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN occurrence_count bigint NOT NULL DEFAULT 1,
    ADD COLUMN status text NOT NULL DEFAULT 'ACTIVE';

UPDATE findings SET finding_key = finding_id WHERE finding_key IS NULL;
ALTER TABLE findings ALTER COLUMN finding_key SET NOT NULL;

CREATE UNIQUE INDEX findings_agent_key_uq ON findings(agent_id, finding_key);
CREATE INDEX findings_active_last_seen_idx ON findings(status, last_seen DESC);
