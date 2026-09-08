-- MS5.2: extend findings beyond network targets without changing existing rows.
ALTER TABLE findings ALTER COLUMN target_host DROP NOT NULL;
ALTER TABLE findings ALTER COLUMN target_port DROP NOT NULL;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS subject_type text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS subject_id text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS severity text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS rule_id text;

CREATE INDEX IF NOT EXISTS findings_subject_idx
    ON findings(agent_id, subject_type, subject_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS findings_rule_idx
    ON findings(rule_id, severity, last_seen DESC);
