CREATE TABLE incidents (
    incident_id text PRIMARY KEY,
    agent_id text NOT NULL REFERENCES agents(agent_id),
    target_host text NOT NULL,
    target_port integer NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','CLOSED')),
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    finding_count integer NOT NULL DEFAULT 0,
    suspicious_count integer NOT NULL DEFAULT 0,
    changed_count integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incidents_status_last_seen_idx ON incidents(status, last_seen DESC);
CREATE INDEX incidents_agent_target_idx ON incidents(agent_id, target_host, target_port, last_seen DESC);

CREATE TABLE incident_findings (
    incident_id text NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    finding_id text NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, finding_id),
    UNIQUE (finding_id)
);
CREATE INDEX incident_findings_incident_idx ON incident_findings(incident_id, added_at);
