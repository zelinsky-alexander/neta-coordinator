CREATE TABLE rule_definitions (
    rule_id             TEXT NOT NULL,
    revision            BIGINT NOT NULL,
    origin              TEXT NOT NULL CHECK (origin IN ('DEFAULT','CUSTOM')),
    engine_rule_id      TEXT NOT NULL,
    name                TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    parameters_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by          TEXT NOT NULL DEFAULT 'system',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, revision)
);

CREATE TABLE rule_sets (
    rule_set_id         UUID PRIMARY KEY,
    revision            BIGINT NOT NULL,
    version             TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('PUBLISHED','ACTIVE','SUPERSEDED')),
    bundle_json         JSONB NOT NULL,
    sha256              TEXT NOT NULL,
    created_by          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (revision),
    UNIQUE (sha256)
);

CREATE UNIQUE INDEX uq_rule_sets_active ON rule_sets ((status)) WHERE status='ACTIVE';

CREATE TABLE agent_rule_state (
    agent_id            TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    desired_revision    BIGINT,
    desired_sha256      TEXT,
    active_revision     BIGINT,
    active_sha256       TEXT,
    status              TEXT NOT NULL DEFAULT 'UNKNOWN',
    last_error          TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO rule_definitions(rule_id,revision,origin,engine_rule_id,name,category,severity,enabled,parameters_json)
VALUES
('NETA-PERF-001',1,'DEFAULT','NETA-PERF-001','Network path degradation','performance','medium',true,
 '{"rtt_ratio":2.0,"rttvar_ratio":2.0,"retransmission_threshold":2,"rtt_weight":0.50,"rttvar_weight":0.20,"retransmission_weight":0.30,"degraded_threshold":0.50}'::jsonb),
('NETA-TRUST-001',1,'DEFAULT','NETA-TRUST-001','Outbound TLS identity','trust','high',true,
 '{"require_chain_valid":true,"require_hostname_valid":true,"compare_spki":true}'::jsonb),
('NETA-TRUST-002',1,'DEFAULT','NETA-TRUST-002','Inbound authenticated TLS identity','trust','high',true,
 '{"require_exact_evidence":true,"require_peer_certificate":true,"require_peer_authentication":true,"verification_failure_suspicious":true,"compare_spki":true,"compare_issuer":true}'::jsonb),
('NETA-PROC-001',1,'DEFAULT','NETA-PROC-001','Execution from transient path','process','medium',true,
 '{"path_prefixes":["/tmp/","/var/tmp/","/dev/shm/"],"path_substrings":["/appdata/local/temp/","/windows/temp/"]}'::jsonb),
('NETA-PROC-002',1,'DEFAULT','NETA-PROC-002','Shell from unexpected parent','process','medium',true,
 '{"shell_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe"],"expected_parent_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe","sshd","sudo","su","login","systemd","init","tmux","screen","gnome-terminal-server","konsole","windowsterminal.exe","wt.exe","conhost.exe","explorer.exe","winlogon.exe"]}'::jsonb),
('NETA-PROC-003',1,'DEFAULT','NETA-PROC-003','Unexpected elevation','process','medium',true,
 '{"expected_parent_names":["sudo","su","pkexec","doas","consent.exe"]}'::jsonb),
('NETA-PROC-004',1,'DEFAULT','NETA-PROC-004','Rapid child process fanout','process','medium',true,
 '{"child_count":6,"window_ms":10000}'::jsonb),
('NETA-PROC-005',1,'DEFAULT','NETA-PROC-005','Short-lived process burst','process','medium',true,
 '{"child_count":6,"max_lifetime_ms":2000,"window_ms":15000}'::jsonb);
