CREATE TABLE platform_profile_catalog (
    profile_id text PRIMARY KEY,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    name text NOT NULL,
    description text NOT NULL,
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE platform_profile_rule_patches (
    profile_id text NOT NULL REFERENCES platform_profile_catalog(profile_id) ON DELETE CASCADE,
    rule_id text NOT NULL,
    parameters_patch jsonb NOT NULL DEFAULT '{}'::jsonb,
    exclusions_patch jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, rule_id),
    CHECK (jsonb_typeof(parameters_patch) = 'object'),
    CHECK (jsonb_typeof(exclusions_patch) = 'object')
);

INSERT INTO platform_profile_catalog(profile_id,version,name,description) VALUES
 ('base',1,'Base / strict','No platform-specific deltas; use the published fleet policy unchanged.'),
 ('linux-server',1,'Linux server','Conservative server defaults with higher process burst thresholds.'),
 ('linux-desktop',1,'Linux desktop','Desktop-oriented process burst thresholds to reduce routine application fanout noise.'),
 ('wsl',1,'WSL','Linux-under-Windows defaults including known WSL parent plumbing and desktop-like burst thresholds.'),
 ('windows',1,'Windows','Windows-oriented process burst thresholds while preserving trusted evaluator semantics.')
ON CONFLICT (profile_id) DO NOTHING;

INSERT INTO platform_profile_rule_patches(profile_id,rule_id,parameters_patch,exclusions_patch) VALUES
 ('linux-server','PROC-004','{"child_count":10}'::jsonb,'{}'::jsonb),
 ('linux-server','PROC-005','{"child_count":10}'::jsonb,'{}'::jsonb),
 ('linux-desktop','PROC-004','{"child_count":12}'::jsonb,'{}'::jsonb),
 ('linux-desktop','PROC-005','{"child_count":12}'::jsonb,'{}'::jsonb),
 ('wsl','PROC-002','{}'::jsonb,'{"parent_process_names":["wsl-pro-service"]}'::jsonb),
 ('wsl','PROC-004','{"child_count":12}'::jsonb,'{}'::jsonb),
 ('wsl','PROC-005','{"child_count":12}'::jsonb,'{}'::jsonb),
 ('windows','PROC-004','{"child_count":12}'::jsonb,'{}'::jsonb),
 ('windows','PROC-005','{"child_count":12}'::jsonb,'{}'::jsonb)
ON CONFLICT (profile_id,rule_id) DO NOTHING;

CREATE INDEX platform_profile_rule_patches_rule_idx
    ON platform_profile_rule_patches(rule_id,profile_id);
