ALTER TABLE rule_definitions
    ADD COLUMN exclusions_json JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN rule_definitions.exclusions_json IS
    'Per-rule evidence exclusions evaluated by the endpoint before a rule match is persisted or reported.';
