-- Central rule convergence over the existing AgentHello/Heartbeat control response.
-- No inbound endpoint command channel is introduced: endpoints remain outbound-only.

ALTER TABLE agent_rule_state
    ADD COLUMN refresh_requested_at TIMESTAMPTZ,
    ADD COLUMN last_ack_at TIMESTAMPTZ;

CREATE INDEX agent_rule_state_status_idx
    ON agent_rule_state(status, updated_at DESC);

-- RuleManagementService already records INSTALLED / ACTIVE / APPLY_FAILED ACK state.
-- Track the ACK time and consume an operator refresh request only after the endpoint
-- confirms the desired effective hash as ACTIVE.
CREATE OR REPLACE FUNCTION neta_track_rule_ack()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IN ('INSTALLED','ACTIVE','APPLY_FAILED')
       AND NEW.active_sha256 IS NOT NULL
       AND (
            TG_OP = 'INSERT'
            OR NEW.active_revision IS DISTINCT FROM OLD.active_revision
            OR NEW.active_sha256 IS DISTINCT FROM OLD.active_sha256
            OR NEW.status IS DISTINCT FROM OLD.status
       ) THEN
        NEW.last_ack_at = now();
    END IF;

    IF NEW.status = 'ACTIVE'
       AND NEW.desired_sha256 IS NOT NULL
       AND NEW.active_sha256 = NEW.desired_sha256 THEN
        NEW.refresh_requested_at = NULL;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS agent_rule_state_ack_tracking ON agent_rule_state;
CREATE TRIGGER agent_rule_state_ack_tracking
BEFORE INSERT OR UPDATE OF active_revision,active_sha256,status
ON agent_rule_state
FOR EACH ROW EXECUTE FUNCTION neta_track_rule_ack();

COMMENT ON COLUMN agent_rule_state.refresh_requested_at IS
    'Operator-requested re-fetch/revalidation marker consumed only by a matching ACTIVE endpoint ACK.';
COMMENT ON COLUMN agent_rule_state.last_ack_at IS
    'Last endpoint rule-state ACK observed by the coordinator.';
