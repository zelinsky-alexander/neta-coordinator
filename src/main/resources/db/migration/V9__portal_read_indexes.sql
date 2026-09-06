-- Portal 0.1.1 read-path indexes. These support stable keyset pagination and the
-- most common fleet filters without introducing portal-owned state.

CREATE INDEX agents_portal_name_idx
    ON agents ((lower(COALESCE(NULLIF(display_name,''), agent_id))), agent_id);

CREATE INDEX agents_portal_status_name_idx
    ON agents (status, (lower(COALESCE(NULLIF(display_name,''), agent_id))), agent_id);

CREATE INDEX agents_portal_platform_name_idx
    ON agents ((lower(COALESCE(agent_os,''))), (lower(COALESCE(NULLIF(display_name,''), agent_id))), agent_id);

CREATE INDEX findings_portal_last_seen_idx
    ON findings (last_seen DESC, finding_id DESC);

CREATE INDEX findings_portal_agent_last_seen_idx
    ON findings (agent_id, last_seen DESC, finding_id DESC);

CREATE INDEX findings_portal_status_last_seen_idx
    ON findings (status, last_seen DESC, finding_id DESC);

CREATE INDEX agent_upgrades_portal_requested_idx
    ON agent_upgrades (requested_at DESC, upgrade_id DESC);
