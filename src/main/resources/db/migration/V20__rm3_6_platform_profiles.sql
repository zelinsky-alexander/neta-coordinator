-- RM3.6: explicit endpoint platform profiles. Profiles are deterministic central policy
-- presets implemented as approved endpoint rule overrides; they never learn or whitelist behavior.

CREATE TABLE endpoint_platform_profiles (
    agent_id        text PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    profile_id      text NOT NULL CHECK (profile_id IN ('base','linux-server','linux-desktop','wsl','windows')),
    profile_version integer NOT NULL DEFAULT 1 CHECK (profile_version > 0),
    assigned_by     text NOT NULL,
    assigned_at     timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX endpoint_platform_profiles_profile_idx
    ON endpoint_platform_profiles(profile_id, updated_at DESC);

COMMENT ON TABLE endpoint_platform_profiles IS
    'RM3.6 deterministic endpoint platform profile selection. Profile policy is materialized through ordinary trusted endpoint rule overrides.';
