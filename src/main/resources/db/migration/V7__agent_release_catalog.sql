CREATE TABLE agent_releases (
    release_id bigserial PRIMARY KEY,
    source_type text NOT NULL CHECK (source_type IN ('RELEASE','GIT_REF')),
    source_ref text NOT NULL,
    source_commit text NOT NULL,
    version text NOT NULL,
    build_id text NOT NULL,
    git_commit text NOT NULL,
    os text NOT NULL,
    arch text NOT NULL,
    artifact_name text NOT NULL,
    artifact_url text NOT NULL,
    artifact_sha256 text NOT NULL,
    published_at timestamptz,
    discovered_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_releases_sha256_format CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_releases_commit_format CHECK (git_commit ~ '^[0-9a-f]{40}$'),
    CONSTRAINT agent_releases_source_commit_format CHECK (source_commit ~ '^[0-9a-f]{40}$')
);

CREATE UNIQUE INDEX agent_releases_resolved_artifact_uq
    ON agent_releases(source_type, source_ref, source_commit, os, arch, artifact_sha256);

CREATE INDEX agent_releases_lookup_idx
    ON agent_releases(version, os, arch, discovered_at DESC);
