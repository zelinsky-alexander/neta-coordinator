CREATE TABLE ingest_receipts (
    agent_id text NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    idempotency_key text NOT NULL,
    payload_hash text NOT NULL,
    message_type text NOT NULL,
    first_message_id text NOT NULL,
    first_sequence bigint NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT now(),
    result_status text NOT NULL DEFAULT 'ACCEPTED',
    PRIMARY KEY (agent_id, idempotency_key)
);

CREATE INDEX ingest_receipts_committed_idx ON ingest_receipts(committed_at);
