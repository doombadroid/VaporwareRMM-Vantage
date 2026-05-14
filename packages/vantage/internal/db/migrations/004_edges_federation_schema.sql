-- F2: full edges schema for federation. F1's edges table was a stub
-- (5 columns, just enough for the empty fleet view query). F2 drops
-- it and rebuilds with the federation columns: token storage,
-- version tracking, status state machine, last-seen heartbeat,
-- tailnet identity, enrollment provenance.
--
-- A DROP + recreate (rather than a series of ALTER TABLE ADD COLUMN
-- statements) keeps the F1→F2 transition unambiguous: the stub
-- table never had production data (no federation flow existed to
-- populate it), so wiping it carries no risk.
--
-- Status state machine per #22 Q5/Q7/Q8:
--   pending        — enrollment minted but Edge hasn't registered
--   active         — paired and polling
--   unpaired       — operator disconnected; awaiting re-pair
--   decommissioned — permanent retirement of this Edge

DROP TABLE IF EXISTS edges;

CREATE TABLE edges (
    id TEXT PRIMARY KEY,
    name TEXT,
    tenant_id TEXT NOT NULL,
    tailnet_identity TEXT,
    tailnet_ip TEXT,

    token_hash TEXT,
    token_issued_at BIGINT,
    token_expires_at BIGINT,

    edge_version TEXT,

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'unpaired', 'decommissioned')),
    last_seen_at BIGINT,

    created_at BIGINT NOT NULL,
    decommissioned_at BIGINT,
    operator_notes TEXT,

    enrollment_token_id TEXT
);

CREATE INDEX idx_edges_tenant_id ON edges(tenant_id);
CREATE INDEX idx_edges_status ON edges(status);
CREATE INDEX idx_edges_token_hash ON edges(token_hash) WHERE token_hash IS NOT NULL;
CREATE INDEX idx_edges_last_seen ON edges(last_seen_at);
