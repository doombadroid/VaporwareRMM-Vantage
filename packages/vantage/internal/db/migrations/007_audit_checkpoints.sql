-- F2: audit chain cross-attestation per issue #22 Q9.
--
-- Edge and Vantage each keep their own audit hash chain
-- (audit_log.chain_seq + signature). The chains are independent —
-- neither side can tamper with the other's — but on every poll
-- exchange they swap chain heads and persist the counterparty's
-- head into this table.
--
-- If a future audit reveals Edge's chain doesn't match the
-- historical checkpoints Vantage stored, tampering is provable
-- (and the reverse direction).
--
-- The table is append-only by convention; no updates, no deletes.
-- The verification CLI (Q9 v1.1, deferred) reads it linearly.

CREATE TABLE audit_checkpoints (
    id BIGSERIAL PRIMARY KEY,

    counterparty_type TEXT NOT NULL CHECK (counterparty_type IN ('edge', 'vantage')),
    counterparty_id TEXT,

    chain_seq BIGINT NOT NULL,
    signature TEXT NOT NULL,

    recorded_at BIGINT NOT NULL,
    recorded_during TEXT
);

CREATE INDEX idx_audit_checkpoints_counterparty ON audit_checkpoints(counterparty_id, recorded_at DESC);
CREATE INDEX idx_audit_checkpoints_recorded_at ON audit_checkpoints(recorded_at);
