-- F2 round-11 audit (codex round 10 findings #1, #4 + sweep
-- additions): tighten schema constraints that the Phase-1 audit
-- surfaced.

-- 1. edges.enrollment_token_id FK to enrollment_tokens(id).
--    F2 originally left this column unenforced (round 10 finding
--    #1). ON DELETE SET NULL keeps an Edge row alive if the
--    operator ever cleans up a consumed enrollment row — the
--    Edge already has its bearer token, the enrollment
--    provenance just goes to NULL.
ALTER TABLE edges
    ADD CONSTRAINT edges_enrollment_token_id_fkey
    FOREIGN KEY (enrollment_token_id)
    REFERENCES enrollment_tokens(id)
    ON DELETE SET NULL;

-- 2. edges.token_hash UNIQUE (partial — NULL allowed for pending/
--    unpaired/decommissioned edges with no live token). Round 10
--    finding #4: without this, data corruption could let one
--    hash authenticate as multiple edges. EdgeAuthMiddleware
--    queries WHERE token_hash = $1 AND status = 'active'; with
--    multiple matches the SELECT returns one arbitrarily.
DROP INDEX IF EXISTS idx_edges_token_hash;
CREATE UNIQUE INDEX idx_edges_token_hash_unique
    ON edges(token_hash)
    WHERE token_hash IS NOT NULL;

-- 3. audit_log.chain_seq UNIQUE. Chain integrity demands no
--    duplicate seq values. The chain write path serializes via
--    pg_advisory_xact_lock (events.go), but the constraint
--    is a database-layer guarantee in case future code paths
--    skip the lock.
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_chain_seq_unique UNIQUE (chain_seq);
