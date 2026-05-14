-- F2: enrollment tokens are the single-use bootstrap artifact that
-- an Edge presents on first registration. Operator mints one per
-- new Edge via POST /api/v1/vantage/enrollment-tokens; the bundle
-- (this row + minted Tailscale auth key + Vantage's JWT public key)
-- is delivered to the customer site out-of-band.
--
-- Lifecycle (issue #22 Q3):
--   - created_at + expires_at (24h TTL)
--   - consumed_at NULL while bundle is live
--   - consumed_at set + consumed_by_edge_id linked when /api/edge/
--     register accepts the bundle (single-use; concurrent attempts
--     resolve via the same DB transaction)
--
-- The Tailscale auth key plaintext is NOT stored on Vantage. Only
-- Tailscale's key ID is retained, so we can later revoke the key
-- via the Tailscale API if the bundle was leaked.

CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,

    tailscale_auth_key_id TEXT,

    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    consumed_by_edge_id TEXT REFERENCES edges(id),

    minted_by_user_id TEXT NOT NULL REFERENCES users(id),
    notes TEXT
);

CREATE INDEX idx_enrollment_tokens_tenant_id ON enrollment_tokens(tenant_id);
CREATE INDEX idx_enrollment_tokens_expires_at ON enrollment_tokens(expires_at);
CREATE INDEX idx_enrollment_tokens_consumed_at ON enrollment_tokens(consumed_at);
