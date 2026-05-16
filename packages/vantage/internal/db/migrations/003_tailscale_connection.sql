-- F2: store the global Tailscale OAuth credential. Singleton row
-- (CHECK constraint enforces it). The credential is fleet-compromise-
-- level — it can mint auth keys for every Edge — so it's
-- super-admin-only at the handler layer and AES-GCM encrypted at
-- rest via SECRETS_ENCRYPTION_KEY.
--
-- Mirrors Edge's tailscale_connection table; scoped to Vantage's
-- needs (no tenant_id splitting since Vantage owns the tailnet
-- globally per issue #22 Q3).

CREATE TABLE tailscale_connection (
    id TEXT PRIMARY KEY DEFAULT 'singleton' CHECK (id = 'singleton'),
    oauth_client_id_encrypted TEXT NOT NULL,
    oauth_client_secret_encrypted TEXT NOT NULL,
    tailnet TEXT NOT NULL,
    tailnet_display_name TEXT,
    connected_at BIGINT NOT NULL,
    connected_by_user_id TEXT REFERENCES users(id),
    last_validated_at BIGINT,
    last_validation_error TEXT,
    rotated_at BIGINT
);
