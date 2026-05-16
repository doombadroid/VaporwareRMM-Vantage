-- F2: Vantage's signing keypair. The private key signs drill-through
-- SSO JWTs that F5 will issue; the public key is bundled into every
-- enrollment-token response so Edges can verify those JWTs
-- offline without re-fetching from Vantage on every drill-through.
--
-- Singleton row. The keypair is generated on first boot if absent
-- and rotated only via explicit operator action (out of scope for
-- F2, deferred until first compromise event or policy change).
--
-- Algorithm fixed to Ed25519: smaller keys, faster signatures,
-- modern construction. The `algorithm` column is for future-proofing
-- (RSA-PSS or Ed448 if Ed25519 ever needs to be replaced) — F2
-- only writes 'Ed25519'.

CREATE TABLE vantage_signing_key (
    id TEXT PRIMARY KEY DEFAULT 'singleton' CHECK (id = 'singleton'),
    private_key_encrypted TEXT NOT NULL,
    public_key TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'Ed25519',
    created_at BIGINT NOT NULL
);
