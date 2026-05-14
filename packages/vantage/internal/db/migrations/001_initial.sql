-- F1 initial schema: users, sessions, edges (empty), audit_log
-- (with hash chain). The edges table is intentionally minimal in
-- F1 — the fleet view query has somewhere to read from but the
-- table is populated by F2's federation pairing flow.
--
-- schema_migrations itself is created out-of-band by db.runMigrations
-- so this file can assume it exists.

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('super_admin', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users(email);

CREATE TABLE user_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    ip TEXT,
    user_agent TEXT
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);

CREATE TABLE edges (
    -- F2 will populate this table fully. F1 just creates the empty shell
    -- so the fleet view query has somewhere to read from.
    id TEXT PRIMARY KEY,
    name TEXT,
    tenant_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_edges_tenant ON edges(tenant_id);
CREATE INDEX idx_edges_status ON edges(status);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    chain_seq BIGINT NOT NULL,
    chain_hash TEXT NOT NULL,
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    details TEXT,
    ip TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_chain_seq ON audit_log(chain_seq);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
