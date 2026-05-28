-- F4a: command queue + tag metadata per issue #22 Q1/Q4/Q5/Q7.
--
-- End-to-end command lifecycle (F4): an operator queues a command on
-- Vantage, the Edge polls and receives it, the on-site agent executes it,
-- and a pass/fail result flows back. F4 ships exactly one command type
-- (restart_service) as the smallest viable vertical slice.
--
-- Three tables:
--   command_queue            — operator intent + lifecycle state machine.
--   tags                     — tag definitions, mirrored FROM the Edge.
--   tag_endpoint_membership  — tag -> endpoint mappings, mirrored FROM
--                              the Edge. Vantage expands tag targets into
--                              explicit endpoint_ids at enqueue time
--                              (Q7); the Edge stays the source of truth
--                              for which endpoints exist.
--
-- Conventions (matching 004/005/007): TEXT primary keys (no UUID type in
-- this schema), tenant_id is a bare TEXT column (there is no tenants
-- table — tenancy is a soft string scope), BIGINT unix-second timestamps
-- for federation rows, FKs to edges(id)/users(id), CHECK constraints on
-- enum-like columns, partial indexes for the hot query paths.
--
-- State machine (Q5; "cancelled" added per Decision 6):
--   queued -> delivered_to_edge -> delivered_to_endpoint -> executing
--          -> succeeded | failed
--   queued -> expired                       (TTL sweep, edge_unreachable)
--   queued | delivered_to_edge -> cancelled (operator, pre-dispatch only)
--   delivered_to_endpoint -> succeeded | failed (fast-returning commands)
-- succeeded/failed/expired/cancelled are terminal sinks.

CREATE TABLE command_queue (
    id BIGSERIAL PRIMARY KEY,
    -- correlation_id links this command across the Vantage/Edge boundary
    -- and back (Q-conventions: uuid.New().String() minted at Vantage, the
    -- originating side). UNIQUE is the idempotency anchor on both sides.
    correlation_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    edge_id TEXT NOT NULL REFERENCES edges(id),
    target_endpoint_id TEXT NOT NULL,
    command_type TEXT NOT NULL CHECK (command_type IN ('restart_service')),
    command_params JSONB NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'queued', 'delivered_to_edge', 'delivered_to_endpoint',
        'executing', 'succeeded', 'failed', 'expired', 'cancelled'
    )),
    -- result_status/result_message are set once the command reaches a
    -- terminal state. result_message is a brief operator-facing string
    -- (NOT endpoint command output — that stays on the Edge, Q4).
    result_status TEXT CHECK (result_status IN ('succeeded', 'failed', 'expired', 'cancelled')),
    result_message TEXT,
    queued_at BIGINT NOT NULL,
    delivered_to_edge_at BIGINT,
    delivered_to_endpoint_at BIGINT,
    terminal_at BIGINT,
    operator_user_id TEXT NOT NULL REFERENCES users(id),
    -- queued_at + 3600 (1h TTL, Decision 5). Sweeper expires un-delivered
    -- commands with result_message='edge_unreachable'.
    expires_at BIGINT NOT NULL
);

-- Hot path: "what is pending for this Edge" during poll. Partial index
-- keeps it small — terminal rows (the vast majority over time) are excluded.
CREATE INDEX idx_command_queue_edge_state ON command_queue(edge_id, state)
    WHERE state IN ('queued', 'delivered_to_edge', 'delivered_to_endpoint', 'executing');
-- TTL sweep scans only still-queued rows.
CREATE INDEX idx_command_queue_expires_at ON command_queue(expires_at)
    WHERE state = 'queued';
-- Operator UI list/filter by tenant.
CREATE INDEX idx_command_queue_tenant ON command_queue(tenant_id);
-- (correlation_id lookups are served by the UNIQUE constraint's index.)

CREATE TABLE tags (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    edge_id TEXT NOT NULL REFERENCES edges(id),
    name TEXT NOT NULL,
    UNIQUE (edge_id, name)
);

CREATE INDEX idx_tags_edge_id ON tags(edge_id);

CREATE TABLE tag_endpoint_membership (
    tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    endpoint_id TEXT NOT NULL,
    PRIMARY KEY (tag_id, endpoint_id)
);

-- Reverse lookup: "which tags is this endpoint in" (and supports the
-- tag-expansion join from the endpoint side).
CREATE INDEX idx_tag_endpoint_endpoint ON tag_endpoint_membership(endpoint_id);
