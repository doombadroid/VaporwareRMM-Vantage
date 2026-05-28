-- F4a (codex round 5 #2): index the command-history query path. The operator
-- dashboard auto-refreshes GET /api/v1/commands every 10s, ordering by
-- queued_at DESC (now with an id DESC tie-breaker, round 5 #1) and optionally
-- filtering by edge_id / tenant_id / state. Migration 009 indexed the poll hot
-- path and tenant, but nothing matched the history ORDER BY, so the list (and
-- its repeated polling) would increasingly scan+sort the table.
--
-- One composite per single-filter mode the UI offers, each carrying the
-- (queued_at DESC, id DESC) ordering so the filter narrows AND the sort is
-- index-ordered:
--   - unfiltered "all" history (the default auto-refresh),
--   - per-edge listing (the edge filter),
--   - per-state listing (the state filter).
-- Combined filters narrow via the most selective of these, then sort.
CREATE INDEX idx_command_queue_history ON command_queue (queued_at DESC, id DESC);
CREATE INDEX idx_command_queue_edge_history ON command_queue (edge_id, queued_at DESC, id DESC);
CREATE INDEX idx_command_queue_state_history ON command_queue (state, queued_at DESC, id DESC);
