-- F4b cancel-signal (codex review of PR #3, second-pass finding): index the
-- per-Edge cancelled poll-signal lookup. fetchCancelledCorrelationIDs runs
-- once per /api/edge/poll for every Edge, scanning command_queue for rows
-- matching (edge_id, state='cancelled', delivered_to_endpoint_at IS NULL,
-- terminal_at > cutoff). Migration 009's idx_command_queue_edge_state only
-- covers the queued/delivered_to_edge/delivered_to_endpoint/executing live
-- states, so 'cancelled' rows are excluded; this becomes a sequential scan in
-- proportion to the table's accumulated terminal rows.
--
-- Partial index on the exact predicate, ordered by (edge_id, terminal_at) so
-- the per-Edge probe is selective and the terminal_at retention bound (7d)
-- evaluates against the same index pages.
CREATE INDEX idx_command_queue_cancelled_signal
    ON command_queue (edge_id, terminal_at)
    WHERE state = 'cancelled' AND delivered_to_endpoint_at IS NULL;
