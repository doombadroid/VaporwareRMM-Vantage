-- F4b cancel-signal round 2 (codex review of PR #3 round 2 + round 3 findings).
--
-- Two additive columns:
--
-- 1. command_queue.cancellation_confirmed_at — set when the Edge acknowledges
--    a cancellation via command.result(status=cancelled) AND, for the
--    never-delivered case (queued + poll_delivered_at IS NULL), set at
--    cancel time so a never-received cancellation does not replay forever
--    (codex review of PR #3 round 3 #3). fetchCancelledCorrelationIDs filters
--    by NULL so an unconfirmed cancellation persists indefinitely — an Edge
--    offline arbitrarily long still sees the drop on its return poll (round 2
--    #6). The confirmation handler CAS-updates this column NULL→now and writes
--    the audit row only on the winning UPDATE, so retries are accepted as
--    benign no-ops without bloating the audit chain (round 2 #2).
--
-- 2. edges.supports_cancel_signal — set by the Edge in its poll request to
--    advertise that it honors cancelled_correlation_ids. MarkCancelled refuses
--    delivered_to_edge cancellation for Edges that have not advertised support
--    (round 2 #5). Defaults to false; pre-F4b Edges keep queued-only
--    cancellation, F4b Edge sets it true on every poll.
--
-- The cancel-vs-poll race for delivered_to_edge is gated by a stabilization
-- window on delivered_to_edge_at (set by F4a's MarkDeliveredToEdge); no new
-- column for it. The window is enforced in MarkCancelled.
ALTER TABLE command_queue ADD COLUMN cancellation_confirmed_at BIGINT;
ALTER TABLE edges ADD COLUMN supports_cancel_signal BOOLEAN NOT NULL DEFAULT false;

-- Replace the cancel-signal lookup index from migration 012 with a partial
-- index matching the new predicate. The terminal-time retention from round 1
-- is gone; filtering by cancellation_confirmed_at IS NULL replaces it.
DROP INDEX IF EXISTS idx_command_queue_cancelled_signal;
CREATE INDEX idx_command_queue_cancelled_signal
    ON command_queue (edge_id)
    WHERE state = 'cancelled'
      AND delivered_to_endpoint_at IS NULL
      AND cancellation_confirmed_at IS NULL;
