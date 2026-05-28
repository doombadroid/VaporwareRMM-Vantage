-- F4b cancel-signal round 2 (codex review of PR #3 round 2 findings).
--
-- Three additive columns:
--
-- 1. command_queue.cancellation_confirmed_at — set when the Edge acknowledges
--    a cancellation via command.result(status=cancelled).
--    fetchCancelledCorrelationIDs filters by NULL so the per-poll signal
--    carries only unconfirmed entries, bounded by actual Edge state instead
--    of a crude time window (round 2 #6). The confirmation handler CAS-updates
--    this column NULL→now and writes the audit row only on the winning UPDATE,
--    so retried events do not bloat the audit chain (round 2 #2).
--
-- 2. command_queue.last_re_polled_at — refreshed on EVERY poll re-delivery
--    (fetchPendingCommands), not just the first hand-out. MarkCancelled
--    refuses delivered_to_edge cancellation while this is within a 30-second
--    window (covers one 15s poll cycle + Edge processing + ack roundtrip) to
--    close the race where the just-built poll response carries the command
--    without including the cancellation in the same batch (round 2 #1).
--
-- 3. edges.supports_cancel_signal — set by the Edge in its poll request to
--    advertise that it honors cancelled_correlation_ids. MarkCancelled refuses
--    delivered_to_edge cancellation for Edges that haven't advertised support
--    (round 2 #5). Defaults to false; F4a-and-earlier Edges keep queued-only
--    cancellation, F4b Edge sets it true on every poll.
ALTER TABLE command_queue ADD COLUMN cancellation_confirmed_at BIGINT;
ALTER TABLE command_queue ADD COLUMN last_re_polled_at BIGINT;
ALTER TABLE edges ADD COLUMN supports_cancel_signal BOOLEAN NOT NULL DEFAULT false;

-- Replace the cancel-signal lookup index from migration 012 with one that
-- matches the new predicate (filtering by cancellation_confirmed_at IS NULL
-- instead of terminal_at retention).
DROP INDEX IF EXISTS idx_command_queue_cancelled_signal;
CREATE INDEX idx_command_queue_cancelled_signal
    ON command_queue (edge_id)
    WHERE state = 'cancelled'
      AND delivered_to_endpoint_at IS NULL
      AND cancellation_confirmed_at IS NULL;
