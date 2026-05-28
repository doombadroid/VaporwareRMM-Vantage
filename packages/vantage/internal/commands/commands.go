// Package commands implements the F4 command lifecycle state machine for
// Vantage. An operator queues a command; the Edge polls, receives, and
// dispatches it to an endpoint; results flow back. Vantage owns the
// authoritative queue and the operator-facing state (issue #22 Q1/Q4/Q5).
//
// State machine (Decision 6 adds "cancelled"; F4b restores the full cancel window):
//
//	queued ──► delivered_to_edge ──► delivered_to_endpoint ──► executing
//	                                          │                    │
//	                                          └────────┬───────────┘
//	                                                   ▼
//	                                           succeeded | failed
//	queued ──► expired                       (TTL sweep, edge_unreachable)
//	queued | delivered_to_edge ──► cancelled (operator, pre-dispatch only)
//
// Cancel window (Decision 6 / F4b cancel-signal): cancellation is legal in two
// non-overlapping bands:
//   1. queued AND NOT yet handed out in a poll (poll_delivered_at IS NULL) —
//      the command has not crossed the Edge boundary yet, safe to terminal.
//   2. delivered_to_edge — the Edge has acked persistence but has not yet
//      dispatched to the endpoint. The F4b poll response carries
//      cancelled_correlation_ids so the Edge drops the local 'received' row
//      (persist→cancel-check→dispatch) before it ever reaches the agent.
//
// The narrow gap between (1) and (2) — queued AND poll_delivered_at IS NOT NULL
// — is deliberately non-cancellable: the poll response that carried this
// command was built without this cancellation, so the Edge will receive the
// command but will NOT see it in cancelled_correlation_ids; it will dispatch
// and the authoritative terminal result would CAS-miss a prematurely-terminal
// cancelled row. The operator retries after the Edge acks (~one poll cycle).
//
// Once delivered_to_endpoint, the command is on its way to running and cancel
// returns ErrNotCancellable.
//
// succeeded/failed/expired/cancelled are terminal sinks (no transitions out).
//
// KNOWN LIMITATION (audit phase 11 — stuck states): only the `queued` state
// has a TTL (the sweeper). Once a command leaves `queued`, nothing on the
// Vantage side times it out: if the Edge acks (delivered_to_edge) or the
// agent receives it (delivered_to_endpoint) or starts running it (executing)
// but never reports a terminal result, the command parks in that state
// indefinitely. F4 ships without an execution timeout because the timeout
// budget depends on command semantics the Edge owns (restart_service is fast,
// but later command types may legitimately run for minutes). Proposed F4
// follow-up: an Edge-reported execution deadline + a Vantage sweep that fails
// commands stuck past delivered_to_endpoint for too long.
//
// Every transition is compare-and-set: UPDATE ... WHERE correlation_id = $1
// AND state IN (<legal predecessors>). RowsAffected == 1 means we won the
// transition and we write an audited chain entry in the SAME transaction;
// RowsAffected == 0 means the row is missing (ErrNotFound) or in a state
// the transition isn't legal from (ErrInvalidTransition). Idempotent callers
// (the ack endpoint, the events handler) treat ErrInvalidTransition as a
// benign already-advanced/duplicate and move on.
package commands

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/events"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// States.
const (
	StateQueued              = "queued"
	StateDeliveredToEdge     = "delivered_to_edge"
	StateDeliveredToEndpoint = "delivered_to_endpoint"
	StateExecuting           = "executing"
	StateSucceeded           = "succeeded"
	StateFailed              = "failed"
	StateExpired             = "expired"
	StateCancelled           = "cancelled"
)

// SystemActor is the audit user_id for transitions driven by the Edge (via
// /api/edge/events) or the TTL sweeper — there is no operator behind them.
const SystemActor = "system"

// TTLSeconds is the queued-without-delivery lifetime (Decision 5). After it
// elapses the sweeper expires the command with reason "edge_unreachable".
const TTLSeconds = 3600

// SweepInterval is how often RunExpirySweeper runs the TTL sweep.
const SweepInterval = 60 * time.Second

// ExpireReason is the result_message for TTL-expired commands.
const ExpireReason = "edge_unreachable"

var (
	// ErrNotFound: no command_queue row with this correlation_id.
	ErrNotFound = errors.New("commands: command not found")
	// ErrInvalidTransition: the row exists but is not in a state from which
	// the requested transition is legal. Benign for idempotent callers.
	ErrInvalidTransition = errors.New("commands: invalid state transition")
	// ErrNotCancellable: cancel requested but the command is already
	// delivered_to_endpoint or later (Decision 6). Maps to 409.
	ErrNotCancellable = errors.New("commands: command not cancellable (already dispatched or terminal)")
)

// EnqueueRequest is one command to queue. Targets are already expanded to a
// single endpoint at the caller (tag expansion happens in the handler, Q7).
type EnqueueRequest struct {
	TenantID         string
	EdgeID           string
	TargetEndpointID string
	CommandType      string
	CommandParams    json.RawMessage
	OperatorUserID   string
}

// EnqueueCommand inserts one queued command and returns its freshly-minted
// correlation_id (the cross-side idempotency anchor; minted here at the
// originating side). Audited within the caller's transaction.
func EnqueueCommand(ctx context.Context, tx *sql.Tx, req EnqueueRequest) (string, error) {
	correlationID := uuid.New().String()
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO command_queue
			(correlation_id, tenant_id, edge_id, target_endpoint_id,
			 command_type, command_params, state, queued_at, expires_at, operator_user_id)
		VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7, $8, $9)`,
		correlationID, req.TenantID, req.EdgeID, req.TargetEndpointID,
		req.CommandType, []byte(req.CommandParams), now, now+TTLSeconds, req.OperatorUserID,
	); err != nil {
		return "", fmt.Errorf("commands: enqueue: %w", err)
	}
	details, _ := json.Marshal(map[string]string{
		"edge_id":      req.EdgeID,
		"endpoint_id":  req.TargetEndpointID,
		"command_type": req.CommandType,
	})
	if err := events.AuditLogSyncTx(tx, req.OperatorUserID, "command.enqueue", "command", correlationID, string(details), ""); err != nil {
		return "", err
	}
	return correlationID, nil
}

// The edge-driven transitions (MarkDeliveredToEdge / MarkDeliveredToEndpoint /
// MarkExecuting / MarkTerminal) are EDGE-SCOPED: the CAS also requires
// edge_id = the authenticated Edge, so one Edge can never advance or report
// results for a command belonging to another Edge (cross-boundary safety,
// audit phase 12). A non-owned correlation_id falls through to classifyMiss
// (ErrInvalidTransition), which idempotent callers treat as benign.

// MarkDeliveredToEdge: queued → delivered_to_edge, on Edge ack (Decision 2).
func MarkDeliveredToEdge(ctx context.Context, tx *sql.Tx, correlationID, edgeID string) error {
	return casTransition(ctx, tx, correlationID, edgeID,
		"state = 'delivered_to_edge', delivered_to_edge_at = $2",
		[]string{StateQueued},
		SystemActor, "command.delivered_to_edge", "", time.Now().Unix())
}

// Progress transitions are MONOTONIC (codex round 3 #2): each is legal from
// any earlier live state, not just its immediate predecessor. Edge progress
// events (delivered_to_endpoint, executing) can arrive out of order or beat
// the ack across retried event batches; if they were legal only from the
// immediate predecessor, an early event would hit ErrInvalidTransition, be
// tolerated as benign, and the progress would be lost (leaving the command
// parked). Allowing them from any lower live state means a progress event
// always advances the command to its level (and is a benign no-op from an
// equal/higher state).

// MarkDeliveredToEndpoint: queued|delivered_to_edge → delivered_to_endpoint,
// when the Edge reports the agent received the command (via /api/edge/events).
func MarkDeliveredToEndpoint(ctx context.Context, tx *sql.Tx, correlationID, edgeID string) error {
	return casTransition(ctx, tx, correlationID, edgeID,
		"state = 'delivered_to_endpoint', delivered_to_endpoint_at = $2",
		[]string{StateQueued, StateDeliveredToEdge},
		SystemActor, "command.delivered_to_endpoint", "", time.Now().Unix())
}

// MarkExecuting: queued|delivered_to_edge|delivered_to_endpoint → executing.
func MarkExecuting(ctx context.Context, tx *sql.Tx, correlationID, edgeID string) error {
	return casTransition(ctx, tx, correlationID, edgeID,
		"state = 'executing'",
		[]string{StateQueued, StateDeliveredToEdge, StateDeliveredToEndpoint},
		SystemActor, "command.executing", "")
}

// MarkTerminal: any non-terminal state → succeeded|failed. A terminal result
// is AUTHORITATIVE — the agent actually ran the command — so it is legal from
// every live state (queued/delivered_to_edge/delivered_to_endpoint/executing),
// not just the "expected" predecessors. The intermediate progress events
// (delivered_to_endpoint, executing) are hints that can arrive late, out of
// order across retried Edge event batches, or not at all; if the terminal
// result were only legal from those, an out-of-order or lost progress event
// would strand the command in a non-terminal state with its result silently
// dropped (codex round 1 #1). Terminal states stay sinks (a result for an
// already-terminal command is a benign idempotent no-op via classifyMiss).
func MarkTerminal(ctx context.Context, tx *sql.Tx, correlationID, edgeID, status, message string) error {
	if status != StateSucceeded && status != StateFailed {
		return fmt.Errorf("%w: terminal status must be succeeded|failed, got %q", ErrInvalidTransition, status)
	}
	now := time.Now().Unix()
	details, _ := json.Marshal(map[string]string{"result_status": status})
	// state = $2 (succeeded|failed); result_status mirrors it; result_message
	// is the brief operator-facing string ($3); terminal_at = $4.
	return casTransition(ctx, tx, correlationID, edgeID,
		"state = $2, result_status = $2, result_message = $3, terminal_at = $4",
		[]string{StateQueued, StateDeliveredToEdge, StateDeliveredToEndpoint, StateExecuting},
		SystemActor, "command.terminal", string(details),
		status, message, now)
}

// CancelInflightWindowSeconds is the cool-down between Vantage re-delivering a
// delivered_to_edge command via poll and the operator being allowed to cancel
// it. Covers one poll cycle (15s default) + Edge persist+dispatch+ack latency
// + safety margin. While the row's last_re_polled_at is inside this window the
// Edge may have received the command and dispatched it before the cancellation
// is computable into a poll response, so we refuse the cancel — the operator
// retries after the window elapses.
const CancelInflightWindowSeconds = 30

// MarkCancelled: cancel a command still pre-dispatch.
//   - state='queued' AND poll_delivered_at IS NULL → cancel succeeds.
//   - state='delivered_to_edge' AND edge advertises supports_cancel_signal
//     AND (last_re_polled_at IS NULL OR last_re_polled_at < now-30s) → cancel
//     succeeds. F4b Decision 6 restoration, with three guards:
//   - state='queued' AND poll_delivered_at IS NOT NULL → ErrNotCancellable.
//     In flight between Vantage poll-build and Edge ack; the just-built poll
//     response did not carry this cancellation (codex review of PR #3 round 1
//     #3). Operator retries after the Edge acks (~one poll cycle).
//   - state='delivered_to_edge' AND last_re_polled_at recent → ErrNotCancellable.
//     Closes the analogous race for delivered_to_edge (codex round 2 #1):
//     the row was just included in a poll response, the Edge will dispatch
//     before the next cancel-signal poll. Operator retries after the window.
//   - state='delivered_to_edge' AND !edges.supports_cancel_signal →
//     ErrNotCancellable. Forces the Edge to advertise F4b capability before
//     widening the cancel window (codex round 2 #5); without the advertised
//     signal handler, the cancel succeeds at Vantage but the Edge dispatches
//     and the terminal result silently CAS-misses.
//   - state='delivered_to_endpoint' or later → ErrNotCancellable (Decision 6
//     cutoff — authoritative terminal result lands on the row).
//
// The cancel is implemented as one atomic UPDATE that JOINs to edges for the
// supports_cancel_signal predicate; a zero-RowsAffected outcome falls through
// to classifyCancelMiss for a precise sentinel.
func MarkCancelled(ctx context.Context, tx *sql.Tx, correlationID, actorUserID string) error {
	now := time.Now().Unix()
	inflightCutoff := now - CancelInflightWindowSeconds
	res, err := tx.ExecContext(ctx, `
		UPDATE command_queue cq
		SET state = 'cancelled', result_status = 'cancelled',
			result_message = 'cancelled by operator', terminal_at = $2
		FROM edges e
		WHERE cq.correlation_id = $1
		  AND cq.edge_id = e.id
		  AND (
		    (cq.state = 'queued' AND cq.poll_delivered_at IS NULL)
		    OR (
		      cq.state = 'delivered_to_edge'
		      AND e.supports_cancel_signal = true
		      AND (cq.last_re_polled_at IS NULL OR cq.last_re_polled_at < $3)
		    )
		  )`,
		correlationID, now, inflightCutoff)
	if err != nil {
		return fmt.Errorf("commands: cancel: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return classifyCancelMiss(ctx, tx, correlationID, inflightCutoff)
	}
	return events.AuditLogSyncTx(tx, actorUserID, "command.cancelled", "command", correlationID, "", "")
}

// classifyCancelMiss diagnoses a zero-rows MarkCancelled outcome. It returns
// ErrNotFound for a missing row and ErrNotCancellable (carrying the precise
// reason) otherwise. The diagnosis runs inside the caller's tx so it observes
// the same snapshot the failed UPDATE saw.
func classifyCancelMiss(ctx context.Context, tx *sql.Tx, correlationID string, inflightCutoff int64) error {
	var (
		state              string
		pollDeliveredAt    sql.NullInt64
		lastRePolledAt     sql.NullInt64
		supportsCancelSig  bool
	)
	err := tx.QueryRowContext(ctx, `
		SELECT cq.state, cq.poll_delivered_at, cq.last_re_polled_at, COALESCE(e.supports_cancel_signal, false)
		FROM command_queue cq
		LEFT JOIN edges e ON e.id = cq.edge_id
		WHERE cq.correlation_id = $1`,
		correlationID,
	).Scan(&state, &pollDeliveredAt, &lastRePolledAt, &supportsCancelSig)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("commands: cancel classify: %w", err)
	}
	switch state {
	case StateQueued:
		if pollDeliveredAt.Valid {
			return fmt.Errorf("%w (current=queued, in flight to Edge — retry after the Edge acks)", ErrNotCancellable)
		}
		// Unreachable: UPDATE matches queued+IS NULL, so this branch only
		// fires if the row state changed between UPDATE and SELECT. Treat as
		// generic not-cancellable.
		return fmt.Errorf("%w (current=queued, transient)", ErrNotCancellable)
	case StateDeliveredToEdge:
		if !supportsCancelSig {
			return fmt.Errorf("%w (current=delivered_to_edge, edge has not advertised cancel-signal support)", ErrNotCancellable)
		}
		if lastRePolledAt.Valid && lastRePolledAt.Int64 >= inflightCutoff {
			return fmt.Errorf("%w (current=delivered_to_edge, in flight via recent re-poll — retry after the cancel-inflight window elapses)", ErrNotCancellable)
		}
		return fmt.Errorf("%w (current=delivered_to_edge, transient)", ErrNotCancellable)
	default:
		return fmt.Errorf("%w (current=%s)", ErrNotCancellable, state)
	}
}

// ExpireStaleQueued is the TTL sweep (Decision 5). It transitions every
// still-queued command past its TTL to expired, in ONE atomic CAS UPDATE so
// it is safe to run from every Vantage instance concurrently (multi-node
// invariant): each row is transitioned exactly once, and each instance
// audits only the rows its own UPDATE returned. Returns the count expired.
func ExpireStaleQueued(ctx context.Context) (int, error) {
	now := time.Now().Unix()
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("commands: expire: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		UPDATE command_queue
		SET state = 'expired', result_status = 'expired',
			result_message = $2, terminal_at = $1
		WHERE state = 'queued' AND expires_at <= $1
		RETURNING correlation_id`, now, ExpireReason)
	if err != nil {
		return 0, fmt.Errorf("commands: expire: update: %w", err)
	}
	var expired []string
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			rows.Close()
			return 0, fmt.Errorf("commands: expire: scan: %w", err)
		}
		expired = append(expired, cid)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("commands: expire: rows: %w", err)
	}
	rows.Close()

	details, _ := json.Marshal(map[string]string{"reason": ExpireReason})
	for _, cid := range expired {
		if err := events.AuditLogSyncTx(tx, SystemActor, "command.expired", "command", cid, string(details), ""); err != nil {
			return 0, fmt.Errorf("commands: expire: audit %s: %w", cid, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commands: expire: commit: %w", err)
	}
	return len(expired), nil
}

// RunExpirySweeper runs the TTL sweep on a ticker until ctx is cancelled
// (wired to server shutdown in main, per the F3 "goroutines respect
// shutdown" lesson). It is safe to run on EVERY Vantage instance:
// ExpireStaleQueued is a single atomic CAS UPDATE, so concurrent instances
// never double-expire or double-audit a command (multi-node invariant) — at
// worst they do redundant scans. Does NOT assume single-instance.
func RunExpirySweeper(ctx context.Context) {
	ticker := time.NewTicker(SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := ExpireStaleQueued(ctx)
			if err != nil {
				slog.Error("command TTL sweep failed", "error", err)
				continue
			}
			if n > 0 {
				slog.Info("command TTL sweep expired commands", "count", n)
			}
		}
	}
}

// casTransition is the shared compare-and-set core. It assembles
//
//	UPDATE command_queue SET <setClause>
//	WHERE correlation_id = $1 AND state = ANY($N)  -- N = legal predecessors
//
// Param layout: $1 = correlation_id, $2.. = the caller's setClause args, and
// the fromStates array is bound LAST (placeholder $N). On exactly-one-row it
// writes an audit entry (action/details); on zero rows it classifies the miss.
func casTransition(ctx context.Context, tx *sql.Tx, correlationID, edgeID, setClause string, fromStates []string, actorUserID, action, details string, args ...interface{}) error {
	// Param layout: $1 = correlation_id, $2.. = setClause args (caller's),
	// then the fromStates array, then edge_id (the edge-scope predicate).
	fromIdx := 2 + len(args)
	edgeIdx := fromIdx + 1
	query := fmt.Sprintf(
		`UPDATE command_queue SET %s WHERE correlation_id = $1 AND state = ANY($%d) AND edge_id = $%d`,
		setClause, fromIdx, edgeIdx)
	allArgs := make([]interface{}, 0, 3+len(args))
	allArgs = append(allArgs, correlationID)
	allArgs = append(allArgs, args...)
	allArgs = append(allArgs, pq.Array(fromStates), edgeID)

	res, err := tx.ExecContext(ctx, query, allArgs...)
	if err != nil {
		return fmt.Errorf("commands: %s: %w", action, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return classifyMiss(ctx, tx, correlationID)
	}
	return events.AuditLogSyncTx(tx, actorUserID, action, "command", correlationID, details, "")
}

// classifyMiss turns a zero-rows CAS into the right sentinel: ErrNotFound if
// the command doesn't exist, ErrInvalidTransition (carrying the current
// state) if it does but wasn't in a legal source state.
func classifyMiss(ctx context.Context, tx *sql.Tx, correlationID string) error {
	var st string
	switch err := tx.QueryRowContext(ctx, `SELECT state FROM command_queue WHERE correlation_id = $1`, correlationID).Scan(&st); {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("commands: classify miss: %w", err)
	default:
		return fmt.Errorf("%w (current=%s)", ErrInvalidTransition, st)
	}
}
