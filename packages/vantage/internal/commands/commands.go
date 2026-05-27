// Package commands implements the F4 command lifecycle state machine for
// Vantage. An operator queues a command; the Edge polls, receives, and
// dispatches it to an endpoint; results flow back. Vantage owns the
// authoritative queue and the operator-facing state (issue #22 Q1/Q4/Q5).
//
// State machine (Decision 6 adds "cancelled"):
//
//	queued ──► delivered_to_edge ──► delivered_to_endpoint ──► executing
//	                                          │                    │
//	                                          └────────┬───────────┘
//	                                                   ▼
//	                                           succeeded | failed
//	queued ──► expired                       (TTL sweep, edge_unreachable)
//	queued | delivered_to_edge ──► cancelled (operator, pre-dispatch only)
//
// succeeded/failed/expired/cancelled are terminal sinks (no transitions out).
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

// MarkDeliveredToEndpoint: delivered_to_edge → delivered_to_endpoint, when the
// Edge reports the agent received the command (via /api/edge/events).
func MarkDeliveredToEndpoint(ctx context.Context, tx *sql.Tx, correlationID, edgeID string) error {
	return casTransition(ctx, tx, correlationID, edgeID,
		"state = 'delivered_to_endpoint', delivered_to_endpoint_at = $2",
		[]string{StateDeliveredToEdge},
		SystemActor, "command.delivered_to_endpoint", "", time.Now().Unix())
}

// MarkExecuting: delivered_to_endpoint → executing.
func MarkExecuting(ctx context.Context, tx *sql.Tx, correlationID, edgeID string) error {
	return casTransition(ctx, tx, correlationID, edgeID,
		"state = 'executing'",
		[]string{StateDeliveredToEndpoint},
		SystemActor, "command.executing", "")
}

// MarkTerminal: delivered_to_endpoint|executing → succeeded|failed. Both
// source states are legal so fast-returning commands that never reported an
// explicit "executing" event still terminate correctly.
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
		[]string{StateDeliveredToEndpoint, StateExecuting},
		SystemActor, "command.terminal", string(details),
		status, message, now)
}

// MarkCancelled: queued|delivered_to_edge → cancelled (Decision 6 — refuse
// once delivered_to_endpoint or later). actorUserID is the operator.
// Returns ErrNotCancellable if the command is past the cancellable window,
// ErrNotFound if it doesn't exist.
func MarkCancelled(ctx context.Context, tx *sql.Tx, correlationID, actorUserID string) error {
	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx, `
		UPDATE command_queue
		SET state = 'cancelled', result_status = 'cancelled',
			result_message = 'cancelled by operator', terminal_at = $2
		WHERE correlation_id = $1 AND state IN ('queued', 'delivered_to_edge')`,
		correlationID, now)
	if err != nil {
		return fmt.Errorf("commands: cancel: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Distinguish not-found from past-the-window for the handler's status.
		var st string
		switch err := tx.QueryRowContext(ctx, `SELECT state FROM command_queue WHERE correlation_id = $1`, correlationID).Scan(&st); {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("commands: cancel classify: %w", err)
		default:
			return fmt.Errorf("%w (current=%s)", ErrNotCancellable, st)
		}
	}
	return events.AuditLogSyncTx(tx, actorUserID, "command.cancelled", "command", correlationID, "", "")
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
