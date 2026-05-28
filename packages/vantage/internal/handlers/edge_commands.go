package handlers

// F4a: the Edge side of the command pipeline (Decision 2 — poll delivers,
// a dedicated ack transitions state).
//
//   - fetchPendingCommands: select the commands to hand an Edge in its poll
//     response. Poll does NOT change command STATE (the queued->delivered_to_
//     edge transition is the ack's job); it only stamps the poll_delivered_at
//     delivery marker atomically with the select.
//   - POST /api/edge/commands/ack: the Edge persisted the commands locally
//     and now acks; we transition queued -> delivered_to_edge. Idempotent and
//     edge-scoped.

import (
	"encoding/json"
	"errors"
	"fmt"

	"vaporrmm/vantage/internal/commands"
	"vaporrmm/vantage/internal/db"

	"github.com/gofiber/fiber/v2"
)

// maxAckBatch bounds one ack request. A poll delivers at most 50 commands, so
// 500 is generous headroom while still bounding the transaction.
const maxAckBatch = 500

// ackGraceSeconds is the TTL margin a queued command must have left before
// poll will deliver it. It closes the deliver-then-expire race (codex round 2
// #1): a command delivered in a poll response is still `queued`, and the TTL
// sweeper expires `queued` rows past expires_at — so a command handed out just
// before expiry could be marked expired before its ack arrives, after which
// the Edge runs it but the result lands on a terminal `expired` row and is
// dropped. By refusing to deliver a queued command within ackGraceSeconds of
// expiry, any delivered command has at least this much time to be acked (the
// Edge acks within ~one poll cycle), so the sweep can't expire it first. The
// sweeper still uses expires_at <= now, so commands in the [now, now+grace)
// band are simply not delivered and expire untouched (never handed out =
// correctly edge_unreachable). 60s = four 15s poll intervals of headroom.
const ackGraceSeconds = 60

// pollCommandDTO is one command delivered in a poll response.
type pollCommandDTO struct {
	CorrelationID    string          `json:"correlation_id"`
	TargetEndpointID string          `json:"target_endpoint_id"`
	CommandType      string          `json:"command_type"`
	CommandParams    json.RawMessage `json:"command_params"`
}

// fetchPendingCommands returns the commands to deliver to an Edge: queued (not
// yet delivered) plus delivered_to_edge (Edge hasn't acked — re-deliver for
// idempotency; the Edge dedupes on correlation_id). State does NOT change on
// poll; the queued->delivered_to_edge transition happens on ACK (Decision 2).
//
// It is a single atomic UPDATE ... RETURNING (codex round 3 #1): the rows it
// hands out get poll_delivered_at stamped in the SAME statement, so there is
// no window where a command is delivered but unmarked — MarkCancelled's
// poll_delivered_at IS NULL guard then can't race a concurrent poll. nowUnix
// MUST be a fresh time.Now() captured by the caller right before this call
// (codex round 3 #4) — a stale value could let an already-near-expiry command
// slip past the grace filter.
//
// The inner CTE selects the rows with FOR UPDATE SKIP LOCKED (so concurrent
// multi-node polls don't double-hand-out the same row) applying:
//   - the TTL grace margin to queued rows ONLY (codex round 2 #1): a queued
//     command is delivered only with > ackGraceSeconds of TTL left, so it can
//     be acked before the sweep (expires_at <= now) could expire it;
//   - always re-polling delivered_to_edge rows regardless of expires_at (codex
//     round 1 #3), so an Edge that lost its local copy recovers the command;
//   - queued-first ordering under the LIMIT (codex round 2 #5), so a backlog
//     of stuck redeliveries can't starve newly queued commands.
//
// poll_delivered_at uses COALESCE so the marker is set on the first hand-out
// and never updated — it gates the cancel-vs-poll race for queued rows. The
// cancel-vs-poll race for delivered_to_edge is closed by a stabilization
// window on delivered_to_edge_at in MarkCancelled (codex review of PR #3
// round 3 #1), not by refreshing a poll-time marker on every re-delivery: a
// re-polled marker would always be fresh for an actively-polling Edge and
// the cancel widening would never trigger.
//
// The RETURNING order is unspecified but irrelevant (the Edge processes every
// command).
func fetchPendingCommands(edgeID string, nowUnix int64) ([]pollCommandDTO, error) {
	rows, err := db.DB.Query(`
		WITH picked AS (
			SELECT correlation_id
			FROM command_queue
			WHERE edge_id = $1
			  AND ( (state = 'queued' AND expires_at > $3) OR state = 'delivered_to_edge' )
			ORDER BY (state <> 'queued'), queued_at ASC
			LIMIT 50
			FOR UPDATE SKIP LOCKED
		)
		UPDATE command_queue c
		SET poll_delivered_at = COALESCE(c.poll_delivered_at, $2)
		FROM picked
		WHERE c.correlation_id = picked.correlation_id
		RETURNING c.correlation_id, c.target_endpoint_id, c.command_type, c.command_params`,
		edgeID, nowUnix, nowUnix+ackGraceSeconds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []pollCommandDTO{}
	for rows.Next() {
		var cmd pollCommandDTO
		if err := rows.Scan(&cmd.CorrelationID, &cmd.TargetEndpointID, &cmd.CommandType, &cmd.CommandParams); err != nil {
			return nil, err
		}
		out = append(out, cmd)
	}
	return out, rows.Err()
}

// maxCancelSignalBatch bounds one poll's cancel signal so an Edge with a
// large unconfirmed backlog (offline, slow to confirm, or buggy) doesn't blow
// the response past proxy/client limits and starve itself of the signal
// entirely (codex review of PR #3 round 4 #4). 200 matches the headroom on
// the commands cap (50) and lets a typical Edge drain a backlog over a few
// poll cycles — Edge confirms each delivered cancellation via
// command.result(cancelled), the corresponding row drops out, and the next
// poll surfaces the next batch.
const maxCancelSignalBatch = 200

// fetchCancelledCorrelationIDs returns correlation_ids of commands the operator
// cancelled while they were still pre-dispatch (state='cancelled' and never
// reached delivered_to_endpoint) AND that this Edge has not yet acknowledged
// via command.result(status=cancelled). F4b includes these in the poll
// response so the Edge can drop them between persist and dispatch (Decision 6
// cancel window restoration; see commands.MarkCancelled).
//
// Filtering on cancellation_confirmed_at IS NULL (codex review of PR #3 round
// 2 #6) replaces the round-1 7-day retention bound: an Edge offline longer
// than the retention window would otherwise lose its signal and dispatch a
// local 'received' row that Vantage has terminal-cancelled. Now an unconfirmed
// cancellation stays in the signal indefinitely; the Edge confirms via the
// cancellation_confirmed event and the row drops out.
//
// delivered_to_endpoint_at IS NULL is belt-and-suspenders: MarkCancelled's
// state predicate already implies no delivered_to_endpoint transition fired,
// but the explicit NULL guard keeps the cancel signal honest even if a future
// state-machine change widens the cancel predicate. ORDER BY terminal_at ASC
// drains oldest cancellations first so a long backlog converges deterministically.
func fetchCancelledCorrelationIDs(edgeID string) ([]string, error) {
	rows, err := db.DB.Query(`
		SELECT correlation_id FROM command_queue
		WHERE edge_id = $1
		  AND state = 'cancelled'
		  AND delivered_to_endpoint_at IS NULL
		  AND cancellation_confirmed_at IS NULL
		ORDER BY terminal_at ASC
		LIMIT $2`, edgeID, maxCancelSignalBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		out = append(out, cid)
	}
	return out, rows.Err()
}

func postEdgeCommandsAck(c *fiber.Ctx) error {
	var req struct {
		AckedCorrelationIDs []string `json:"acked_correlation_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if len(req.AckedCorrelationIDs) > maxAckBatch {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("ack batch %d exceeds max %d", len(req.AckedCorrelationIDs), maxAckBatch),
		})
	}
	edgeID, _ := c.Locals("edge_id").(string)

	tx, err := db.DB.Begin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "transaction begin failed"})
	}
	defer func() { _ = tx.Rollback() }()

	ctx := c.UserContext()
	acked := 0
	for _, cid := range req.AckedCorrelationIDs {
		switch err := commands.MarkDeliveredToEdge(ctx, tx, cid, edgeID); {
		case err == nil:
			acked++
		case errors.Is(err, commands.ErrInvalidTransition), errors.Is(err, commands.ErrNotFound):
			// Benign: already delivered_to_edge or later, terminal, not owned
			// by this Edge, or gone. Idempotent — don't fail the batch.
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "ack failed"})
		}
	}
	if err := tx.Commit(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "commit failed"})
	}
	return c.JSON(fiber.Map{"acked": acked})
}
