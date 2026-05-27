package handlers

// F4a: the Edge side of the command pipeline (Decision 2 — poll delivers,
// a dedicated ack transitions state).
//
//   - fetchPendingCommands: read the commands to hand an Edge in its poll
//     response. Poll does NOT mutate command state.
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
// The TTL filter applies ONLY to queued rows, and with an ackGraceSeconds
// margin (codex round 2 #1): a queued command is delivered only if it has more
// than ackGraceSeconds of TTL left, guaranteeing time to ack before the sweep
// (expires_at <= now) could expire it. delivered_to_edge rows are ALWAYS
// re-pollable regardless of expires_at — the queued TTL no longer applies once
// the Edge acked, and re-delivery lets an Edge that lost its local copy (crash
// before dispatch) recover the command rather than strand it (codex round 1 #3).
//
// Ordering puts queued commands FIRST (codex round 2 #5): with the LIMIT, a
// backlog of stuck delivered_to_edge redeliveries must not crowd out newly
// queued commands — new operator intent always flows; redeliveries (recovery
// insurance for an Edge that already has the command) fill the spare slots.
func fetchPendingCommands(edgeID string, nowUnix int64) ([]pollCommandDTO, error) {
	rows, err := db.DB.Query(`
		SELECT correlation_id, target_endpoint_id, command_type, command_params
		FROM command_queue
		WHERE edge_id = $1
		  AND ( (state = 'queued' AND expires_at > $2) OR state = 'delivered_to_edge' )
		ORDER BY (state <> 'queued'), queued_at ASC
		LIMIT 50`, edgeID, nowUnix+ackGraceSeconds)
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
