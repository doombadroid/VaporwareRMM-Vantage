package handlers

// F4a: operator-facing command queue API (issue #22 Q1/Q5/Q7).
//
//	POST   /api/v1/commands                  enqueue (expand targets, queue)
//	DELETE /api/v1/commands/:correlation_id  cancel (pre-dispatch only)
//	GET    /api/v1/commands                  list (operator UI)
//
// Mutations require super_admin (the operator role). Vantage has no
// per-user tenant — super_admins are global; a queued command inherits the
// TARGET EDGE's tenant_id. Tag targets are expanded to explicit endpoint_ids
// here (Q7) against the membership the Edge mirrored via /api/edge/tags/sync.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/commands"
	"vaporrmm/vantage/internal/db"

	"github.com/gofiber/fiber/v2"
	"github.com/lib/pq"
)

// maxTargetsPerEnqueue bounds the fan-out of one enqueue request so a single
// tag covering a huge fleet can't open an unbounded transaction.
const maxTargetsPerEnqueue = 1000

// RegisterCommandRoutes wires the operator command endpoints onto the authed
// API group (AuthMiddleware + CSRFMiddleware already applied by the caller).
func RegisterCommandRoutes(g fiber.Router) {
	g.Post("/commands", enqueueCommandsHandler)
	g.Delete("/commands/:correlation_id", cancelCommandHandler)
	g.Get("/commands", listCommandsHandler)
}

// restartServiceParams is the only command_type's params in F4.
type restartServiceParams struct {
	ServiceName string `json:"service_name"`
}

func enqueueCommandsHandler(c *fiber.Ctx) error {
	role, _ := c.Locals("user_role").(string)
	if !auth.IsSuperAdmin(role) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "super_admin required"})
	}
	userID, _ := c.Locals("user_id").(string)

	// ---- Phase 1: parse + validate (no DB writes) ----
	var req struct {
		EdgeID  string `json:"edge_id"`
		Targets struct {
			Kind   string   `json:"kind"`
			Values []string `json:"values"`
		} `json:"targets"`
		CommandType   string          `json:"command_type"`
		CommandParams json.RawMessage `json:"command_params"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.EdgeID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "edge_id is required"})
	}
	if req.Targets.Kind != "endpoint" && req.Targets.Kind != "tag" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "targets.kind must be 'endpoint' or 'tag'"})
	}
	if len(req.Targets.Values) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "targets.values must not be empty"})
	}
	if req.CommandType != "restart_service" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "command_type must be 'restart_service'"})
	}
	// Validate restart_service params: a non-empty service_name, nothing else.
	var rsp restartServiceParams
	if err := json.Unmarshal(req.CommandParams, &rsp); err != nil || rsp.ServiceName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "command_params.service_name is required for restart_service"})
	}

	// ---- Phase 2: reads (validate edge, expand targets) ----
	var edgeTenant string
	switch err := db.DB.QueryRow(`SELECT tenant_id FROM edges WHERE id = $1`, req.EdgeID).Scan(&edgeTenant); {
	case errors.Is(err, sql.ErrNoRows):
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "edge not found"})
	case err != nil:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "edge lookup failed"})
	}

	endpointIDs, err := expandTargets(req.EdgeID, req.Targets.Kind, req.Targets.Values)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "target expansion failed"})
	}
	if len(endpointIDs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "no target endpoints (tag has no members, or no endpoint ids supplied)",
		})
	}
	if len(endpointIDs) > maxTargetsPerEnqueue {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "target set exceeds max " + strconv.Itoa(maxTargetsPerEnqueue),
		})
	}

	// ---- Phase 3: single transaction wraps all inserts ----
	tx, err := db.DB.Begin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "transaction begin failed"})
	}
	defer func() { _ = tx.Rollback() }()

	ctx := c.UserContext()
	correlationIDs := make([]string, 0, len(endpointIDs))
	for _, ep := range endpointIDs {
		cid, err := commands.EnqueueCommand(ctx, tx, commands.EnqueueRequest{
			TenantID:         edgeTenant,
			EdgeID:           req.EdgeID,
			TargetEndpointID: ep,
			CommandType:      req.CommandType,
			CommandParams:    req.CommandParams,
			OperatorUserID:   userID,
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "enqueue failed"})
		}
		correlationIDs = append(correlationIDs, cid)
	}
	if err := tx.Commit(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "commit failed"})
	}

	// ---- Phase 4: response ----
	return c.JSON(fiber.Map{"correlation_ids": correlationIDs})
}

// expandTargets resolves a targets spec to a deduplicated endpoint_id set.
// kind=endpoint: the values ARE endpoint ids. kind=tag: join membership for
// this edge's tags named in values.
func expandTargets(edgeID, kind string, values []string) ([]string, error) {
	if kind == "endpoint" {
		seen := make(map[string]bool, len(values))
		out := make([]string, 0, len(values))
		for _, v := range values {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
		return out, nil
	}
	// kind == "tag"
	rows, err := db.DB.Query(`
		SELECT DISTINCT tem.endpoint_id
		FROM tag_endpoint_membership tem
		JOIN tags t ON t.id = tem.tag_id
		WHERE t.edge_id = $1 AND t.name = ANY($2)`,
		edgeID, pq.Array(values))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ep string
		if err := rows.Scan(&ep); err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

func cancelCommandHandler(c *fiber.Ctx) error {
	role, _ := c.Locals("user_role").(string)
	if !auth.IsSuperAdmin(role) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "super_admin required"})
	}
	userID, _ := c.Locals("user_id").(string)
	correlationID := c.Params("correlation_id")
	if correlationID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "correlation_id is required"})
	}

	tx, err := db.DB.Begin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "transaction begin failed"})
	}
	defer func() { _ = tx.Rollback() }()

	switch err := commands.MarkCancelled(c.UserContext(), tx, correlationID, userID); {
	case errors.Is(err, commands.ErrNotFound):
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "command not found"})
	case errors.Is(err, commands.ErrNotCancellable):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "command already dispatched to endpoint or terminal; cannot cancel",
			"code":  "not_cancellable",
		})
	case err != nil:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "cancel failed"})
	}
	if err := tx.Commit(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "commit failed"})
	}
	return c.JSON(fiber.Map{"cancelled": correlationID})
}

// CommandRow is the JSON shape for the operator command list. result_message
// is the brief operator-facing string; endpoint output stays on the Edge (Q4).
type CommandRow struct {
	CorrelationID         string `json:"correlation_id"`
	EdgeID                string `json:"edge_id"`
	TenantID              string `json:"tenant_id"`
	TargetEndpointID      string `json:"target_endpoint_id"`
	CommandType           string `json:"command_type"`
	State                 string `json:"state"`
	ResultStatus          string `json:"result_status,omitempty"`
	ResultMessage         string `json:"result_message,omitempty"`
	QueuedAt              int64  `json:"queued_at"`
	DeliveredToEdgeAt     int64  `json:"delivered_to_edge_at,omitempty"`
	DeliveredToEndpointAt int64  `json:"delivered_to_endpoint_at,omitempty"`
	TerminalAt            int64  `json:"terminal_at,omitempty"`
	ExpiresAt             int64  `json:"expires_at"`
}

func listCommandsHandler(c *fiber.Ctx) error {
	limit, offset := parsePagination(c)

	// Optional filters: edge_id, state, tenant_id. Build the WHERE clause
	// from whichever are present (positional args track the count).
	var conds []string
	var args []interface{}
	add := func(clause string, val string) {
		args = append(args, val)
		conds = append(conds, clause+" $"+strconv.Itoa(len(args)))
	}
	if v := c.Query("edge_id"); v != "" {
		add("edge_id =", v)
	}
	if v := c.Query("tenant_id"); v != "" {
		add("tenant_id =", v)
	}
	if v := c.Query("state"); v != "" {
		if !validState(v) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid state filter"})
		}
		add("state =", v)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + conds[0]
		for _, cd := range conds[1:] {
			where += " AND " + cd
		}
	}

	var total int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM command_queue `+where, args...).Scan(&total); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "count failed"})
	}

	// limit/offset are the next two positional args.
	limOffArgs := append(append([]interface{}{}, args...), limit, offset)
	q := `SELECT correlation_id, edge_id, tenant_id, target_endpoint_id, command_type, state,
	             COALESCE(result_status, ''), COALESCE(result_message, ''),
	             queued_at, COALESCE(delivered_to_edge_at, 0), COALESCE(delivered_to_endpoint_at, 0),
	             COALESCE(terminal_at, 0), expires_at
	        FROM command_queue ` + where +
		` ORDER BY queued_at DESC LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)
	rows, err := db.DB.Query(q, limOffArgs...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "query failed"})
	}
	defer rows.Close()

	out := []CommandRow{}
	for rows.Next() {
		var r CommandRow
		if err := rows.Scan(&r.CorrelationID, &r.EdgeID, &r.TenantID, &r.TargetEndpointID, &r.CommandType, &r.State,
			&r.ResultStatus, &r.ResultMessage, &r.QueuedAt, &r.DeliveredToEdgeAt, &r.DeliveredToEndpointAt,
			&r.TerminalAt, &r.ExpiresAt); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "scan failed"})
		}
		out = append(out, r)
	}
	return c.JSON(fiber.Map{
		"data":     out,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+len(out) < total,
	})
}

func validState(s string) bool {
	switch s {
	case commands.StateQueued, commands.StateDeliveredToEdge, commands.StateDeliveredToEndpoint,
		commands.StateExecuting, commands.StateSucceeded, commands.StateFailed,
		commands.StateExpired, commands.StateCancelled:
		return true
	}
	return false
}
