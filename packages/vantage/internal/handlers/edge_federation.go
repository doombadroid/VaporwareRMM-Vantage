// Edge-side federation endpoints: register, poll (commit 10),
// events (commit 11). All consume the same /api/edge/* path
// prefix. register is the unauth bootstrap path (enrollment token);
// the others use EdgeAuthMiddleware (commit 9).

package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/events"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/google/uuid"
)

// Edge bearer-token prefix: "vet_" = "vantage edge token". Visually
// distinct from enrollment tokens (vrt_) so operators can triage
// leaked secrets at a glance.
const edgeTokenPrefix = "vet_"

// edgeTokenTTL: 30 days per #22 Q2. The poll endpoint rotates the
// token when it's within the rotation window of expiry.
const edgeTokenTTL = 30 * 24 * time.Hour

// defaultPollInterval: 15 seconds per #22 Q1. Server-driven so a
// later phase can throttle individual Edges by extending it on a
// per-poll basis.
const defaultPollIntervalSeconds = 15

// tokenRotationWindow: if token_expires_at < now + window, the
// poll handler rotates the bearer and returns the new plaintext
// in the response. 7 days gives Edges plenty of margin to pick up
// the new token before the old one expires.
const tokenRotationWindow = 7 * 24 * time.Hour

// RegisterEdgeRoutes mounts the federation endpoints on the app.
// register is at the root group with its own rate limiter; the
// authed routes (commits 10/11) get wired through their own
// middleware chain.
func RegisterEdgeRoutes(app *fiber.App) {
	// Per-IP limiter on register: enrollment tokens are 256-bit
	// random, so brute-forcing is impossible in practice, but
	// rate-limiting still cuts off a misbehaving caller before
	// they fill the audit log with bogus attempts.
	//
	// Multi-node note (#22 Q10): Fiber's default limiter is
	// in-memory per process. With multi-node Vantage, each node
	// enforces its own quota — total fleet quota is N * 10 per
	// minute. A Redis-backed limiter is the upgrade path; F2
	// ships in-memory since single-node is the v1 deployment.
	registerLimiter := limiter.New(limiter.Config{
		Max:        10,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "rate limit exceeded; slow down",
				"code":  429,
			})
		},
	})
	app.Post("/api/edge/register", registerLimiter, registerEdge)

	// Authed federation endpoints. Edge presents Bearer token;
	// EdgeAuthMiddleware validates + attaches edge_id/tenant_id/
	// tailnet_identity to c.Locals.
	authed := app.Group("/api/edge", auth.EdgeAuthMiddleware())
	authed.Post("/poll", pollEdge)
	authed.Post("/events", postEdgeEvents)
}

// maxEventsPerBatch caps a single /api/edge/events request. F4's
// command-result pipeline batches a handful of results per poll
// cycle; 100 is generous headroom without enabling DoS.
const maxEventsPerBatch = 100

// knownEventTypes is the F2 allowlist. F4 will extend.
var knownEventTypes = map[string]bool{
	"heartbeat":         true,
	"alert":             true,
	"command_result":    true,
	"inventory_summary": true,
}

// postEdgeEvents accepts a batch of out-of-band events from Edge.
// Per issue #22 Q1, events push independently of polling so an
// alert can surface faster than the 15s poll cadence allows.
//
// F2 establishes the contract: validation, per-event accept/reject,
// audit checkpoint exchange. The downstream application of events
// (storing alert summaries, command-result correlation) lands with
// the F4 command pipeline.
func postEdgeEvents(c *fiber.Ctx) error {
	var req struct {
		Events []struct {
			CorrelationID string          `json:"correlation_id"`
			Type          string          `json:"type"`
			OccurredAt    int64           `json:"occurred_at"`
			Payload       json.RawMessage `json:"payload"`
		} `json:"events"`
		AuditChainHead struct {
			Seq       int64  `json:"seq"`
			Signature string `json:"signature"`
		} `json:"audit_chain_head"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if len(req.Events) > maxEventsPerBatch {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("batch size %d exceeds max %d", len(req.Events), maxEventsPerBatch),
		})
	}

	edgeID, _ := c.Locals("edge_id").(string)

	events.RecordAuditCheckpointSync("edge", edgeID, req.AuditChainHead.Seq, req.AuditChainHead.Signature, "events")

	type rejection struct {
		CorrelationID string `json:"correlation_id"`
		Reason        string `json:"reason"`
	}
	rejected := []rejection{}
	accepted := 0
	for _, e := range req.Events {
		if !knownEventTypes[e.Type] {
			rejected = append(rejected, rejection{
				CorrelationID: e.CorrelationID,
				Reason:        "unknown event type: " + e.Type,
			})
			continue
		}
		// F2 stub-handling: heartbeats are already implicitly
		// observed via last_seen_at in EdgeAuthMiddleware. The
		// other three types are logged for now and stored by F4
		// when the aggregates table lands.
		slog.Info("edge event",
			"edge_id", edgeID,
			"type", e.Type,
			"correlation_id", e.CorrelationID,
			"occurred_at", e.OccurredAt,
		)
		accepted++
	}

	events.AuditLog("", "edge.events.batch", "edge", edgeID,
		fmt.Sprintf("accepted=%d rejected=%d", accepted, len(rejected)), c.IP())

	return c.JSON(fiber.Map{
		"accepted": accepted,
		"rejected": rejected,
	})
}

// pollEdge handles /api/edge/poll. Issue #22 Q1 + Q5 + Q6 + Q9:
//
//   - Records the counterparty's audit chain head (cross-
//     attestation), then returns Vantage's own chain head.
//   - Refuses (426) if edge_version drops below the configured
//     MINIMUM_REQUIRED_EDGE_VERSION.
//   - Rotates the Edge bearer token if it's within the rotation
//     window (7 days). New plaintext returned in the response;
//     old token continues to work until expiry so the Edge has
//     a chance to persist the rotation before its current request
//     loop ends.
//   - Returns commands=[] for F2 (the command pipeline lands in
//     F4). Shape is locked so F4 just populates the slice.
func pollEdge(c *fiber.Ctx) error {
	var req struct {
		EdgeVersion     string `json:"edge_version"`
		AuditChainHead  struct {
			Seq       int64  `json:"seq"`
			Signature string `json:"signature"`
		} `json:"audit_chain_head"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}

	edgeID, _ := c.Locals("edge_id").(string)
	minimum := os.Getenv("MINIMUM_REQUIRED_EDGE_VERSION")
	ok, err := versionAtLeast(req.EdgeVersion, minimum)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "malformed edge_version: " + err.Error(),
		})
	}
	if !ok {
		return c.Status(fiber.StatusUpgradeRequired).JSON(fiber.Map{
			"error":                fmt.Sprintf("edge_version %s below minimum %s", req.EdgeVersion, minimum),
			"code":                 426,
			"required_min_version": minimum,
			"current_version":      req.EdgeVersion,
		})
	}

	// Update Edge's reported version on every poll so the operator
	// dashboard reflects current state without waiting for the next
	// register. Best-effort.
	if _, err := db.DB.Exec(`UPDATE edges SET edge_version = $1 WHERE id = $2`, req.EdgeVersion, edgeID); err != nil {
		slog.Warn("poll: edge_version update", "error", err, "edge_id", edgeID)
	}

	// Cross-attestation: persist the counterparty's chain head.
	// Synchronous so the audit_checkpoints row is durable before
	// the response leaves.
	events.RecordAuditCheckpointSync("edge", edgeID, req.AuditChainHead.Seq, req.AuditChainHead.Signature, "poll")

	// Token rotation. Inside a transaction with FOR UPDATE so
	// concurrent polls from the same Edge (rare; clock skew) can't
	// double-rotate.
	rotatedToken, newExpiresAt, err := maybeRotateToken(edgeID)
	if err != nil {
		slog.Error("poll: rotate check", "error", err, "edge_id", edgeID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rotation check failed"})
	}

	vantageSeq, vantageSig, _ := events.LatestChainHead()

	resp := fiber.Map{
		"vantage_version": "0.1.0",
		"audit_chain_head": fiber.Map{
			"seq":       vantageSeq,
			"signature": vantageSig,
		},
		"commands":                  json.RawMessage("[]"),
		"next_poll_after_seconds":   defaultPollIntervalSeconds,
		"min_required_edge_version": minimum,
	}
	if rotatedToken != "" {
		resp["new_edge_token"] = rotatedToken
		resp["new_token_expires_at"] = newExpiresAt
	} else {
		resp["new_edge_token"] = nil
	}
	return c.JSON(resp)
}

// maybeRotateToken atomically checks expiry and rotates if needed.
// Returns the new plaintext token (empty if no rotation) and the
// new expiry timestamp.
func maybeRotateToken(edgeID string) (string, int64, error) {
	tx, err := db.DB.Begin()
	if err != nil {
		return "", 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var expiresAt sql.NullInt64
	if err := tx.QueryRow(
		`SELECT token_expires_at FROM edges WHERE id = $1 FOR UPDATE`,
		edgeID,
	).Scan(&expiresAt); err != nil {
		return "", 0, fmt.Errorf("read expiry: %w", err)
	}
	if !expiresAt.Valid {
		return "", 0, nil
	}
	now := time.Now()
	threshold := now.Add(tokenRotationWindow).Unix()
	if expiresAt.Int64 > threshold {
		// Not yet within rotation window.
		return "", 0, nil
	}

	newPlain, err := generateEdgeToken()
	if err != nil {
		return "", 0, fmt.Errorf("generate: %w", err)
	}
	newHash := auth.HashToken(newPlain)
	newExpires := now.Add(edgeTokenTTL).Unix()
	if _, err := tx.Exec(
		`UPDATE edges
		     SET token_hash = $1, token_issued_at = $2, token_expires_at = $3
		     WHERE id = $4`,
		newHash, now.Unix(), newExpires, edgeID,
	); err != nil {
		return "", 0, fmt.Errorf("rotate update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("commit: %w", err)
	}

	events.AuditLogSync("", "edge.token.rotated", "edge", edgeID, "polled within rotation window", "")
	return newPlain, newExpires, nil
}

// registerEdge consumes an enrollment token + issues a long-lived
// Edge bearer token. The two side effects (consume enrollment +
// insert edge) happen inside one transaction so single-use
// semantics are enforced by the database, not the application.
func registerEdge(c *fiber.Ctx) error {
	var req struct {
		EnrollmentToken string `json:"enrollment_token"`
		EdgeVersion     string `json:"edge_version"`
		EdgeHostname    string `json:"edge_hostname"`
		TailnetIdentity string `json:"tailnet_identity"`
		TailnetIP       string `json:"tailnet_ip"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.EnrollmentToken == "" || req.EdgeVersion == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "enrollment_token and edge_version required"})
	}

	// Version floor: refuse below MINIMUM_REQUIRED_EDGE_VERSION
	// with 426 Upgrade Required, per #22 Q6.
	minimum := os.Getenv("MINIMUM_REQUIRED_EDGE_VERSION")
	ok, err := versionAtLeast(req.EdgeVersion, minimum)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "malformed edge_version: " + err.Error(),
		})
	}
	if !ok {
		return c.Status(fiber.StatusUpgradeRequired).JSON(fiber.Map{
			"error":                fmt.Sprintf("edge_version %s below minimum %s; update Edge before continuing", req.EdgeVersion, minimum),
			"code":                 426,
			"required_min_version": minimum,
			"current_version":      req.EdgeVersion,
		})
	}

	tokenHash := auth.HashToken(req.EnrollmentToken)

	// Inside the transaction: look up the enrollment token, validate
	// not-consumed and not-expired, insert the new edges row, mark
	// the enrollment_token consumed. If any step fails, both
	// sides roll back together so the token stays single-use.
	tx, err := db.DB.Begin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "transaction begin failed"})
	}
	defer func() {
		// Rollback is a no-op after a successful Commit. If we
		// returned early on error, this rolls back state.
		_ = tx.Rollback()
	}()

	var (
		etID         string
		etTenantID   string
		etExpiresAt  int64
		etConsumedAt sql.NullInt64
	)
	if err := tx.QueryRow(
		`SELECT id, tenant_id, expires_at, consumed_at FROM enrollment_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&etID, &etTenantID, &etExpiresAt, &etConsumedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unknown enrollment token"})
		}
		slog.Error("edge register: enrollment lookup", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "enrollment lookup failed"})
	}
	if etConsumedAt.Valid {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "enrollment token already consumed"})
	}
	now := time.Now()
	if etExpiresAt < now.Unix() {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "enrollment token expired"})
	}

	edgeID := uuid.New().String()
	edgeTokenPlain, err := generateEdgeToken()
	if err != nil {
		slog.Error("edge register: generate token", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate edge token"})
	}
	edgeTokenHash := auth.HashToken(edgeTokenPlain)
	tokenExpiresAt := now.Add(edgeTokenTTL).Unix()

	if _, err := tx.Exec(
		`INSERT INTO edges
		     (id, name, tenant_id, tailnet_identity, tailnet_ip,
		      token_hash, token_issued_at, token_expires_at,
		      edge_version, status, last_seen_at, created_at,
		      enrollment_token_id)
		     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11, $12)`,
		edgeID,
		nullableString(req.EdgeHostname),
		etTenantID,
		nullableString(req.TailnetIdentity),
		nullableString(req.TailnetIP),
		edgeTokenHash,
		now.Unix(),
		tokenExpiresAt,
		req.EdgeVersion,
		now.Unix(),
		now.Unix(),
		etID,
	); err != nil {
		slog.Error("edge register: insert edge", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create edge record"})
	}

	if _, err := tx.Exec(
		`UPDATE enrollment_tokens
		     SET consumed_at = $1, consumed_by_edge_id = $2
		     WHERE id = $3`,
		now.Unix(), edgeID, etID,
	); err != nil {
		slog.Error("edge register: mark consumed", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to mark enrollment consumed"})
	}

	if err := tx.Commit(); err != nil {
		slog.Error("edge register: commit", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "registration commit failed"})
	}

	// Audit synchronously: the bearer token returned to the caller
	// is operative immediately, so the trace must be durable before
	// it leaves the server.
	events.AuditLogSync("", "edge.register", "edge", edgeID,
		fmt.Sprintf("registered via enrollment %s for tenant %s; version=%s", etID, etTenantID, req.EdgeVersion),
		c.IP())

	return c.JSON(fiber.Map{
		"edge_id":               edgeID,
		"edge_token":            edgeTokenPlain,
		"token_expires_at":      tokenExpiresAt,
		"poll_interval_seconds": defaultPollIntervalSeconds,
	})
}

// generateEdgeToken returns a fresh `vet_<43-char base64>` string.
// 32 random bytes ≈ 256 bits of entropy.
func generateEdgeToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return edgeTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

