// Edge-side federation endpoints: register, poll (commit 10),
// events (commit 11). All consume the same /api/edge/* path
// prefix. register is the unauth bootstrap path (enrollment token);
// the others use EdgeAuthMiddleware (commit 9).

package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
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

