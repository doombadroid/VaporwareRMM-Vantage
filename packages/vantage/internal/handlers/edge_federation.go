// Edge-side federation endpoints: register, poll (commit 10),
// events (commit 11). All consume the same /api/edge/* path
// prefix. register is the unauth bootstrap path (enrollment token);
// the others use EdgeAuthMiddleware (commit 9).

package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
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

// ErrTokenHashMismatch fires from maybeRotateToken when the
// presented token hash no longer matches the edges row inside the
// rotation transaction. A concurrent poll rotated the token after
// the middleware validated it but before this request reached the
// rotation step. The caller must reject with 401 so the Edge
// re-presents whatever token won that race.
var ErrTokenHashMismatch = errors.New("edge token hash mismatch")

// RegisterEdgeRoutes mounts the federation endpoints on the app.
// register is at the root group with its own rate limiter; the
// authed routes (commits 10/11) get wired through their own
// middleware chain.
func RegisterEdgeRoutes(app *fiber.App) {
	// Per-enrollment-token limiter on register. Codex finding #3
	// flagged that c.IP() collapses to the reverse proxy's address
	// behind Caddy, making per-IP buckets useless. Key by a hash
	// of the enrollment_token from the request body so the limit
	// is "10 attempts on this specific token per minute" — the
	// attack surface the limit actually defends against (brute-
	// forcing a known-issued enrollment token).
	//
	// Body-parse note: Fiber caches the request body in
	// c.Request().Body() and re-reads on every BodyParser call,
	// so the downstream handler can still parse normally after
	// the KeyGenerator peeks at it.
	//
	// Multi-node note (#22 Q10): Fiber's default limiter is
	// in-memory per process. With multi-node Vantage, each node
	// enforces its own quota — total fleet quota is N * 10 per
	// token per minute. A Redis-backed limiter is the upgrade
	// path; F2 ships in-memory since single-node is the v1
	// deployment.
	registerLimiter := limiter.New(limiter.Config{
		Max:        10,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			var body struct {
				EnrollmentToken string `json:"enrollment_token"`
			}
			if err := c.BodyParser(&body); err != nil {
				return "ip:" + c.IP()
			}
			if body.EnrollmentToken == "" {
				return "ip:" + c.IP()
			}
			sum := sha256.Sum256([]byte(body.EnrollmentToken))
			return "tok:" + hex.EncodeToString(sum[:])[:16]
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
	if auditChainHeadInvalid(c, req.AuditChainHead.Seq, req.AuditChainHead.Signature) {
		return nil
	}

	edgeID, _ := c.Locals("edge_id").(string)

	if err := events.RecordAuditCheckpointSync("edge", edgeID, req.AuditChainHead.Seq, req.AuditChainHead.Signature, "events"); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to record audit checkpoint",
			"code":  "checkpoint_write_failed",
		})
	}

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
//     window (7 days). The rotation is ATOMIC: the UPDATE
//     overwrites token_hash in one statement, so the old token is
//     invalidated server-side the instant the response is built.
//   - Returns commands=[] for F2 (the command pipeline lands in
//     F4). Shape is locked so F4 just populates the slice.
//
// Atomic rotation contract (F3 implementer note):
//   When the response carries new_edge_token, the old token is
//   already dead. The Edge MUST persist the new token (atomic
//   write — e.g., write to token.new, fsync, rename to token)
//   before issuing any subsequent request. If the persist fails
//   or the response is lost mid-flight, the Edge will see 401 on
//   the next request and must fall back to re-enrollment via the
//   operator-issued bundle. No grace window — the simpler
//   contract closes a race where an attacker who captured the
//   old token could use it during a rotation overlap.
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
	if auditChainHeadInvalid(c, req.AuditChainHead.Seq, req.AuditChainHead.Signature) {
		return nil
	}

	edgeID, _ := c.Locals("edge_id").(string)
	minimum := os.Getenv("MINIMUM_REQUIRED_EDGE_VERSION")
	ok, err := versionAtLeast(req.EdgeVersion, minimum)
	if err != nil {
		// Server-side MINIMUM_REQUIRED_EDGE_VERSION is validated
		// at boot (ValidateMinEdgeVersion in version.go), so any
		// versionAtLeast error here is unambiguously the client
		// sending a malformed edge_version.
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "malformed edge_version: " + err.Error(),
			"code":  "invalid_edge_version",
		})
	}
	if !ok {
		return c.Status(fiber.StatusUpgradeRequired).JSON(fiber.Map{
			"error":                "edge version below minimum required",
			"code":                 "edge_version_below_minimum",
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
	// the response leaves. A write failure here breaks the
	// tamper-evidence contract; fail loudly (codex round-3 #3).
	if err := events.RecordAuditCheckpointSync("edge", edgeID, req.AuditChainHead.Seq, req.AuditChainHead.Signature, "poll"); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to record audit checkpoint",
			"code":  "checkpoint_write_failed",
		})
	}

	// Token rotation. Re-hash the bearer the request arrived with;
	// maybeRotateToken's tx revalidates that hash against the row
	// (defense against concurrent-poll races where the middleware
	// validated against a token that's since been rotated by a
	// peer request — codex round-3 finding #1).
	presentedToken := extractBearerToken(c)
	presentedHash := auth.HashToken(presentedToken)
	rotatedToken, newExpiresAt, err := maybeRotateToken(edgeID, presentedHash)
	if errors.Is(err, ErrTokenHashMismatch) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "token has been rotated concurrently; re-authenticate with the latest token",
			"code":  "token_concurrently_rotated",
		})
	}
	if err != nil {
		slog.Error("poll: rotate check", "error", err, "edge_id", edgeID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rotation check failed"})
	}

	vantageSeq, vantageSig, err := events.LatestChainHead()
	if err != nil {
		// Codex round-3 finding #2: chain state is load-bearing
		// for cross-attestation. A genesis-shaped (0/"") response
		// would silently degrade the tamper-evidence contract
		// from #22 Q9. Fail loudly.
		slog.Error("poll: read vantage chain head", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to read chain state",
			"code":  "chain_read_failed",
		})
	}

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
// presentedTokenHash is the SHA-256 of the bearer token the request
// arrived with. Inside the transaction we re-read token_hash with
// a row lock and refuse to rotate if it no longer matches — a
// concurrent poll has already rotated and this request is holding
// a stale token. ErrTokenHashMismatch signals that case so the
// caller can return 401 rather than overwriting the row with a
// rotation based on an old hash.
//
// Returns (newPlaintext, newExpiry, nil) on a successful rotation,
// ("", 0, nil) when no rotation was needed, or (zero, zero, err)
// on failure (including ErrTokenHashMismatch).
func maybeRotateToken(edgeID, presentedTokenHash string) (string, int64, error) {
	tx, err := db.DB.Begin()
	if err != nil {
		return "", 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentHash sql.NullString
	var expiresAt sql.NullInt64
	if err := tx.QueryRow(
		`SELECT token_hash, token_expires_at FROM edges WHERE id = $1 FOR UPDATE`,
		edgeID,
	).Scan(&currentHash, &expiresAt); err != nil {
		return "", 0, fmt.Errorf("read row: %w", err)
	}
	if !currentHash.Valid || currentHash.String != presentedTokenHash {
		// Codex round-3 finding #1: a concurrent rotation already
		// happened. Caller must 401 and the Edge needs to switch
		// to whichever token won that race.
		return "", 0, ErrTokenHashMismatch
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
	// Guard the UPDATE with the presented hash so even if a
	// second concurrent transaction somehow slipped past the
	// FOR UPDATE lock (shouldn't, but defense-in-depth), the
	// WHERE clause refuses to rotate a stale row.
	if _, err := tx.Exec(
		`UPDATE edges
		     SET token_hash = $1, token_issued_at = $2, token_expires_at = $3
		     WHERE id = $4 AND token_hash = $5`,
		newHash, now.Unix(), newExpires, edgeID, presentedTokenHash,
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
		// MINIMUM_REQUIRED_EDGE_VERSION is validated at boot
		// (ValidateMinEdgeVersion), so any error here is the
		// client sending a malformed edge_version.
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "malformed edge_version: " + err.Error(),
			"code":  "invalid_edge_version",
		})
	}
	if !ok {
		return c.Status(fiber.StatusUpgradeRequired).JSON(fiber.Map{
			"error":                "edge version below minimum required",
			"code":                 "edge_version_below_minimum",
			"required_min_version": minimum,
			"current_version":      req.EdgeVersion,
		})
	}

	tokenHash := auth.HashToken(req.EnrollmentToken)
	edgeID := uuid.New().String()
	edgeTokenPlain, err := generateEdgeToken()
	if err != nil {
		slog.Error("edge register: generate token", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate edge token"})
	}
	edgeTokenHash := auth.HashToken(edgeTokenPlain)
	now := time.Now()
	nowUnix := now.Unix()
	tokenExpiresAt := now.Add(edgeTokenTTL).Unix()

	// Single-use enforcement at the DB layer (codex finding #6).
	// Two concurrent requests with the same token would both pass a
	// SELECT-then-UPDATE check under Read Committed; the atomic
	// UPDATE...WHERE consumed_at IS NULL...RETURNING guarantees
	// exactly one wins. The losing request sees 0 rows affected
	// and we diagnose via a follow-up SELECT to return precise
	// 401/409 codes.
	//
	// The UPDATE runs BEFORE the edges INSERT inside the same
	// transaction. If the INSERT fails (constraint violation, FK
	// violation, etc.), the transaction rolls back and the row
	// returns to consumed_at IS NULL — the enrollment stays
	// replayable, which is the invariant we want for failed
	// registrations.
	tx, err := db.DB.Begin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "transaction begin failed"})
	}
	defer func() { _ = tx.Rollback() }()

	// Two-step consume: first atomic UPDATE claims the row by
	// setting consumed_at (without consumed_by_edge_id, since the
	// edges row doesn't exist yet and the FK would fail). After
	// the INSERT lands, a second UPDATE wires up the FK. All three
	// statements run in one transaction so a failed INSERT rolls
	// back the consume.
	var etID, etTenantID string
	consumeErr := tx.QueryRow(
		`UPDATE enrollment_tokens
		     SET consumed_at = $1
		     WHERE token_hash = $2 AND consumed_at IS NULL AND expires_at > $1
		     RETURNING id, tenant_id`,
		nowUnix, tokenHash,
	).Scan(&etID, &etTenantID)
	if errors.Is(consumeErr, sql.ErrNoRows) {
		// Diagnose: does the row exist? Is it consumed or expired?
		// Same tx so we observe the post-UPDATE state of the row
		// the winning request left behind (consumed_at set).
		var consumedAt sql.NullInt64
		var expiresAt int64
		diagErr := tx.QueryRow(
			`SELECT consumed_at, expires_at FROM enrollment_tokens WHERE token_hash = $1`,
			tokenHash,
		).Scan(&consumedAt, &expiresAt)
		if errors.Is(diagErr, sql.ErrNoRows) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unknown enrollment token"})
		}
		if diagErr != nil {
			slog.Error("edge register: diagnose consume failure", "error", diagErr)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "consume diagnostics failed"})
		}
		if consumedAt.Valid {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "enrollment token already consumed"})
		}
		// The atomic UPDATE's WHERE uses `expires_at > $1` (strict).
		// A row with expires_at == nowUnix fails the UPDATE but
		// would also fail this diagnostic's `<` and fall to the
		// "unreachable" 500. Use `<=` here so the diagnostic
		// matches the UPDATE's notion of "alive vs not".
		if expiresAt <= nowUnix {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "enrollment token expired"})
		}
		// Row exists, not consumed, not expired — yet the UPDATE
		// matched 0 rows. Unreachable in practice; return 500.
		slog.Error("edge register: consume returned 0 rows but row appears valid", "token_hash", tokenHash)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "consume failed unexpectedly"})
	}
	if consumeErr != nil {
		slog.Error("edge register: consume update", "error", consumeErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "consume failed"})
	}

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
		nowUnix,
		tokenExpiresAt,
		req.EdgeVersion,
		nowUnix,
		nowUnix,
		etID,
	); err != nil {
		slog.Error("edge register: insert edge", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create edge record"})
	}

	if _, err := tx.Exec(
		`UPDATE enrollment_tokens SET consumed_by_edge_id = $1 WHERE id = $2`,
		edgeID, etID,
	); err != nil {
		slog.Error("edge register: link consumed_by_edge_id", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to link consume"})
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

// extractBearerToken pulls the token out of the Authorization
// header. Mirrors EdgeAuthMiddleware's case-insensitive parse
// (RFC 7235 §2.1) so the rotation revalidation hashes the same
// bytes the middleware did. Returns "" if no usable token —
// callers shouldn't reach this code path without middleware
// having already accepted a token, but be defensive.
func extractBearerToken(c *fiber.Ctx) string {
	const scheme = "bearer "
	h := strings.TrimSpace(c.Get("Authorization"))
	if len(h) < len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(h[len(scheme):])
}

// auditChainHeadInvalid writes a 400 response describing what's
// wrong with audit_chain_head, and reports back whether it wrote
// anything. Callers pattern: `if invalid := auditChainHeadInvalid(c, seq, sig); invalid { return nil }`.
//
// Codex finding #2 caught that the poll/events handlers were
// persisting empty signatures silently — defeats the tamper-
// evidence contract (#22 Q9).
//
// Returning a bool (rather than an error) sidesteps Fiber's
// convention where a non-nil return from a handler triggers the
// framework error handler and clobbers our JSON. c.Status(...)
// .JSON(...) returns the error from JSON encoding (nil on
// success), so a callsite checking `if err := validate(...); err != nil`
// silently fell through under that earlier pattern.
func auditChainHeadInvalid(c *fiber.Ctx, seq int64, signature string) bool {
	if signature == "" {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "audit_chain_head.signature is required",
			"code":  "missing_audit_chain_signature",
		})
		return true
	}
	if seq <= 0 {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "audit_chain_head.seq must be positive",
			"code":  "invalid_audit_chain_seq",
		})
		return true
	}
	return false
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

