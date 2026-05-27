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

// Rotation-race rejection (round 3 → round 5):
//
// Earlier iterations of pollEdge factored rotation into a
// standalone maybeRotateToken helper that returned the sentinel
// ErrTokenHashMismatch when the presented hash no longer matched
// the row. Round 5 inlined the rotation inside a single handler
// transaction so all mutations (rotation, edge_version, audit
// checkpoint) commit atomically. The sentinel disappeared with
// the helper; the in-tx mismatch check now returns 401
// token_concurrently_rotated directly.

// RegisterEdgeRoutes mounts the federation endpoints on the app.
// register is at the root group with its own rate limiter; the
// authed routes (commits 10/11) get wired through their own
// middleware chain.
func RegisterEdgeRoutes(app *fiber.App) {
	// Two chained rate limiters on /register (codex round-6 #1).
	// Per-IP catches brute-force iteration across guessed tokens;
	// per-token catches repeated attempts on a specific token.
	// Round-1 fix moved to per-token only, which actually weakened
	// brute-force resistance because each guess got its own bucket.
	// The right answer is both — and per-IP requires Fiber's
	// TrustedProxies config to see the real client IP behind
	// Caddy (configured in main.go).
	limitReached := func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": "rate limit exceeded; slow down",
			"code":  429,
		})
	}
	ipLimiter := limiter.New(limiter.Config{
		Max:        30, // legitimate operators may register many edges from one bastion
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return "ip:" + c.IP()
		},
		LimitReached: limitReached,
	})
	tokenLimiter := limiter.New(limiter.Config{
		Max:        5,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			var body struct {
				EnrollmentToken string `json:"enrollment_token"`
			}
			if err := c.BodyParser(&body); err != nil {
				return "tok:malformed"
			}
			if body.EnrollmentToken == "" {
				return "tok:empty"
			}
			sum := sha256.Sum256([]byte(body.EnrollmentToken))
			return "tok:" + hex.EncodeToString(sum[:])[:16]
		},
		LimitReached: limitReached,
	})
	app.Post("/api/edge/register", ipLimiter, tokenLimiter, registerEdge)

	// Authed federation endpoints. Edge presents Bearer token;
	// EdgeAuthMiddleware validates + attaches edge_id/tenant_id/
	// tailnet_identity to c.Locals.
	authed := app.Group("/api/edge", auth.EdgeAuthMiddleware())
	authed.Post("/poll", pollEdge)
	authed.Post("/events", postEdgeEvents)
	authed.Post("/tags/sync", postEdgeTagsSync) // F4a tag metadata mirror
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
// pollEdge is structured around four strict phases (codex round-5
// #1/#2):
//
//   Phase 1: parse + validate the request body. No state mutation.
//   Phase 2: read failure-prone external state (Vantage chain
//            head). No state mutation; failures here return 500
//            with old state intact.
//   Phase 3: single transaction wraps every mutation — rotation
//            check, rotation UPDATE (if window), edge_version
//            UPDATE, audit_checkpoints INSERT. COMMIT is the last
//            act. If anything before commit fails, rollback
//            restores the pre-handler state and Edge can retry
//            with the same token.
//   Phase 4: build + return response. Past commit, no failure
//            path can lose the rotation.
//
// Failure surface that remains: TCP reset between commit and
// client-side receive. Edge will see no response, retry with old
// token, get 401 from middleware (token rotated), need to
// re-enroll. Two-phase rotation (old + new valid until Edge ACKs
// the new) would close this, but it adds significant complexity
// and is out of scope for F2.
func pollEdge(c *fiber.Ctx) error {
	// ---- Phase 1: parse + validate ----
	var req struct {
		EdgeVersion    string `json:"edge_version"`
		AuditChainHead struct {
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
		// MINIMUM_REQUIRED_EDGE_VERSION validated at boot, so any
		// versionAtLeast error here is the client's edge_version.
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
	presentedToken := extractBearerToken(c)
	presentedHash := auth.HashToken(presentedToken)

	// ---- Phase 2: read Vantage chain head ----
	// Done before the tx so a chain-read failure does NOT roll
	// back an already-prepared rotation. If this errors, no
	// mutation has occurred — Edge can retry with the same token.
	vantageSeq, vantageSig, err := events.LatestChainHead()
	if err != nil {
		slog.Error("poll: read vantage chain head", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to read chain state",
			"code":  "chain_read_failed",
		})
	}

	// ---- Phase 3: single transaction for all mutations ----
	tx, err := db.DB.Begin()
	if err != nil {
		slog.Error("poll: begin tx", "error", err, "edge_id", edgeID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "transaction begin failed"})
	}
	defer func() { _ = tx.Rollback() }()

	// 3a. Lock the row and verify presented hash is current.
	var currentHash sql.NullString
	var expiresAt sql.NullInt64
	if err := tx.QueryRow(
		`SELECT token_hash, token_expires_at FROM edges WHERE id = $1 FOR UPDATE`,
		edgeID,
	).Scan(&currentHash, &expiresAt); err != nil {
		slog.Error("poll: read row for update", "error", err, "edge_id", edgeID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "row read failed"})
	}
	if !currentHash.Valid || currentHash.String != presentedHash {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "token has been rotated concurrently; re-authenticate with the latest token",
			"code":  "token_concurrently_rotated",
		})
	}

	// 3b. Rotate if within window. The UPDATE's WHERE clause
	// re-checks token_hash so even if FOR UPDATE somehow released
	// early, the rotation refuses on a stale row.
	now := time.Now()
	nowUnix := now.Unix()
	var newPlain string
	var newExpires int64
	if expiresAt.Valid && expiresAt.Int64 <= now.Add(tokenRotationWindow).Unix() {
		np, gerr := generateEdgeToken()
		if gerr != nil {
			slog.Error("poll: generate edge token", "error", gerr, "edge_id", edgeID)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token generation failed"})
		}
		nh := auth.HashToken(np)
		ne := now.Add(edgeTokenTTL).Unix()
		result, uerr := tx.Exec(
			`UPDATE edges SET token_hash = $1, token_issued_at = $2, token_expires_at = $3
			     WHERE id = $4 AND token_hash = $5`,
			nh, nowUnix, ne, edgeID, presentedHash,
		)
		if uerr != nil {
			slog.Error("poll: rotate update", "error", uerr, "edge_id", edgeID)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rotation update failed"})
		}
		ra, raerr := result.RowsAffected()
		if raerr != nil {
			slog.Error("poll: rotate rowsAffected", "error", raerr)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rotation verify failed"})
		}
		if ra == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "token has been rotated concurrently; re-authenticate with the latest token",
				"code":  "token_concurrently_rotated",
			})
		}
		newPlain, newExpires = np, ne
	}

	// 3c. Refresh reported edge_version. Inside the tx so a
	// failure rolls back any rotation just performed.
	if _, err := tx.Exec(`UPDATE edges SET edge_version = $1 WHERE id = $2`, req.EdgeVersion, edgeID); err != nil {
		slog.Error("poll: edge_version update", "error", err, "edge_id", edgeID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "edge_version update failed"})
	}

	// 3d. Persist the counterparty's audit chain head. Inline the
	// INSERT inside the same tx (rather than calling out to
	// RecordAuditCheckpointSync) so the row participates in the
	// atomic commit.
	if _, err := tx.Exec(
		`INSERT INTO audit_checkpoints (counterparty_type, counterparty_id, chain_seq, signature, recorded_at, recorded_during)
		     VALUES ('edge', $1, $2, $3, $4, 'poll')`,
		edgeID, req.AuditChainHead.Seq, req.AuditChainHead.Signature, nowUnix,
	); err != nil {
		slog.Error("poll: checkpoint insert", "error", err, "edge_id", edgeID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to record audit checkpoint",
			"code":  "checkpoint_write_failed",
		})
	}

	// 3e. Commit. After this point the rotation is durable.
	if err := tx.Commit(); err != nil {
		slog.Error("poll: commit", "error", err, "edge_id", edgeID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "commit failed"})
	}

	// Post-commit audit (fire-and-forget). The rotation is already
	// durable; this row is an operator-facing notification.
	if newPlain != "" {
		events.AuditLog("", "edge.token.rotated", "edge", edgeID, "polled within rotation window", "")
	}

	// ---- Phase 4: response ----
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
	if newPlain != "" {
		resp["new_edge_token"] = newPlain
		resp["new_token_expires_at"] = newExpires
	} else {
		resp["new_edge_token"] = nil
	}
	return c.JSON(resp)
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

	// Audit inside the tx so the trace lands atomically with the
	// enrollment consume + edge insert. Codex round-6 #2: the
	// previous post-commit AuditLogSync could have failed silently
	// while the bearer token was already issued to the caller.
	if err := events.AuditLogSyncTx(tx, "", "edge.register", "edge", edgeID,
		fmt.Sprintf("registered via enrollment %s for tenant %s; version=%s", etID, etTenantID, req.EdgeVersion),
		c.IP()); err != nil {
		slog.Error("edge register: audit write", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to write audit record; registration rolled back",
			"code":  "audit_write_failed",
		})
	}

	if err := tx.Commit(); err != nil {
		slog.Error("edge register: commit", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "registration commit failed"})
	}

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

