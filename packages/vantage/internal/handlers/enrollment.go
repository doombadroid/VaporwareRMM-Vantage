// Enrollment-token mint handler — the Vantage-side entrypoint for
// bootstrapping a new Edge. Returns the three-artifact bundle per
// issue #22 Q3:
//
//   - enrollment_token plaintext (single-use, 24h TTL)
//   - Tailscale auth key plaintext (single-use, 24h TTL)
//   - Vantage's JWT public key (PEM, validates future drill-through
//     SSO JWTs without re-fetching)
//
// Plus operator metadata (vantage_url, expires_at, notes).
//
// Super-admin only. Tailscale credential must be connected first.

package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"time"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/events"
	"vaporrmm/vantage/internal/signing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// RegisterEnrollmentRoutes wires the operator-facing federation
// admin endpoints (mint a bundle, future: list/revoke). Mounted at
// /api/v1/vantage/* alongside the other authed routes.
func RegisterEnrollmentRoutes(api fiber.Router) {
	api.Post("/vantage/enrollment-tokens", requireSuperAdmin, mintEnrollmentToken)
}

// enrollmentTokenPrefix is the human-distinguishable prefix for
// enrollment-token plaintext. Lets operators visually triage a
// leaked secret ("is this an enrollment token or an Edge token?").
const enrollmentTokenPrefix = "vrt_"

// enrollmentTokenTTL: issue #22 Q3 locks 24 hours.
const enrollmentTokenTTL = 24 * time.Hour

func mintEnrollmentToken(c *fiber.Ctx) error {
	var req struct {
		TenantID string `json:"tenant_id"`
		Notes    string `json:"notes"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.TenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}

	// Tailscale must be connected — without it, we can't mint the
	// auth key that's the second artifact in the bundle. Surface a
	// precise error instead of a vague 500 later.
	clientID, clientSecret, tailnet, ok, err := loadTailscaleCredential()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("read tailscale credential: %v", err),
		})
	}
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Tailscale must be connected before minting enrollment tokens. POST /api/v1/tailscale/connect first.",
		})
	}

	// Signing keypair must be loaded — Bootstrap runs at server
	// startup; refuse the request rather than mint a bundle without
	// the public key.
	pubKeyPEM := signing.PublicKeyPEM()
	if pubKeyPEM == "" {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Vantage signing keypair not loaded; server boot incomplete",
		})
	}

	plaintext, err := generateEnrollmentToken()
	if err != nil {
		slog.Error("enrollment: generate plaintext", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate enrollment token"})
	}
	tokenHash := auth.HashToken(plaintext)

	now := time.Now()
	expiresAt := now.Add(enrollmentTokenTTL).Unix()
	id := uuid.New().String()
	userID, _ := c.Locals("user_id").(string)

	// Insert enrollment_tokens row FIRST with NULL tailscale_auth_
	// key_id. If we minted the Tailscale key first and then the
	// INSERT failed, the key would dangle in Tailscale with no
	// Vantage record of it (codex finding #4). Ordering INSERT
	// before mint flips the failure mode: if mint fails, the
	// orphaned row has no Tailscale key to leak — the operator
	// sees a clear error and the row will simply expire per its TTL.
	if _, err := db.DB.Exec(
		`INSERT INTO enrollment_tokens
		     (id, token_hash, tenant_id, tailscale_auth_key_id, created_at, expires_at, minted_by_user_id, notes)
		     VALUES ($1, $2, $3, NULL, $4, $5, $6, $7)`,
		id, tokenHash, req.TenantID, now.Unix(), expiresAt, userID, nullableString(req.Notes),
	); err != nil {
		slog.Error("enrollment: insert row", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to persist enrollment token"})
	}

	cl := tailscaleClientFactory(clientID, clientSecret)
	authKey, err := cl.MintEdgeEnrollmentAuthKey(c.UserContext(), tailnet,
		fmt.Sprintf("vantage enrollment for tenant %s", req.TenantID))
	if err != nil {
		slog.Error("enrollment: mint tailscale key", "error", err, "row_id", id)
		// Row exists with NULL tailscale_auth_key_id. Operator
		// gets the error and can either retry (which will hit
		// token_hash UNIQUE) or manually clean up. The row
		// expires naturally per its 24h TTL.
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error":  classifyTailscaleError(err, "failed to mint Tailscale auth key"),
			"row_id": id,
		})
	}

	if _, err := db.DB.Exec(
		`UPDATE enrollment_tokens SET tailscale_auth_key_id = $1 WHERE id = $2`,
		authKey.ID, id,
	); err != nil {
		// Compensation: revoke the Tailscale key we just minted —
		// without this it would dangle in Tailscale with the
		// enrollment row pointing at NULL.
		slog.Error("enrollment: link tailscale key id", "error", err, "key_id", authKey.ID)
		if revokeErr := cl.RevokeAuthKey(c.UserContext(), tailnet, authKey.ID); revokeErr != nil {
			slog.Error("enrollment: failed to revoke orphaned tailscale key",
				"error", revokeErr, "key_id", authKey.ID,
				"note", "key will expire per its 24h TTL")
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to link tailscale auth key"})
	}

	// Synchronous: operator only sees the bundle after the audit
	// row is durable. Codex round-6 #2/#3: AuditLogSync now
	// returns error. The enrollment row + Tailscale key already
	// exist at this point (orphans on failure), so a non-nil
	// error here surfaces a 500 but leaves a recoverable
	// half-state — operator will retry, hit the token_hash UNIQUE
	// constraint, and the orphan row expires per its 24h TTL.
	if err := events.AuditLogSync(userID, "enrollment_token.mint", "enrollment_token", id,
		fmt.Sprintf("minted enrollment token for tenant %s", req.TenantID), c.IP()); err != nil {
		slog.Error("enrollment: audit write", "error", err, "row_id", id)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":  "failed to write audit record",
			"code":   "audit_write_failed",
			"row_id": id,
		})
	}

	return c.JSON(fiber.Map{
		"enrollment_token":       plaintext,
		"tailscale_auth_key":     authKey.Key,
		"vantage_jwt_public_key": pubKeyPEM,
		"vantage_url":            os.Getenv("VANTAGE_PUBLIC_URL"),
		"expires_at":             expiresAt,
		"tenant_id":              req.TenantID,
		"notes":                  req.Notes,
	})
}

// generateEnrollmentToken returns a fresh `vrt_<48-char base64>`
// string. Backed by crypto/rand. 32 bytes ≈ 256 bits of entropy.
func generateEnrollmentToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return enrollmentTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

