package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/signing"
	"vaporrmm/vantage/internal/tailscale"

	"github.com/gofiber/fiber/v2"
)

// enrollmentEnv builds on tailscaleTestEnv (same DB+identity setup)
// and additionally bootstraps the signing keypair and mounts the
// enrollment routes onto the same /api/v1 group the tailscale
// routes use. Returning the app + swap closure mirrors the
// tailscaleTestEnv contract.
func enrollmentEnv(t *testing.T, role string) (*fiber.App, func(tailscaleAPI)) {
	t.Helper()
	app, swap := tailscaleTestEnv(t, role)
	signing.ResetForTests()
	if err := signing.Bootstrap(); err != nil {
		t.Fatalf("signing.Bootstrap: %v", err)
	}
	api := app.Group("/api/v1", func(c *fiber.Ctx) error {
		c.Locals("user_role", role)
		c.Locals("user_id", "test-user")
		return c.Next()
	})
	RegisterEnrollmentRoutes(api)
	return app, swap
}

func TestMintEnrollmentToken_HappyPath(t *testing.T) {
	app, swap := enrollmentEnv(t, "super_admin")

	// Connect Tailscale first — handler refuses without it.
	swap(&fakeTSClient{})
	r := postJSON(t, app, "/api/v1/tailscale/connect", map[string]string{
		"client_id": "id", "client_secret": "secret", "tailnet": "acme.ts.net",
	})
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("tailscale connect status %d", r.StatusCode)
	}

	swap(&fakeTSClient{
		mintEnrollment: func(ctx context.Context, tn, desc string) (*tailscale.AuthKey, error) {
			if tn != "acme.ts.net" {
				t.Errorf("mint called with wrong tailnet %q", tn)
			}
			if !strings.Contains(desc, "tenant-acme") {
				t.Errorf("description should carry tenant id, got %q", desc)
			}
			return &tailscale.AuthKey{ID: "k-abc", Key: "tskey-auth-XXXX"}, nil
		},
	})

	resp := postJSON(t, app, "/api/v1/vantage/enrollment-tokens", map[string]string{
		"tenant_id": "tenant-acme",
		"notes":     "ACME Corp HQ",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("mint status %d body=%s", resp.StatusCode, body)
	}

	var out struct {
		EnrollmentToken     string `json:"enrollment_token"`
		TailscaleAuthKey    string `json:"tailscale_auth_key"`
		VantageJWTPublicKey string `json:"vantage_jwt_public_key"`
		ExpiresAt           int64  `json:"expires_at"`
		TenantID            string `json:"tenant_id"`
		Notes               string `json:"notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(out.EnrollmentToken, "vrt_") {
		t.Errorf("enrollment_token should start with vrt_, got %q", out.EnrollmentToken)
	}
	if out.TailscaleAuthKey != "tskey-auth-XXXX" {
		t.Errorf("tailscale_auth_key mismatch: %q", out.TailscaleAuthKey)
	}
	if !strings.Contains(out.VantageJWTPublicKey, "BEGIN PUBLIC KEY") {
		t.Errorf("vantage_jwt_public_key should be PEM: %q", out.VantageJWTPublicKey)
	}
	if out.TenantID != "tenant-acme" || out.Notes != "ACME Corp HQ" {
		t.Errorf("metadata mismatch: %+v", out)
	}
	if out.ExpiresAt == 0 {
		t.Error("expires_at should be non-zero")
	}

	var tokenHash, tailscaleKeyID string
	if err := db.DB.QueryRow(
		`SELECT token_hash, tailscale_auth_key_id FROM enrollment_tokens WHERE tenant_id = 'tenant-acme'`,
	).Scan(&tokenHash, &tailscaleKeyID); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if tokenHash == out.EnrollmentToken {
		t.Error("token plaintext stored in token_hash column!")
	}
	if tailscaleKeyID != "k-abc" {
		t.Errorf("tailscale_auth_key_id %q != k-abc", tailscaleKeyID)
	}

	var auditCount int
	if err := db.DB.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action = 'enrollment_token.mint'`,
	).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Errorf("expected 1 audit row, got %d", auditCount)
	}
}

func TestMintEnrollmentToken_RefusesWithoutTailscale(t *testing.T) {
	app, _ := enrollmentEnv(t, "super_admin")
	resp := postJSON(t, app, "/api/v1/vantage/enrollment-tokens", map[string]string{
		"tenant_id": "tenant-x",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 without tailscale connection, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Tailscale must be connected") {
		t.Errorf("error should explain missing Tailscale: %s", string(body))
	}
}

func TestMintEnrollmentToken_RequiresSuperAdmin(t *testing.T) {
	app, _ := enrollmentEnv(t, "admin")
	resp := postJSON(t, app, "/api/v1/vantage/enrollment-tokens", map[string]string{
		"tenant_id": "tenant-x",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-super-admin should hit 403, got %d", resp.StatusCode)
	}
}

// TestMintEnrollmentToken_TailscaleMintFails: the Tailscale mint
// fails; the enrollment_tokens row should exist (it was INSERTed
// before the mint attempt) but tailscale_auth_key_id stays NULL.
// No orphaned Tailscale auth key. The operator gets a clear error
// with the row_id for manual cleanup if desired.
func TestMintEnrollmentToken_TailscaleMintFails(t *testing.T) {
	app, swap := enrollmentEnv(t, "super_admin")

	swap(&fakeTSClient{})
	r := postJSON(t, app, "/api/v1/tailscale/connect", map[string]string{
		"client_id": "id", "client_secret": "secret", "tailnet": "acme.ts.net",
	})
	r.Body.Close()

	swap(&fakeTSClient{
		mintEnrollment: func(ctx context.Context, tn, desc string) (*tailscale.AuthKey, error) {
			return nil, tailscale.ErrTailscaleUnreachable
		},
	})

	resp := postJSON(t, app, "/api/v1/vantage/enrollment-tokens", map[string]string{
		"tenant_id": "tenant-mint-fail",
		"notes":     "mint will fail",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 when mint fails, got %d", resp.StatusCode)
	}

	// Row exists with NULL tailscale_auth_key_id.
	var rowCount int
	var keyIDNull bool
	if err := db.DB.QueryRow(
		`SELECT COUNT(*), bool_and(tailscale_auth_key_id IS NULL) FROM enrollment_tokens WHERE tenant_id = 'tenant-mint-fail'`,
	).Scan(&rowCount, &keyIDNull); err != nil {
		t.Fatal(err)
	}
	if rowCount != 1 {
		t.Errorf("expected enrollment row to exist after mint failure, got %d rows", rowCount)
	}
	if !keyIDNull {
		t.Error("tailscale_auth_key_id should be NULL after mint failure")
	}
}

// TestMintEnrollmentToken_LinkUpdateFailsRevokes: in the (rare)
// case where the post-mint UPDATE fails, the handler must revoke
// the just-minted Tailscale key so it doesn't dangle.
func TestMintEnrollmentToken_LinkUpdateFailsRevokes(t *testing.T) {
	app, swap := enrollmentEnv(t, "super_admin")

	swap(&fakeTSClient{})
	r := postJSON(t, app, "/api/v1/tailscale/connect", map[string]string{
		"client_id": "id", "client_secret": "secret", "tailnet": "acme.ts.net",
	})
	r.Body.Close()

	revoked := ""
	swap(&fakeTSClient{
		mintEnrollment: func(ctx context.Context, tn, desc string) (*tailscale.AuthKey, error) {
			return &tailscale.AuthKey{ID: "k-orphan", Key: "tskey-orphan"}, nil
		},
		revokeAuthKey: func(ctx context.Context, tn, keyID string) error {
			revoked = keyID
			return nil
		},
	})

	// Force the UPDATE to fail with a CHECK constraint that blocks
	// the specific key_id the fake returns. INSERT writes NULL so
	// passes the check; UPDATE setting it to k-orphan violates.
	if _, err := db.DB.Exec(`ALTER TABLE enrollment_tokens ADD CONSTRAINT block_orphan CHECK (tailscale_auth_key_id IS DISTINCT FROM 'k-orphan')`); err != nil {
		t.Fatalf("install check: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`ALTER TABLE enrollment_tokens DROP CONSTRAINT block_orphan`)
	})

	resp := postJSON(t, app, "/api/v1/vantage/enrollment-tokens", map[string]string{
		"tenant_id": "tenant-link-fail",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 when link UPDATE fails, got %d", resp.StatusCode)
	}
	if revoked != "k-orphan" {
		t.Errorf("orphaned Tailscale key should have been revoked, got %q", revoked)
	}
}

// TestMintEnrollmentToken_CASPredicateFails_RevokesKey: codex
// round-9 #1. Drives the CAS-miss path by hooking into the fake
// Tailscale client's mintEnrollment — after the mint succeeds,
// the hook directly UPDATEs the enrollment row's
// tailscale_auth_key_id to a DIFFERENT value, simulating a
// concurrent modifier. The handler's subsequent CAS UPDATE finds
// 0 rows affected, revokes the orphaned key, and returns 409
// enrollment_modified_concurrently.
func TestMintEnrollmentToken_CASPredicateFails_RevokesKey(t *testing.T) {
	app, swap := enrollmentEnv(t, "super_admin")

	swap(&fakeTSClient{})
	r := postJSON(t, app, "/api/v1/tailscale/connect", map[string]string{
		"client_id": "id", "client_secret": "secret", "tailnet": "acme.ts.net",
	})
	r.Body.Close()

	revoked := ""
	swap(&fakeTSClient{
		mintEnrollment: func(ctx context.Context, tn, desc string) (*tailscale.AuthKey, error) {
			// Race window: between this mint returning and the
			// handler running its CAS UPDATE, simulate a concurrent
			// modifier filling tailscale_auth_key_id to a different
			// value.
			if _, err := db.DB.Exec(
				`UPDATE enrollment_tokens SET tailscale_auth_key_id = 'concurrent-winner-key' WHERE tenant_id = 'tenant-cas-miss'`,
			); err != nil {
				t.Fatalf("simulate concurrent modify: %v", err)
			}
			return &tailscale.AuthKey{ID: "k-original-mint", Key: "tskey-original"}, nil
		},
		revokeAuthKey: func(ctx context.Context, tn, keyID string) error {
			revoked = keyID
			return nil
		},
	})

	resp := postJSON(t, app, "/api/v1/vantage/enrollment-tokens", map[string]string{
		"tenant_id": "tenant-cas-miss",
		"notes":     "race victim",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 409 on CAS miss, got %d body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "enrollment_modified_concurrently") {
		t.Errorf("body should carry code=enrollment_modified_concurrently, got %s", body)
	}

	// Revoke must have fired with the original mint's key id, NOT
	// the concurrent winner's key.
	if revoked != "k-original-mint" {
		t.Errorf("revoke must target the orphaned original mint; got %q", revoked)
	}

	// DB row preserves the concurrent winner's key (handler must
	// not have overwritten it).
	var stored string
	db.DB.QueryRow(
		`SELECT tailscale_auth_key_id FROM enrollment_tokens WHERE tenant_id = 'tenant-cas-miss'`,
	).Scan(&stored)
	if stored != "concurrent-winner-key" {
		t.Errorf("CAS predicate should have refused to overwrite; expected concurrent-winner-key, got %q", stored)
	}
}
