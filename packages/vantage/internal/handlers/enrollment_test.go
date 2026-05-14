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
