package auth

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"

	"github.com/gofiber/fiber/v2"
)

const edgeAuthTestEncryptionKey = "fmZn0pFd/f58gKeknlaECEbcMDh5oQ+nRhFB/sAMScY="

// edgeAuthEnv stands up DB + a Fiber app with a single test route
// behind EdgeAuthMiddleware. The route returns c.Locals so tests
// can assert what the middleware attached.
func edgeAuthEnv(t *testing.T) *fiber.App {
	t.Helper()
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL")
	}
	if err := crypto.SetKeyForTests(edgeAuthTestEncryptionKey); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)

	conn, _ := sql.Open("postgres", url)
	_, _ = conn.Exec(`DROP TABLE IF EXISTS command_queue, tags, tag_endpoint_membership, audit_checkpoints, enrollment_tokens, vantage_signing_key, tailscale_connection, audit_log, user_sessions, users, edges, schema_migrations CASCADE`)
	_ = conn.Close()
	t.Cleanup(func() {
		if db.DB != nil {
			_, _ = db.DB.Exec(`DROP TABLE IF EXISTS command_queue, tags, tag_endpoint_membership, audit_checkpoints, enrollment_tokens, vantage_signing_key, tailscale_connection, audit_log, user_sessions, users, edges, schema_migrations CASCADE`)
			_ = db.DB.Close()
			db.DB = nil
		}
	})
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/echo", EdgeAuthMiddleware(), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"edge_id":          c.Locals("edge_id"),
			"tenant_id":        c.Locals("tenant_id"),
			"tailnet_identity": c.Locals("tailnet_identity"),
		})
	})
	return app
}

// seedEdge inserts an edge row with the given token + properties.
// Returns plaintext token to pass in Authorization.
func seedEdge(t *testing.T, edgeID, tenantID, tailnetIP, status string, tokenExpiry time.Duration) string {
	t.Helper()
	plain := "vet_test_" + edgeID + "_tok"
	hash := HashToken(plain)
	now := time.Now().Unix()
	expiry := now + int64(tokenExpiry.Seconds())
	_, err := db.DB.Exec(
		`INSERT INTO edges
		     (id, tenant_id, tailnet_identity, tailnet_ip,
		      token_hash, token_issued_at, token_expires_at,
		      edge_version, status, last_seen_at, created_at)
		     VALUES ($1, $2, 'identity-'||$1, $3, $4, $5, $6, '0.1.0', $7, $8, $9)`,
		edgeID, tenantID, nullable(tailnetIP), hash, now, expiry, status, now, now,
	)
	if err != nil {
		t.Fatalf("seed edge: %v", err)
	}
	return plain
}

// nullable mirrors the helper in events; copied locally so the
// auth test file doesn't need to import events.
func nullable(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func authedRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/echo", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestEdgeAuthMiddleware_HappyPath(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-1", "tenant-1", "", "active", time.Hour)

	resp, _ := app.Test(authedRequest(plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out struct {
		EdgeID          string `json:"edge_id"`
		TenantID        string `json:"tenant_id"`
		TailnetIdentity string `json:"tailnet_identity"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.EdgeID != "edge-1" || out.TenantID != "tenant-1" {
		t.Errorf("c.Locals not set: %+v", out)
	}
	if out.TailnetIdentity != "identity-edge-1" {
		t.Errorf("tailnet_identity wrong: %q", out.TailnetIdentity)
	}

	// last_seen_at updated by middleware.
	var lastSeen int64
	db.DB.QueryRow(`SELECT last_seen_at FROM edges WHERE id = 'edge-1'`).Scan(&lastSeen)
	if lastSeen == 0 || lastSeen < time.Now().Add(-10*time.Second).Unix() {
		t.Errorf("last_seen_at not updated: %d", lastSeen)
	}
}

func TestEdgeAuthMiddleware_MissingHeader(t *testing.T) {
	app := edgeAuthEnv(t)
	resp, _ := app.Test(authedRequest(""), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestEdgeAuthMiddleware_UnknownToken(t *testing.T) {
	app := edgeAuthEnv(t)
	resp, _ := app.Test(authedRequest("vet_never_existed"), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestEdgeAuthMiddleware_InactiveStatus(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-decom", "tenant-x", "", "decommissioned", time.Hour)
	resp, _ := app.Test(authedRequest(plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("decommissioned edge should hit 401, got %d", resp.StatusCode)
	}
}

func TestEdgeAuthMiddleware_ExpiredToken(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-old", "tenant-x", "", "active", -time.Hour)
	resp, _ := app.Test(authedRequest(plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired token should hit 401, got %d", resp.StatusCode)
	}
}

// TestEdgeAuthMiddleware_AcceptsAnyClientIP: codex review removed
// the source-IP binding from EdgeAuthMiddleware (it couldn't be
// implemented reliably behind a reverse proxy). The middleware now
// authenticates by Bearer token alone — a valid token from any
// client address must succeed. tailnet_ip stays in the edges
// schema for operator visibility but is load-bearing in nothing.
func TestEdgeAuthMiddleware_AcceptsAnyClientIP(t *testing.T) {
	app := edgeAuthEnv(t)
	// Seed with a tailnet_ip the test request can't possibly use.
	plain := seedEdge(t, "edge-any-ip", "tenant-x", "100.99.99.99", "active", time.Hour)
	resp, _ := app.Test(authedRequest(plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid token should auth regardless of source IP; got %d", resp.StatusCode)
	}
}

// TestEdgeAuthMiddleware_TokenExactlyAtExpiry: codex finding #7.
// A token whose token_expires_at lands on exactly the current
// second was previously routed to the "unreachable" 500 path
// because of a `<` comparison. The fix is `<=` — exactly-at-
// expiry tokens are expired, full stop.
func TestEdgeAuthMiddleware_TokenExactlyAtExpiry(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-exact-expiry", "tenant-x", "", "active", 0)
	// Force token_expires_at to be exactly time.Now().Unix() at
	// the moment the middleware checks. The middleware computes
	// time.Now().Unix() each request; this test asserts the row
	// gets refused even if the comparison stamps the same second.
	_, _ = db.DB.Exec(`UPDATE edges SET token_expires_at = $1 WHERE id = 'edge-exact-expiry'`, time.Now().Unix())

	resp, _ := app.Test(authedRequest(plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token exactly at expiry should be 401, got %d", resp.StatusCode)
	}
}

// Codex finding #4: scheme name is case-insensitive per RFC 7235.

func authedRequestRaw(authHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/echo", nil)
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	return r
}

func TestEdgeAuth_BearerLowercase(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-lower", "tenant-x", "", "active", time.Hour)
	resp, _ := app.Test(authedRequestRaw("bearer "+plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("lowercase 'bearer' should auth, got %d", resp.StatusCode)
	}
}

func TestEdgeAuth_BearerMixedCase(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-mixed", "tenant-x", "", "active", time.Hour)
	resp, _ := app.Test(authedRequestRaw("BeArEr "+plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("mixed-case 'BeArEr' should auth, got %d", resp.StatusCode)
	}
}

func TestEdgeAuth_BearerUppercase(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-upper", "tenant-x", "", "active", time.Hour)
	resp, _ := app.Test(authedRequestRaw("BEARER "+plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("uppercase 'BEARER' should auth, got %d", resp.StatusCode)
	}
}

func TestEdgeAuth_NoScheme(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-noscheme", "tenant-x", "", "active", time.Hour)
	resp, _ := app.Test(authedRequestRaw(plain), -1) // raw token, no scheme
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing scheme should be 401, got %d", resp.StatusCode)
	}
}

func TestEdgeAuth_WrongScheme(t *testing.T) {
	app := edgeAuthEnv(t)
	plain := seedEdge(t, "edge-wrongscheme", "tenant-x", "", "active", time.Hour)
	resp, _ := app.Test(authedRequestRaw("Basic "+plain), -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("non-Bearer scheme should be 401, got %d", resp.StatusCode)
	}
}
