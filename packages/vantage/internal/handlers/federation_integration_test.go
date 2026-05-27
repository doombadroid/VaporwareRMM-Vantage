package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/signing"
	"vaporrmm/vantage/internal/tailscale"

	"github.com/gofiber/fiber/v2"
)

// TestFederationF2_FullFlow exercises the F2 surface end to end
// against a real Postgres + a fake Tailscale client:
//
//  1. Operator (stamped super-admin) connects Tailscale
//  2. Operator mints an enrollment bundle
//  3. Fake Edge registers with that bundle's enrollment_token
//  4. Fake Edge polls — gets vantage_chain_head, commands=[]
//  5. Fake Edge pushes an events batch
//  6. Token rotation: simulate expiry within 7-day window,
//     poll again, expect new_edge_token + DB row updated
//  7. Version refusal: poll with edge_version below minimum,
//     expect 426
//
// After this test passes, a "fake Edge" implemented purely with
// curl against a Vantage process can drive the full F2 lifecycle.
// F3 will replace the curl with the real Edge-side client.
func TestFederationF2_FullFlow(t *testing.T) {
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL")
	}
	if err := crypto.SetKeyForTests(tailscaleTestEncryptionKey); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)
	t.Setenv("VANTAGE_PUBLIC_URL", "https://vantage.acme.ts.net")

	// Fresh DB.
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
		t.Fatalf("db init: %v", err)
	}
	if _, err := db.DB.Exec(
		`INSERT INTO users (id, email, password_hash, role) VALUES ('ops-1', 'ops@example.com', 'x', 'super_admin')`,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	signing.ResetForTests()
	if err := signing.Bootstrap(); err != nil {
		t.Fatalf("signing bootstrap: %v", err)
	}

	// Build app with full route set. /api/v1 group stamps a
	// super-admin identity onto every request so the operator-
	// facing endpoints accept the calls (no real login dance —
	// covered separately by main_test.go's TestLoginFlow).
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	api := app.Group("/api/v1", func(c *fiber.Ctx) error {
		c.Locals("user_role", "super_admin")
		c.Locals("user_id", "ops-1")
		return c.Next()
	})
	RegisterTailscaleRoutes(api)
	RegisterEnrollmentRoutes(api)
	RegisterEdgeRoutes(app)

	// Swap in the fake Tailscale client.
	origFactory := tailscaleClientFactory
	t.Cleanup(func() { tailscaleClientFactory = origFactory })
	mintCalled := 0
	fake := &fakeTSClient{
		mintEnrollment: func(ctx context.Context, tn, desc string) (*tailscale.AuthKey, error) {
			mintCalled++
			return &tailscale.AuthKey{
				ID:  "k-integration",
				Key: "tskey-auth-INTEGRATION",
			}, nil
		},
	}
	tailscaleClientFactory = func(string, string) tailscaleAPI { return fake }

	// ---- Step 1: connect Tailscale.
	connectResp := postFedJSON(t, app, http.MethodPost, "/api/v1/tailscale/connect", map[string]string{
		"client_id": "id", "client_secret": "secret", "tailnet": "acme.ts.net",
	})
	defer connectResp.Body.Close()
	if connectResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(connectResp.Body)
		t.Fatalf("tailscale connect status %d body=%s", connectResp.StatusCode, body)
	}

	// ---- Step 2: mint enrollment bundle.
	mintResp := postFedJSON(t, app, http.MethodPost, "/api/v1/vantage/enrollment-tokens", map[string]string{
		"tenant_id": "tenant-acme",
		"notes":     "integration test",
	})
	defer mintResp.Body.Close()
	if mintResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(mintResp.Body)
		t.Fatalf("mint status %d body=%s", mintResp.StatusCode, body)
	}
	var bundle struct {
		EnrollmentToken     string `json:"enrollment_token"`
		TailscaleAuthKey    string `json:"tailscale_auth_key"`
		VantageJWTPublicKey string `json:"vantage_jwt_public_key"`
		VantageURL          string `json:"vantage_url"`
		ExpiresAt           int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(mintResp.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.EnrollmentToken == "" || bundle.TailscaleAuthKey == "" {
		t.Fatalf("bundle missing fields: %+v", bundle)
	}
	if bundle.VantageURL != "https://vantage.acme.ts.net" {
		t.Errorf("vantage_url not propagated from env: %q", bundle.VantageURL)
	}
	if mintCalled != 1 {
		t.Errorf("expected 1 Tailscale mint call, got %d", mintCalled)
	}

	// ---- Step 3: Edge registers with the bundle.
	registerResp := postFedJSON(t, app, http.MethodPost, "/api/edge/register", map[string]interface{}{
		"enrollment_token": bundle.EnrollmentToken,
		"edge_version":     "0.1.0",
		"edge_hostname":    "edge-acme-hq",
		"tailnet_identity": "device-acme-edge-1",
	})
	defer registerResp.Body.Close()
	if registerResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(registerResp.Body)
		t.Fatalf("register status %d body=%s", registerResp.StatusCode, body)
	}
	var registration struct {
		EdgeID              string `json:"edge_id"`
		EdgeToken           string `json:"edge_token"`
		TokenExpiresAt      int64  `json:"token_expires_at"`
		PollIntervalSeconds int    `json:"poll_interval_seconds"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registration); err != nil {
		t.Fatal(err)
	}
	if registration.PollIntervalSeconds != 15 {
		t.Errorf("poll_interval_seconds should be 15, got %d", registration.PollIntervalSeconds)
	}

	// Enrollment row consumed.
	var consumedAt sql.NullInt64
	db.DB.QueryRow(
		`SELECT consumed_at FROM enrollment_tokens WHERE tenant_id = 'tenant-acme'`,
	).Scan(&consumedAt)
	if !consumedAt.Valid {
		t.Error("enrollment token should be consumed after registration")
	}

	// ---- Step 4: Edge polls.
	pollResp := postFedAuthJSON(t, app, http.MethodPost, "/api/edge/poll", registration.EdgeToken, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "edge-genesis-sig",
		},
	})
	defer pollResp.Body.Close()
	if pollResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(pollResp.Body)
		t.Fatalf("poll status %d body=%s", pollResp.StatusCode, body)
	}
	var pollOut struct {
		AuditChainHead struct {
			Seq       int64  `json:"seq"`
			Signature string `json:"signature"`
		} `json:"audit_chain_head"`
		Commands             []json.RawMessage `json:"commands"`
		NewEdgeToken         *string           `json:"new_edge_token"`
		NextPollAfterSeconds int               `json:"next_poll_after_seconds"`
	}
	json.NewDecoder(pollResp.Body).Decode(&pollOut)
	if pollOut.Commands == nil {
		t.Error("commands should be [] not null in F2")
	}
	if len(pollOut.Commands) != 0 {
		t.Errorf("F2 commands should be empty, got %d", len(pollOut.Commands))
	}
	if pollOut.NewEdgeToken != nil {
		t.Errorf("fresh 30-day token shouldn't rotate yet; got new_edge_token=%v", *pollOut.NewEdgeToken)
	}

	// Checkpoint persisted.
	var checkpointCount int
	db.DB.QueryRow(
		`SELECT COUNT(*) FROM audit_checkpoints WHERE counterparty_id = $1`, registration.EdgeID,
	).Scan(&checkpointCount)
	if checkpointCount < 1 {
		t.Error("expected at least one audit checkpoint after poll")
	}

	// ---- Step 5: Edge pushes events.
	eventsResp := postFedAuthJSON(t, app, http.MethodPost, "/api/edge/events", registration.EdgeToken, map[string]interface{}{
		"events": []map[string]interface{}{
			{"correlation_id": "hb-1", "type": "heartbeat", "occurred_at": time.Now().Unix()},
		},
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(2),
			"signature": "edge-sig-2",
		},
	})
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(eventsResp.Body)
		t.Fatalf("events status %d body=%s", eventsResp.StatusCode, body)
	}
	var eventsOut struct {
		Accepted int           `json:"accepted"`
		Rejected []interface{} `json:"rejected"`
	}
	json.NewDecoder(eventsResp.Body).Decode(&eventsOut)
	if eventsOut.Accepted != 1 || len(eventsOut.Rejected) != 0 {
		t.Errorf("expected accepted=1 rejected=0, got %+v", eventsOut)
	}

	// ---- Step 6: simulate near-expiry, poll again, expect rotation.
	rotateDeadline := time.Now().Add(3 * 24 * time.Hour).Unix() // 3 days from now → within 7d window
	if _, err := db.DB.Exec(
		`UPDATE edges SET token_expires_at = $1 WHERE id = $2`,
		rotateDeadline, registration.EdgeID,
	); err != nil {
		t.Fatalf("nudge expiry: %v", err)
	}
	rotResp := postFedAuthJSON(t, app, http.MethodPost, "/api/edge/poll", registration.EdgeToken, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(3),
			"signature": "edge-sig-3",
		},
	})
	defer rotResp.Body.Close()
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("rotation poll status %d", rotResp.StatusCode)
	}
	var rotOut struct {
		NewEdgeToken      string `json:"new_edge_token"`
		NewTokenExpiresAt int64  `json:"new_token_expires_at"`
	}
	json.NewDecoder(rotResp.Body).Decode(&rotOut)
	if rotOut.NewEdgeToken == "" {
		t.Fatal("expected new_edge_token after nudge into rotation window")
	}
	if rotOut.NewEdgeToken == registration.EdgeToken {
		t.Error("rotated token should differ from original")
	}
	if rotOut.NewTokenExpiresAt <= rotateDeadline {
		t.Errorf("new expiry %d should be later than pre-rotation expiry %d", rotOut.NewTokenExpiresAt, rotateDeadline)
	}

	// DB row updated to new hash.
	var storedHash string
	db.DB.QueryRow(`SELECT token_hash FROM edges WHERE id = $1`, registration.EdgeID).Scan(&storedHash)
	if storedHash != auth.HashToken(rotOut.NewEdgeToken) {
		t.Error("DB token_hash should match new plaintext")
	}

	// ---- Step 7: version refusal. Poll with edge_version below
	// the configured minimum.
	t.Setenv("MINIMUM_REQUIRED_EDGE_VERSION", "1.0.0")
	versionResp := postFedAuthJSON(t, app, http.MethodPost, "/api/edge/poll", rotOut.NewEdgeToken, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(4),
			"signature": "edge-sig-4",
		},
	})
	defer versionResp.Body.Close()
	if versionResp.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("expected 426 for version below minimum, got %d", versionResp.StatusCode)
	}
}

func postFedJSON(t *testing.T, app *fiber.App, method, path string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	return resp
}

func postFedAuthJSON(t *testing.T, app *fiber.App, method, path, token string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	return resp
}
