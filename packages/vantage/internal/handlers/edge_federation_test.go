package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"vaporrmm/vantage/internal/auth"
	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"

	"github.com/gofiber/fiber/v2"
)

// edgeFederationEnv stands up a fresh DB and an unauth-friendly app
// (RegisterEdgeRoutes is the only registration; no AuthMiddleware
// in the chain because /api/edge/register is the pre-token path).
// Returns the app plus a seed function that creates an enrollment
// token row directly so each test starts from a known state.
func edgeFederationEnv(t *testing.T) *fiber.App {
	t.Helper()
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL to a Postgres connection string")
	}
	if err := crypto.SetKeyForTests(tailscaleTestEncryptionKey); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)

	conn, _ := sql.Open("postgres", url)
	_, _ = conn.Exec(`DROP TABLE IF EXISTS audit_checkpoints, enrollment_tokens, vantage_signing_key, tailscale_connection, audit_log, user_sessions, users, edges, schema_migrations CASCADE`)
	_ = conn.Close()
	t.Cleanup(func() {
		if db.DB != nil {
			_, _ = db.DB.Exec(`DROP TABLE IF EXISTS audit_checkpoints, enrollment_tokens, vantage_signing_key, tailscale_connection, audit_log, user_sessions, users, edges, schema_migrations CASCADE`)
			_ = db.DB.Close()
			db.DB = nil
		}
	})
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}

	// Seed a super-admin user so the FK on enrollment_tokens.
	// minted_by_user_id resolves for the seeded enrollment row.
	if _, err := db.DB.Exec(
		`INSERT INTO users (id, email, password_hash, role) VALUES ('seed-admin', 'admin@vaporrmm-vantage.local', 'x', 'super_admin')`,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	RegisterEdgeRoutes(app)
	return app
}

// seedEnrollment inserts a fresh enrollment_tokens row and returns
// the plaintext token (which the test then sends to /register).
func seedEnrollment(t *testing.T, tenantID string, ttl time.Duration) string {
	t.Helper()
	plain := "vrt_test_" + tenantID + "_token"
	hash := auth.HashToken(plain)
	now := time.Now()
	if _, err := db.DB.Exec(
		`INSERT INTO enrollment_tokens
		     (id, token_hash, tenant_id, tailscale_auth_key_id,
		      created_at, expires_at, minted_by_user_id)
		     VALUES ($1, $2, $3, 'fake-tskey', $4, $5, 'seed-admin')`,
		"et-"+tenantID, hash, tenantID, now.Unix(), now.Add(ttl).Unix(),
	); err != nil {
		t.Fatalf("seed enrollment: %v", err)
	}
	return plain
}

func postEdgeRegister(t *testing.T, app *fiber.App, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/edge/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	return resp
}

func TestEdgeRegister_HappyPath(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEnrollment(t, "tenant-1", time.Hour)

	resp := postEdgeRegister(t, app, map[string]interface{}{
		"enrollment_token": plain,
		"edge_version":     "0.1.0",
		"edge_hostname":    "edge-tenant-1-hq",
		"tailnet_identity": "device-abc",
		"tailnet_ip":       "100.64.0.5",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status %d body=%s", resp.StatusCode, body)
	}
	var out struct {
		EdgeID              string `json:"edge_id"`
		EdgeToken           string `json:"edge_token"`
		TokenExpiresAt      int64  `json:"token_expires_at"`
		PollIntervalSeconds int    `json:"poll_interval_seconds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.EdgeID == "" {
		t.Error("edge_id should be set")
	}
	if len(out.EdgeToken) < 36 || out.EdgeToken[:4] != "vet_" {
		t.Errorf("edge_token shape wrong: %q", out.EdgeToken)
	}
	if out.PollIntervalSeconds != 15 {
		t.Errorf("poll_interval_seconds should default to 15, got %d", out.PollIntervalSeconds)
	}

	// Edge row stored with hashed token, status=active.
	var status, tokenHash, tenantID string
	if err := db.DB.QueryRow(
		`SELECT status, token_hash, tenant_id FROM edges WHERE id = $1`, out.EdgeID,
	).Scan(&status, &tokenHash, &tenantID); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Errorf("expected status=active, got %q", status)
	}
	if tokenHash == out.EdgeToken {
		t.Error("plaintext token stored in token_hash column")
	}
	if tokenHash != auth.HashToken(out.EdgeToken) {
		t.Error("stored hash doesn't match HashToken(edge_token)")
	}
	if tenantID != "tenant-1" {
		t.Errorf("tenant_id wrong: %q", tenantID)
	}

	// Enrollment marked consumed atomically.
	var consumedAt sql.NullInt64
	var consumedBy sql.NullString
	if err := db.DB.QueryRow(
		`SELECT consumed_at, consumed_by_edge_id FROM enrollment_tokens WHERE token_hash = $1`,
		auth.HashToken(plain),
	).Scan(&consumedAt, &consumedBy); err != nil {
		t.Fatal(err)
	}
	if !consumedAt.Valid {
		t.Error("enrollment token consumed_at should be set")
	}
	if consumedBy.String != out.EdgeID {
		t.Errorf("consumed_by_edge_id should be %q, got %q", out.EdgeID, consumedBy.String)
	}
}

func TestEdgeRegister_UnknownEnrollment(t *testing.T) {
	app := edgeFederationEnv(t)
	resp := postEdgeRegister(t, app, map[string]string{
		"enrollment_token": "vrt_never_existed",
		"edge_version":     "0.1.0",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestEdgeRegister_ExpiredEnrollment(t *testing.T) {
	app := edgeFederationEnv(t)
	// Negative TTL: the row is created already past expires_at.
	plain := seedEnrollment(t, "tenant-expired", -time.Hour)

	resp := postEdgeRegister(t, app, map[string]string{
		"enrollment_token": plain,
		"edge_version":     "0.1.0",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired enrollment should be 401, got %d", resp.StatusCode)
	}
}

func TestEdgeRegister_AlreadyConsumed(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEnrollment(t, "tenant-2", time.Hour)

	r1 := postEdgeRegister(t, app, map[string]string{
		"enrollment_token": plain,
		"edge_version":     "0.1.0",
	})
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first register status %d", r1.StatusCode)
	}

	r2 := postEdgeRegister(t, app, map[string]string{
		"enrollment_token": plain,
		"edge_version":     "0.1.0",
	})
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		t.Errorf("re-use should be 409, got %d", r2.StatusCode)
	}
}

func TestEdgeRegister_BelowMinimumVersion(t *testing.T) {
	t.Setenv("MINIMUM_REQUIRED_EDGE_VERSION", "1.0.0")
	app := edgeFederationEnv(t)
	plain := seedEnrollment(t, "tenant-old", time.Hour)

	resp := postEdgeRegister(t, app, map[string]string{
		"enrollment_token": plain,
		"edge_version":     "0.9.0",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("below-minimum version should be 426, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("required_min_version")) {
		t.Errorf("error should structure include required_min_version, body=%s", body)
	}

	// And the enrollment row must NOT be marked consumed (the
	// transaction never opened — the version check refused before).
	var consumedAt sql.NullInt64
	db.DB.QueryRow(
		`SELECT consumed_at FROM enrollment_tokens WHERE token_hash = $1`,
		auth.HashToken(plain),
	).Scan(&consumedAt)
	if consumedAt.Valid {
		t.Error("rejected register attempt must NOT consume the enrollment token")
	}
}

func TestEdgeRegister_AtomicityOnInsertFailure(t *testing.T) {
	// Forced failure: pre-seed an edges row with a token_hash
	// collision (impossible in practice with 256-bit tokens but
	// useful to assert that ANY insert failure leaves the
	// enrollment token un-consumed).
	app := edgeFederationEnv(t)
	plain := seedEnrollment(t, "tenant-3", time.Hour)

	// Insert a row with a primary key the registerEdge handler is
	// about to want — impossible since IDs are UUIDs, so instead
	// drop the edges table's NOT NULL on tenant_id to provoke a
	// generic insert error. Simpler: corrupt the schema by adding
	// an extra CHECK that the test row will violate.
	if _, err := db.DB.Exec(`ALTER TABLE edges ADD CONSTRAINT block_tenant_3 CHECK (tenant_id != 'tenant-3')`); err != nil {
		t.Fatalf("install constraint: %v", err)
	}
	defer db.DB.Exec(`ALTER TABLE edges DROP CONSTRAINT block_tenant_3`)

	resp := postEdgeRegister(t, app, map[string]string{
		"enrollment_token": plain,
		"edge_version":     "0.1.0",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 from insert failure, got %d", resp.StatusCode)
	}

	// Enrollment token NOT marked consumed (transaction rolled
	// back). This is the single-use invariant: a failed register
	// leaves the token replayable, which is what we want.
	var consumedAt sql.NullInt64
	db.DB.QueryRow(
		`SELECT consumed_at FROM enrollment_tokens WHERE token_hash = $1`,
		auth.HashToken(plain),
	).Scan(&consumedAt)
	if consumedAt.Valid {
		t.Error("failed register must NOT mark enrollment consumed (transaction atomicity)")
	}
}

// seedEdgeForPoll inserts an active edge row with a known token,
// returning the plaintext for use in poll-request Authorization.
func seedEdgeForPoll(t *testing.T, id, tenantID string, expiryFromNow time.Duration) string {
	t.Helper()
	plain := "vet_test_" + id + "_polltok"
	hash := auth.HashToken(plain)
	now := time.Now().Unix()
	expiry := now + int64(expiryFromNow.Seconds())
	if _, err := db.DB.Exec(
		`INSERT INTO edges
		     (id, tenant_id, token_hash, token_issued_at, token_expires_at,
		      edge_version, status, last_seen_at, created_at)
		     VALUES ($1, $2, $3, $4, $5, '0.1.0', 'active', $6, $7)`,
		id, tenantID, hash, now, expiry, now, now,
	); err != nil {
		t.Fatalf("seed edge: %v", err)
	}
	return plain
}

func postEdgePoll(t *testing.T, app *fiber.App, token string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/edge/poll", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	return resp
}

func TestEdgePoll_HappyPath_NoRotation(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-poll-1", "tenant-1", 25*24*time.Hour) // 25d > 7d window

	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(7),
			"signature": "edgesig-7",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body=%s", resp.StatusCode, body)
	}
	var out struct {
		VantageVersion       string         `json:"vantage_version"`
		AuditChainHead       map[string]any `json:"audit_chain_head"`
		Commands             []any          `json:"commands"`
		NewEdgeToken         *string        `json:"new_edge_token"`
		NextPollAfterSeconds int            `json:"next_poll_after_seconds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.VantageVersion == "" {
		t.Error("vantage_version should be populated")
	}
	if out.Commands == nil {
		t.Error("commands should be [] not null")
	}
	if len(out.Commands) != 0 {
		t.Errorf("commands should be empty in F2, got %d", len(out.Commands))
	}
	if out.NewEdgeToken != nil {
		t.Errorf("token not in rotation window; new_edge_token should be null, got %v", *out.NewEdgeToken)
	}
	if out.NextPollAfterSeconds != 15 {
		t.Errorf("next_poll_after_seconds should default to 15, got %d", out.NextPollAfterSeconds)
	}

	// Checkpoint persisted.
	var cnt int
	db.DB.QueryRow(
		`SELECT COUNT(*) FROM audit_checkpoints WHERE counterparty_type = 'edge' AND counterparty_id = 'edge-poll-1' AND chain_seq = 7`,
	).Scan(&cnt)
	if cnt != 1 {
		t.Errorf("expected 1 checkpoint row for edge-poll-1 seq=7, got %d", cnt)
	}
}

func TestEdgePoll_TriggersTokenRotation(t *testing.T) {
	app := edgeFederationEnv(t)
	// Expiry 3 days out — inside the 7-day rotation window.
	plain := seedEdgeForPoll(t, "edge-poll-rot", "tenant-1", 3*24*time.Hour)

	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out struct {
		NewEdgeToken      string `json:"new_edge_token"`
		NewTokenExpiresAt int64  `json:"new_token_expires_at"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.NewEdgeToken == "" {
		t.Fatal("expected new_edge_token on rotation")
	}
	if out.NewEdgeToken[:4] != "vet_" {
		t.Errorf("rotated token wrong prefix: %q", out.NewEdgeToken)
	}
	// New plaintext != old plaintext.
	if out.NewEdgeToken == plain {
		t.Error("rotated token must differ from prior plaintext")
	}

	// DB row updated to the new hash.
	var storedHash string
	db.DB.QueryRow(`SELECT token_hash FROM edges WHERE id = 'edge-poll-rot'`).Scan(&storedHash)
	if storedHash != auth.HashToken(out.NewEdgeToken) {
		t.Error("stored token_hash doesn't match rotated plaintext")
	}
}

func TestEdgePoll_BelowMinimumVersion(t *testing.T) {
	t.Setenv("MINIMUM_REQUIRED_EDGE_VERSION", "1.0.0")
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-poll-old", "tenant-1", 25*24*time.Hour)

	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.9.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("expected 426, got %d", resp.StatusCode)
	}
}

func TestEdgePoll_RequiresAuth(t *testing.T) {
	app := edgeFederationEnv(t)
	resp := postEdgePoll(t, app, "", map[string]interface{}{
		"edge_version": "0.1.0",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}
}

func postEdgeEventsHTTP(t *testing.T, app *fiber.App, token string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/edge/events", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	return resp
}

func TestEdgeEvents_HappyPathBatch(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-evt-1", "tenant-1", 25*24*time.Hour)

	resp := postEdgeEventsHTTP(t, app, plain, map[string]interface{}{
		"events": []map[string]interface{}{
			{"correlation_id": "c1", "type": "heartbeat", "occurred_at": time.Now().Unix(), "payload": map[string]string{}},
			{"correlation_id": "c2", "type": "alert", "occurred_at": time.Now().Unix(), "payload": map[string]string{"severity": "warn"}},
		},
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(10),
			"signature": "edgesig-10",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body=%s", resp.StatusCode, body)
	}
	var out struct {
		Accepted int `json:"accepted"`
		Rejected []struct {
			CorrelationID string `json:"correlation_id"`
			Reason        string `json:"reason"`
		} `json:"rejected"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Accepted != 2 || len(out.Rejected) != 0 {
		t.Errorf("expected accepted=2, rejected=0; got %+v", out)
	}

	// Checkpoint persisted with recorded_during=events.
	var during string
	db.DB.QueryRow(
		`SELECT recorded_during FROM audit_checkpoints WHERE counterparty_id = 'edge-evt-1' AND chain_seq = 10`,
	).Scan(&during)
	if during != "events" {
		t.Errorf("recorded_during should be 'events', got %q", during)
	}
}

func TestEdgeEvents_UnknownTypeRejected(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-evt-bad", "tenant-1", 25*24*time.Hour)

	resp := postEdgeEventsHTTP(t, app, plain, map[string]interface{}{
		"events": []map[string]interface{}{
			{"correlation_id": "c-bad", "type": "telemetry-burst", "occurred_at": time.Now().Unix()},
		},
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	var out struct {
		Accepted int `json:"accepted"`
		Rejected []struct {
			CorrelationID string `json:"correlation_id"`
			Reason        string `json:"reason"`
		} `json:"rejected"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Accepted != 0 {
		t.Errorf("unknown event type should not be accepted; got %d", out.Accepted)
	}
	if len(out.Rejected) != 1 || out.Rejected[0].CorrelationID != "c-bad" {
		t.Errorf("expected one rejection for c-bad, got %+v", out.Rejected)
	}
}

func TestEdgeEvents_BatchSizeCap(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-evt-big", "tenant-1", 25*24*time.Hour)

	big := make([]map[string]interface{}, 101)
	for i := range big {
		big[i] = map[string]interface{}{
			"correlation_id": fmt.Sprintf("c%d", i),
			"type":           "heartbeat",
			"occurred_at":    time.Now().Unix(),
		}
	}
	resp := postEdgeEventsHTTP(t, app, plain, map[string]interface{}{
		"events": big,
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("oversize batch should be 400, got %d", resp.StatusCode)
	}
}

func TestEdgeRegister_ConcurrentConsumptionRace(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEnrollment(t, "tenant-race", time.Hour)

	const N = 10
	var wg sync.WaitGroup
	statuses := make([]int, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := postEdgeRegister(t, app, map[string]interface{}{
				"enrollment_token": plain,
				"edge_version":     "0.1.0",
				"edge_hostname":    fmt.Sprintf("racer-%d", i),
			})
			defer resp.Body.Close()
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	successCount, conflictCount := 0, 0
	for _, s := range statuses {
		switch s {
		case http.StatusOK:
			successCount++
		case http.StatusConflict:
			conflictCount++
		}
	}
	if successCount != 1 {
		t.Errorf("exactly one register should succeed, got %d (statuses: %v)", successCount, statuses)
	}
	if conflictCount != N-1 {
		t.Errorf("expected %d conflicts, got %d", N-1, conflictCount)
	}

	var rowCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM edges`).Scan(&rowCount); err != nil {
		t.Fatal(err)
	}
	if rowCount != 1 {
		t.Errorf("exactly one edges row should exist, got %d", rowCount)
	}

	var consumedAt sql.NullInt64
	db.DB.QueryRow(
		`SELECT consumed_at FROM enrollment_tokens WHERE token_hash = $1`,
		auth.HashToken(plain),
	).Scan(&consumedAt)
	if !consumedAt.Valid {
		t.Error("consumed_at should be set exactly once after the race")
	}
}

// TestEdgePoll_TokenRotation_OldTokenImmediatelyInvalid locks the
// atomic-rotation contract: after the rotation poll, the prior
// plaintext is dead server-side immediately. No grace window.
// F3's Edge-side implementation MUST atomically persist the new
// token before issuing any subsequent request.
func TestEdgePoll_TokenRotation_OldTokenImmediatelyInvalid(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-rot-atomic", "tenant-1", 3*24*time.Hour)

	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotation poll status %d", resp.StatusCode)
	}
	var out struct {
		NewEdgeToken string `json:"new_edge_token"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.NewEdgeToken == "" {
		t.Fatal("expected rotation; no new_edge_token in response")
	}

	// Old token must be dead immediately.
	resp2 := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(2),
			"signature": "sig",
		},
	})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("old token after rotation must be 401 immediately; got %d", resp2.StatusCode)
	}

	// New token works.
	resp3 := postEdgePoll(t, app, out.NewEdgeToken, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(3),
			"signature": "sig",
		},
	})
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("new token should succeed, got %d", resp3.StatusCode)
	}
}

// TestEdgeRegister_RateLimitPerToken: hammer /register with the
// same enrollment_token. After 10 attempts in a minute the 11th
// should hit the rate limit (429) — not 401. Proves the limiter
// is per-token, not per-attempt.
func TestEdgeRegister_RateLimitPerToken(t *testing.T) {
	app := edgeFederationEnv(t)
	const sameToken = "vrt_unknown_burner"

	statuses := make([]int, 11)
	for i := 0; i < 11; i++ {
		resp := postEdgeRegister(t, app, map[string]string{
			"enrollment_token": sameToken,
			"edge_version":     "0.1.0",
		})
		statuses[i] = resp.StatusCode
		resp.Body.Close()
	}
	limit429Count := 0
	auth401Count := 0
	for _, s := range statuses {
		switch s {
		case http.StatusTooManyRequests:
			limit429Count++
		case http.StatusUnauthorized:
			auth401Count++
		}
	}
	if auth401Count != 10 {
		t.Errorf("expected first 10 attempts to be 401, got auth401Count=%d (statuses: %v)", auth401Count, statuses)
	}
	if limit429Count != 1 {
		t.Errorf("expected exactly one 429 (11th), got %d (statuses: %v)", limit429Count, statuses)
	}
}

// TestEdgeRegister_RateLimitScopedPerToken: 11 distinct tokens
// from a single source — each gets its own bucket so none of
// them should hit the limit. Proves the limiter is NOT collapsing
// to per-IP buckets (which would have rejected the 11th).
func TestEdgeRegister_RateLimitScopedPerToken(t *testing.T) {
	app := edgeFederationEnv(t)

	statuses := make([]int, 11)
	for i := 0; i < 11; i++ {
		resp := postEdgeRegister(t, app, map[string]string{
			"enrollment_token": fmt.Sprintf("vrt_distinct_burner_%d", i),
			"edge_version":     "0.1.0",
		})
		statuses[i] = resp.StatusCode
		resp.Body.Close()
	}
	for i, s := range statuses {
		if s == http.StatusTooManyRequests {
			t.Errorf("request %d hit 429; per-token bucket should have allowed it (statuses: %v)", i, statuses)
		}
	}
}

// audit_chain_head validation (codex finding #2). Persisting an
// empty signature would silently degrade the tamper-evidence
// contract from #22 Q9. Handlers must reject before any DB write.

func TestPoll_MissingSignature(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-poll-nosig", "tenant-1", 25*24*time.Hour)
	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq": int64(1),
			// signature omitted
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing signature should be 400, got %d", resp.StatusCode)
	}
	var checkpointCount int
	db.DB.QueryRow(`SELECT COUNT(*) FROM audit_checkpoints WHERE counterparty_id = 'edge-poll-nosig'`).Scan(&checkpointCount)
	if checkpointCount != 0 {
		t.Errorf("no checkpoint should have been written on rejected request, got %d", checkpointCount)
	}
}

func TestPoll_EmptySignature(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-poll-emptysig", "tenant-1", 25*24*time.Hour)
	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty signature should be 400, got %d", resp.StatusCode)
	}
}

func TestPoll_ZeroSeq(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-poll-zeroseq", "tenant-1", 25*24*time.Hour)
	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(0),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("seq=0 should be 400, got %d", resp.StatusCode)
	}
}

func TestPoll_NegativeSeq(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-poll-negseq", "tenant-1", 25*24*time.Hour)
	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(-5),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("seq<0 should be 400, got %d", resp.StatusCode)
	}
}

func TestEvents_MissingSignature(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-evt-nosig", "tenant-1", 25*24*time.Hour)
	resp := postEdgeEventsHTTP(t, app, plain, map[string]interface{}{
		"events": []map[string]interface{}{
			{"correlation_id": "c1", "type": "heartbeat", "occurred_at": time.Now().Unix()},
		},
		"audit_chain_head": map[string]interface{}{
			"seq": int64(1),
			// signature omitted
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("events with missing signature should be 400, got %d", resp.StatusCode)
	}
}

func TestEdgeRegister_MalformedClientVersion(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEnrollment(t, "tenant-malf", time.Hour)
	resp := postEdgeRegister(t, app, map[string]string{
		"enrollment_token": plain,
		"edge_version":     "totally-not-a-version",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed edge_version should be 400, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("invalid_edge_version")) {
		t.Errorf("body should carry code=invalid_edge_version, got %s", body)
	}
}

func TestEdgePoll_MalformedClientVersion(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-malf", "tenant-1", 25*24*time.Hour)
	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "🙃-not-semver",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed edge_version on poll should be 400, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("invalid_edge_version")) {
		t.Errorf("body should carry code=invalid_edge_version, got %s", body)
	}
}

// TestEdgePoll_ConcurrentRotationRace: codex round-3 finding #1.
// N concurrent polls from the same Edge with the same near-expiry
// token. The first to acquire the rotation row lock wins and
// returns new_edge_token; the others must see their token hash no
// longer match inside the transaction and return 401 with code
// token_concurrently_rotated. The edges.token_hash must match
// exactly the winner's new token at the end.
func TestEdgePoll_ConcurrentRotationRace(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-rot-race", "tenant-1", 3*24*time.Hour)

	const N = 10
	type result struct {
		status   int
		newToken string
		code     string
	}
	results := make([]result, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := postEdgePoll(t, app, plain, map[string]interface{}{
				"edge_version": "0.1.0",
				"audit_chain_head": map[string]interface{}{
					"seq":       int64(i + 1),
					"signature": fmt.Sprintf("sig-%d", i),
				},
			})
			defer resp.Body.Close()
			var out struct {
				NewEdgeToken string `json:"new_edge_token"`
				Code         string `json:"code"`
			}
			json.NewDecoder(resp.Body).Decode(&out)
			results[i] = result{status: resp.StatusCode, newToken: out.NewEdgeToken, code: out.Code}
		}(i)
	}
	wg.Wait()

	winners := 0
	rejected := 0
	winnerToken := ""
	for _, r := range results {
		switch {
		case r.status == http.StatusOK && r.newToken != "":
			winners++
			winnerToken = r.newToken
		case r.status == http.StatusUnauthorized:
			// Two valid rejection paths: middleware noticed the
			// row's hash had changed (auth lookup miss) OR the
			// in-tx revalidation fired (code=token_concurrently_
			// rotated). Both correctly refuse a stale token.
			rejected++
		}
	}
	if winners != 1 {
		t.Errorf("exactly one rotation winner expected, got %d (results: %+v)", winners, results)
	}
	if winners+rejected != N {
		t.Errorf("expected %d total winners+rejected, got winners=%d rejected=%d (results: %+v)", N, winners, rejected, results)
	}

	var storedHash string
	db.DB.QueryRow(`SELECT token_hash FROM edges WHERE id = 'edge-rot-race'`).Scan(&storedHash)
	if storedHash != auth.HashToken(winnerToken) {
		t.Error("edges.token_hash must match winner's new token after the race")
	}
}

// TestMaybeRotateToken_StaleHashReturnsErr drives the in-tx
// revalidation path directly. The concurrent test above can't
// deterministically land on this branch because middleware
// filters stale presentations first.
func TestMaybeRotateToken_StaleHashReturnsErr(t *testing.T) {
	_ = edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-stale", "tenant-1", 3*24*time.Hour)
	currentHash := auth.HashToken(plain)
	staleHash := auth.HashToken("vet_other_value_42")
	if currentHash == staleHash {
		t.Fatal("test fixture broken: hashes should differ")
	}

	_, _, err := maybeRotateToken("edge-stale", staleHash)
	if !errors.Is(err, ErrTokenHashMismatch) {
		t.Errorf("expected ErrTokenHashMismatch on stale presented hash, got %v", err)
	}
}

// TestEdgePoll_ChainReadFailure: codex round-3 finding #2. When
// the audit_log table is unavailable (simulated by dropping it),
// LatestChainHead errors and the poll handler must return 500
// chain_read_failed rather than emit a fake genesis-shaped head.
func TestEdgePoll_ChainReadFailure(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-chainfail", "tenant-1", 25*24*time.Hour)

	// Drop the audit_log table so LatestChainHead errors with
	// "relation does not exist".
	if _, err := db.DB.Exec(`DROP TABLE audit_log CASCADE`); err != nil {
		t.Fatalf("drop audit_log: %v", err)
	}

	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("chain read failure should be 500, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("chain_read_failed")) {
		t.Errorf("body should carry code=chain_read_failed, got %s", body)
	}
}

// TestPoll_CheckpointWriteFails: codex round-3 finding #3. When
// the audit_checkpoints table is unavailable (simulated by drop),
// the synchronous checkpoint write should return an error and the
// handler must surface 500 checkpoint_write_failed rather than
// silently dropping the cross-attestation record.
func TestPoll_CheckpointWriteFails(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-chkfail", "tenant-1", 25*24*time.Hour)
	if _, err := db.DB.Exec(`DROP TABLE audit_checkpoints CASCADE`); err != nil {
		t.Fatalf("drop audit_checkpoints: %v", err)
	}
	resp := postEdgePoll(t, app, plain, map[string]interface{}{
		"edge_version": "0.1.0",
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("checkpoint write failure should be 500, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("checkpoint_write_failed")) {
		t.Errorf("body should carry code=checkpoint_write_failed, got %s", body)
	}
}

// TestEvents_CheckpointWriteFails: same coverage on /api/edge/events.
func TestEvents_CheckpointWriteFails(t *testing.T) {
	app := edgeFederationEnv(t)
	plain := seedEdgeForPoll(t, "edge-evt-chkfail", "tenant-1", 25*24*time.Hour)
	if _, err := db.DB.Exec(`DROP TABLE audit_checkpoints CASCADE`); err != nil {
		t.Fatalf("drop audit_checkpoints: %v", err)
	}
	resp := postEdgeEventsHTTP(t, app, plain, map[string]interface{}{
		"events": []map[string]interface{}{
			{"correlation_id": "c1", "type": "heartbeat", "occurred_at": time.Now().Unix()},
		},
		"audit_chain_head": map[string]interface{}{
			"seq":       int64(1),
			"signature": "sig",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("events checkpoint failure should be 500, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("checkpoint_write_failed")) {
		t.Errorf("body should carry code=checkpoint_write_failed, got %s", body)
	}
}
