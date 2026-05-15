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
	"strings"
	"sync"
	"testing"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
	"vaporrmm/vantage/internal/tailscale"

	"github.com/gofiber/fiber/v2"
)

// fakeTSClient implements the tailscaleAPI interface. Tests
// assemble per-case behavior in one struct literal instead of
// spinning up an httptest.Server per assertion.
type fakeTSClient struct {
	authenticate      func(ctx context.Context) error
	listTailnets      func(ctx context.Context) ([]tailscale.Tailnet, error)
	validateAuthKey   func(ctx context.Context, tn string) error
	validateDeviceLst func(ctx context.Context, tn string) error
	listDevices       func(ctx context.Context, tn string) ([]tailscale.Device, error)
	mintEnrollment    func(ctx context.Context, tn, desc string) (*tailscale.AuthKey, error)
	revokeAuthKey     func(ctx context.Context, tn, keyID string) error
}

func (f *fakeTSClient) Authenticate(ctx context.Context) error {
	if f.authenticate == nil {
		return nil
	}
	return f.authenticate(ctx)
}
func (f *fakeTSClient) ListTailnets(ctx context.Context) ([]tailscale.Tailnet, error) {
	if f.listTailnets == nil {
		return []tailscale.Tailnet{{Name: "acme.ts.net", DisplayName: "Acme"}}, nil
	}
	return f.listTailnets(ctx)
}
func (f *fakeTSClient) ValidateAuthKeyScope(ctx context.Context, tn string) error {
	if f.validateAuthKey == nil {
		return nil
	}
	return f.validateAuthKey(ctx, tn)
}
func (f *fakeTSClient) ValidateDeviceListScope(ctx context.Context, tn string) error {
	if f.validateDeviceLst == nil {
		return nil
	}
	return f.validateDeviceLst(ctx, tn)
}
func (f *fakeTSClient) ListDevices(ctx context.Context, tn string) ([]tailscale.Device, error) {
	if f.listDevices == nil {
		return []tailscale.Device{}, nil
	}
	return f.listDevices(ctx, tn)
}
func (f *fakeTSClient) MintEdgeEnrollmentAuthKey(ctx context.Context, tn, desc string) (*tailscale.AuthKey, error) {
	if f.mintEnrollment == nil {
		return &tailscale.AuthKey{ID: "fake-key-id", Key: "tskey-auth-fake"}, nil
	}
	return f.mintEnrollment(ctx, tn, desc)
}
func (f *fakeTSClient) RevokeAuthKey(ctx context.Context, tn, keyID string) error {
	if f.revokeAuthKey == nil {
		return nil
	}
	return f.revokeAuthKey(ctx, tn, keyID)
}

const tailscaleTestEncryptionKey = "fmZn0pFd/f58gKeknlaECEbcMDh5oQ+nRhFB/sAMScY="

// tailscaleTestEnv stands up a fresh DB + super-admin-identity-
// stamped Fiber app. Returns a `swap` closure tests use to install
// the per-case fake Tailscale client.
func tailscaleTestEnv(t *testing.T, role string) (*fiber.App, func(client tailscaleAPI)) {
	t.Helper()
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL to a Postgres connection string")
	}
	if err := crypto.SetKeyForTests(tailscaleTestEncryptionKey); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)

	// Reset state so each test starts with a fresh schema.
	conn, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
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
		t.Fatalf("db init: %v", err)
	}

	// Insert a real user row so the audit_log FK and the
	// tailscale_connection.connected_by_user_id FK are satisfied
	// when the handler stamps the actor ID into the row.
	if _, err := db.DB.Exec(
		`INSERT INTO users (id, email, password_hash, role) VALUES ('test-user', 'test@vantage.local', 'x', $1) ON CONFLICT DO NOTHING`,
		role,
	); err != nil {
		t.Fatalf("seed test-user: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	api := app.Group("/api/v1", func(c *fiber.Ctx) error {
		c.Locals("user_role", role)
		c.Locals("user_id", "test-user")
		return c.Next()
	})
	RegisterTailscaleRoutes(api)

	origFactory := tailscaleClientFactory
	t.Cleanup(func() { tailscaleClientFactory = origFactory })

	swap := func(client tailscaleAPI) {
		tailscaleClientFactory = func(string, string) tailscaleAPI { return client }
	}
	return app, swap
}

func postJSON(t *testing.T, app *fiber.App, path string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	return resp
}

func TestTailscaleValidate_AllChecksPass(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{})

	resp := postJSON(t, app, "/api/v1/tailscale/validate", map[string]string{
		"client_id":     "id",
		"client_secret": "secret",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var out struct {
		Checks   map[string]string   `json:"checks"`
		Tailnets []tailscale.Tailnet `json:"tailnets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"authentication", "auth_key_scope", "device_list_scope"} {
		if out.Checks[k] != "ok" {
			t.Errorf("%s expected ok, got %s", k, out.Checks[k])
		}
	}
	if len(out.Tailnets) != 1 || out.Tailnets[0].Name != "acme.ts.net" {
		t.Errorf("tailnets: %+v", out.Tailnets)
	}
}

func TestTailscaleValidate_AuthKeyScopeMissing(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{
		validateAuthKey: func(ctx context.Context, tn string) error {
			return tailscale.ErrTailscaleScopeMissingAuthKeys
		},
	})
	resp := postJSON(t, app, "/api/v1/tailscale/validate", map[string]string{
		"client_id":     "id",
		"client_secret": "secret",
	})
	defer resp.Body.Close()
	var out struct {
		Checks map[string]string `json:"checks"`
		Errors map[string]string `json:"errors"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Checks["auth_key_scope"] != "failed" {
		t.Errorf("expected failed, got %s", out.Checks["auth_key_scope"])
	}
	if !strings.Contains(out.Errors["auth_key_scope"], "auth_keys") {
		t.Errorf("error should mention auth_keys: %s", out.Errors["auth_key_scope"])
	}
}

func TestTailscaleValidate_NetworkError(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{
		authenticate: func(ctx context.Context) error { return tailscale.ErrTailscaleUnreachable },
	})
	resp := postJSON(t, app, "/api/v1/tailscale/validate", map[string]string{
		"client_id":     "id",
		"client_secret": "secret",
	})
	defer resp.Body.Close()
	var out struct {
		Checks map[string]string `json:"checks"`
		Errors map[string]string `json:"errors"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Checks["authentication"] != "failed" {
		t.Errorf("expected failed, got %s", out.Checks["authentication"])
	}
	if !strings.Contains(out.Errors["authentication"], "unreachable") {
		t.Errorf("error should say unreachable: %s", out.Errors["authentication"])
	}
}

func TestTailscaleConnect_RefusesIfAlreadyConnected(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{})
	body := map[string]string{"client_id": "id", "client_secret": "secret", "tailnet": "acme.ts.net"}
	r1 := postJSON(t, app, "/api/v1/tailscale/connect", body)
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first connect status=%d", r1.StatusCode)
	}
	r2 := postJSON(t, app, "/api/v1/tailscale/connect", body)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		t.Errorf("second connect should be 409, got %d", r2.StatusCode)
	}
}

func TestTailscaleConnect_EncryptsCredentialsAtRest(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{})
	resp := postJSON(t, app, "/api/v1/tailscale/connect", map[string]string{
		"client_id":     "PLAINTEXT-CLIENT-ID",
		"client_secret": "PLAINTEXT-CLIENT-SECRET",
		"tailnet":       "acme.ts.net",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect: %d", resp.StatusCode)
	}
	var encID, encSecret string
	if err := db.DB.QueryRow(
		`SELECT oauth_client_id_encrypted, oauth_client_secret_encrypted FROM tailscale_connection WHERE id = 'singleton'`,
	).Scan(&encID, &encSecret); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if encID == "PLAINTEXT-CLIENT-ID" || encSecret == "PLAINTEXT-CLIENT-SECRET" {
		t.Error("credentials stored in plaintext! encryption skipped")
	}
	if !strings.HasPrefix(encID, "enc:") || !strings.HasPrefix(encSecret, "enc:") {
		t.Errorf("expected enc: prefix on encrypted columns; got id=%q secret=%q", encID, encSecret)
	}
}

func TestTailscaleRotate_RequiresSameTailnet(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{})
	postJSON(t, app, "/api/v1/tailscale/connect", map[string]string{
		"client_id": "id1", "client_secret": "secret1", "tailnet": "acme.ts.net",
	}).Body.Close()

	swap(&fakeTSClient{
		listTailnets: func(ctx context.Context) ([]tailscale.Tailnet, error) {
			return []tailscale.Tailnet{{Name: "other.ts.net"}}, nil
		},
	})
	body, _ := json.Marshal(map[string]string{"client_id": "id2", "client_secret": "secret2"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tailscale/connection", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req, -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("rotation to different tailnet should be 400, got %d", resp.StatusCode)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(bodyBytes), "different tailnet") &&
		!strings.Contains(string(bodyBytes), "Disconnect and reconnect") {
		t.Errorf("error should mention disconnect-and-reconnect path: %s", string(bodyBytes))
	}
}

func TestTailscaleDisconnect_AuditsAndWipes(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{})
	postJSON(t, app, "/api/v1/tailscale/connect", map[string]string{
		"client_id": "id", "client_secret": "secret", "tailnet": "acme.ts.net",
	}).Body.Close()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tailscale/connection", nil)
	resp, _ := app.Test(req, -1)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disconnect status=%d", resp.StatusCode)
	}

	var cnt int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM tailscale_connection`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Errorf("expected 0 rows after disconnect, got %d", cnt)
	}
}

// TestTailscaleEndpoints_RequireSuperAdmin: an "admin" role must be
// refused. Vantage doesn't expose Tailscale management to non-super
// admins per #22 Q3.
func TestTailscaleEndpoints_RequireSuperAdmin(t *testing.T) {
	app, _ := tailscaleTestEnv(t, "admin")
	resp := postJSON(t, app, "/api/v1/tailscale/validate", map[string]string{
		"client_id":     "id",
		"client_secret": "secret",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("admin role should hit 403 on validate, got %d", resp.StatusCode)
	}
}

// TestConnectTailscale_ConcurrentConnect: codex round-3 finding #4.
// Two concurrent connect calls should resolve deterministically:
// exactly one 200, one 409 with code=already_connected. The
// pre-fix SELECT-then-INSERT pattern could return nondeterministic
// 500 from the loser's PK-violation.
func TestConnectTailscale_ConcurrentConnect(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{})
	body := map[string]string{"client_id": "id", "client_secret": "secret", "tailnet": "acme.ts.net"}

	const N = 5
	statuses := make([]int, N)
	codes := make([]string, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := postJSON(t, app, "/api/v1/tailscale/connect", body)
			defer resp.Body.Close()
			statuses[i] = resp.StatusCode
			var out struct {
				Code string `json:"code"`
			}
			json.NewDecoder(resp.Body).Decode(&out)
			codes[i] = out.Code
		}(i)
	}
	wg.Wait()

	wins, conflicts, fives := 0, 0, 0
	for i, s := range statuses {
		switch s {
		case http.StatusOK:
			wins++
		case http.StatusConflict:
			conflicts++
			if codes[i] != "already_connected" {
				t.Errorf("conflict %d should carry code=already_connected, got %q", i, codes[i])
			}
		case http.StatusInternalServerError:
			fives++
		}
	}
	if wins != 1 {
		t.Errorf("expected exactly 1 winner, got %d (statuses: %v)", wins, statuses)
	}
	if conflicts != N-1 {
		t.Errorf("expected %d conflicts, got %d (statuses: %v)", N-1, conflicts, statuses)
	}
	if fives != 0 {
		t.Errorf("no concurrent connect should return 500; got %d (statuses: %v)", fives, statuses)
	}
}

// TestRotateTailscaleConnection_RaceWithDisconnect: codex round-3
// finding #5. If the row is deleted between the rotate handler's
// SELECT and its UPDATE, the UPDATE silently affects zero rows.
// The new RowsAffected check returns 404 + code=not_connected
// and refuses to emit an audit row for the no-op rotation.
func TestRotateTailscaleConnection_RaceWithDisconnect(t *testing.T) {
	app, swap := tailscaleTestEnv(t, "super_admin")
	swap(&fakeTSClient{})
	postJSON(t, app, "/api/v1/tailscale/connect", map[string]string{
		"client_id": "id1", "client_secret": "secret1", "tailnet": "acme.ts.net",
	}).Body.Close()

	// Simulate the race by DELETing the singleton between the
	// rotate handler's logical SELECT and its UPDATE — we delete
	// before the rotate request runs since the handler's internal
	// SELECT happens immediately at request start, but the UPDATE
	// is what's testable as "zero rows".
	if _, err := db.DB.Exec(`DELETE FROM tailscale_connection WHERE id = 'singleton'`); err != nil {
		t.Fatalf("simulate disconnect: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"client_id": "id2", "client_secret": "secret2"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tailscale/connection", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req, -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("rotate after disconnect should be 404, got %d", resp.StatusCode)
	}
	out, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(out, []byte("not_connected")) {
		t.Errorf("body should carry code=not_connected, got %s", out)
	}

	// Audit log should NOT contain a tailscale.rotated entry
	// because the UPDATE landed zero rows.
	var auditCount int
	db.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'tailscale.rotated'`).Scan(&auditCount)
	if auditCount != 0 {
		t.Errorf("no rotate audit row should exist after zero-rows update; got %d", auditCount)
	}
}
