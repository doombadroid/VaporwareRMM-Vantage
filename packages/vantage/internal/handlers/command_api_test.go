package handlers

import (
	"bytes"
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

// commandAPIEnv builds an app with command routes behind a stub auth
// middleware that injects the given operator role/user (mirrors
// tailscaleTestEnv). Seeds the operator user row for the audit FK.
func commandAPIEnv(t *testing.T, role string) *fiber.App {
	t.Helper()
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL to a Postgres connection string")
	}
	if err := crypto.SetKeyForTests(tailscaleTestEncryptionKey); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)

	conn, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = conn.Exec(dropAllForCommandAPITest)
	_ = conn.Close()
	t.Cleanup(func() {
		if db.DB != nil {
			_, _ = db.DB.Exec(dropAllForCommandAPITest)
			_ = db.DB.Close()
			db.DB = nil
		}
	})
	if err := db.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	if _, err := db.DB.Exec(
		`INSERT INTO users (id, email, password_hash, role) VALUES ('op-user', 'op@vantage.local', 'x', $1) ON CONFLICT DO NOTHING`,
		role,
	); err != nil {
		t.Fatalf("seed op user: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	api := app.Group("/api/v1", func(c *fiber.Ctx) error {
		c.Locals("user_role", role)
		c.Locals("user_id", "op-user")
		return c.Next()
	})
	RegisterCommandRoutes(api)
	return app
}

const dropAllForCommandAPITest = `DROP TABLE IF EXISTS command_queue, tags, tag_endpoint_membership, audit_checkpoints, enrollment_tokens, vantage_signing_key, tailscale_connection, audit_log, user_sessions, users, edges, schema_migrations CASCADE`

func doCmd(t *testing.T, app *fiber.App, method, path string, body interface{}) *http.Response {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	return resp
}

func seedTag(t *testing.T, tagID, tenantID, edgeID, name string, endpoints ...string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO tags (id, tenant_id, edge_id, name) VALUES ($1,$2,$3,$4)`, tagID, tenantID, edgeID, name); err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	for _, ep := range endpoints {
		if _, err := db.DB.Exec(`INSERT INTO tag_endpoint_membership (tag_id, endpoint_id) VALUES ($1,$2)`, tagID, ep); err != nil {
			t.Fatalf("seed membership: %v", err)
		}
	}
}

func TestEnqueue_EndpointTarget(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)

	resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id":        "edge-1",
		"targets":        map[string]any{"kind": "endpoint", "values": []string{"host-a", "host-b", "host-a"}}, // dup
		"command_type":   "restart_service",
		"command_params": map[string]any{"service_name": "nginx"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var out struct {
		CorrelationIDs []string `json:"correlation_ids"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.CorrelationIDs) != 2 { // host-a deduped
		t.Fatalf("correlation_ids=%d, want 2 (deduped)", len(out.CorrelationIDs))
	}
	var n int
	db.DB.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE edge_id='edge-1' AND state='queued'`).Scan(&n)
	if n != 2 {
		t.Errorf("queued rows=%d, want 2", n)
	}
	// tenant_id inherited from the edge.
	var tenant string
	db.DB.QueryRow(`SELECT tenant_id FROM command_queue WHERE edge_id='edge-1' LIMIT 1`).Scan(&tenant)
	if tenant != "tenant-x" {
		t.Errorf("command tenant=%q, want tenant-x (inherited from edge)", tenant)
	}
}

func TestEnqueue_TagTarget(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	seedTag(t, "tag-1", "tenant-x", "edge-1", "linux-prod", "h1", "h2", "h3")

	resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id":        "edge-1",
		"targets":        map[string]any{"kind": "tag", "values": []string{"linux-prod"}},
		"command_type":   "restart_service",
		"command_params": map[string]any{"service_name": "nginx"},
	})
	defer resp.Body.Close()
	var out struct {
		CorrelationIDs []string `json:"correlation_ids"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.CorrelationIDs) != 3 {
		t.Errorf("tag expansion → %d commands, want 3", len(out.CorrelationIDs))
	}
}

func TestEnqueue_EmptyTarget_400(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	// tag with no members
	seedTag(t, "tag-empty", "tenant-x", "edge-1", "empty-tag")
	resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id":        "edge-1",
		"targets":        map[string]any{"kind": "tag", "values": []string{"empty-tag"}},
		"command_type":   "restart_service",
		"command_params": map[string]any{"service_name": "nginx"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("empty tag: status=%d, want 400", resp.StatusCode)
	}
}

func TestEnqueue_UnknownEdge_404(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id":        "no-such-edge",
		"targets":        map[string]any{"kind": "endpoint", "values": []string{"h1"}},
		"command_type":   "restart_service",
		"command_params": map[string]any{"service_name": "nginx"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("unknown edge: status=%d, want 404", resp.StatusCode)
	}
}

func TestEnqueue_Validation_400(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	cases := []map[string]any{
		{"edge_id": "edge-1", "targets": map[string]any{"kind": "bogus", "values": []string{"h1"}}, "command_type": "restart_service", "command_params": map[string]any{"service_name": "x"}},
		{"edge_id": "edge-1", "targets": map[string]any{"kind": "endpoint", "values": []string{"h1"}}, "command_type": "reboot", "command_params": map[string]any{"service_name": "x"}},
		{"edge_id": "edge-1", "targets": map[string]any{"kind": "endpoint", "values": []string{"h1"}}, "command_type": "restart_service", "command_params": map[string]any{}}, // missing service_name
	}
	for i, body := range cases {
		resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", body)
		if resp.StatusCode != 400 {
			t.Errorf("case %d: status=%d, want 400", i, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestEnqueue_RequiresSuperAdmin_403(t *testing.T) {
	app := commandAPIEnv(t, "admin") // not super_admin
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id":        "edge-1",
		"targets":        map[string]any{"kind": "endpoint", "values": []string{"h1"}},
		"command_type":   "restart_service",
		"command_params": map[string]any{"service_name": "nginx"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("non-super_admin enqueue: status=%d, want 403", resp.StatusCode)
	}
}

func TestEnqueue_InactiveEdge_409(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	db.DB.Exec(`UPDATE edges SET status='unpaired' WHERE id='edge-1'`)
	resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id": "edge-1", "targets": map[string]any{"kind": "endpoint", "values": []string{"h1"}},
		"command_type": "restart_service", "command_params": map[string]any{"service_name": "nginx"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Errorf("enqueue to inactive edge: status=%d, want 409", resp.StatusCode)
	}
}

// TestCancel_DeliveredToEdge_200: F4b restores Decision 6's full cancel window.
// A command in delivered_to_edge is still pre-dispatch from the endpoint's POV
// — the Edge has it locally but has not yet handed it to the agent. The cancel
// signal in the Edge's next poll response tells it to drop the command before
// dispatch, so Vantage can transition delivered_to_edge → cancelled.
func TestCancel_DeliveredToEdge_200(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id": "edge-1", "targets": map[string]any{"kind": "endpoint", "values": []string{"h1"}},
		"command_type": "restart_service", "command_params": map[string]any{"service_name": "nginx"},
	})
	var enq struct {
		CorrelationIDs []string `json:"correlation_ids"`
	}
	json.NewDecoder(resp.Body).Decode(&enq)
	resp.Body.Close()
	cid := enq.CorrelationIDs[0]
	// Edge acked it (delivered_to_edge). Under F4b this is still cancellable.
	db.DB.Exec(`UPDATE command_queue SET state='delivered_to_edge' WHERE correlation_id=$1`, cid)
	c := doCmd(t, app, http.MethodDelete, "/api/v1/commands/"+cid, nil)
	defer c.Body.Close()
	if c.StatusCode != 200 {
		t.Errorf("cancel delivered_to_edge: status=%d, want 200 (F4b restored window)", c.StatusCode)
	}
	var st string
	db.DB.QueryRow(`SELECT state FROM command_queue WHERE correlation_id=$1`, cid).Scan(&st)
	if st != "cancelled" {
		t.Errorf("state after cancel=%s, want cancelled", st)
	}
}

func TestCancel_QueuedSucceeds_DispatchedConflicts(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)

	// Enqueue one, capture its correlation_id.
	resp := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id":        "edge-1",
		"targets":        map[string]any{"kind": "endpoint", "values": []string{"h1"}},
		"command_type":   "restart_service",
		"command_params": map[string]any{"service_name": "nginx"},
	})
	var enq struct {
		CorrelationIDs []string `json:"correlation_ids"`
	}
	json.NewDecoder(resp.Body).Decode(&enq)
	resp.Body.Close()
	cid := enq.CorrelationIDs[0]

	// Cancel while queued → 200.
	cresp := doCmd(t, app, http.MethodDelete, "/api/v1/commands/"+cid, nil)
	if cresp.StatusCode != 200 {
		t.Fatalf("cancel queued: status=%d, want 200", cresp.StatusCode)
	}
	cresp.Body.Close()
	var st string
	db.DB.QueryRow(`SELECT state FROM command_queue WHERE correlation_id=$1`, cid).Scan(&st)
	if st != "cancelled" {
		t.Errorf("state after cancel=%s, want cancelled", st)
	}

	// A second command, force it past the cancellable window → 409.
	resp2 := doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id":        "edge-1",
		"targets":        map[string]any{"kind": "endpoint", "values": []string{"h2"}},
		"command_type":   "restart_service",
		"command_params": map[string]any{"service_name": "nginx"},
	})
	var enq2 struct {
		CorrelationIDs []string `json:"correlation_ids"`
	}
	json.NewDecoder(resp2.Body).Decode(&enq2)
	resp2.Body.Close()
	cid2 := enq2.CorrelationIDs[0]
	db.DB.Exec(`UPDATE command_queue SET state='delivered_to_endpoint' WHERE correlation_id=$1`, cid2)

	conf := doCmd(t, app, http.MethodDelete, "/api/v1/commands/"+cid2, nil)
	defer conf.Body.Close()
	if conf.StatusCode != 409 {
		t.Errorf("cancel dispatched: status=%d, want 409", conf.StatusCode)
	}
}

func TestCancel_Unknown_404(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	resp := doCmd(t, app, http.MethodDelete, "/api/v1/commands/no-such-cid", nil)
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("cancel unknown: status=%d, want 404", resp.StatusCode)
	}
}

// TestListCommands_StablePagination: commands sharing a queued_at second (a
// tag/multi-endpoint fan-out) must page without dup/skip thanks to the id
// tie-breaker (codex round 5 #1).
func TestListCommands_RequiresSuperAdmin_403(t *testing.T) {
	app := commandAPIEnv(t, "admin") // authenticated, but not super_admin
	resp := doCmd(t, app, http.MethodGet, "/api/v1/commands", nil)
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("list commands as admin: status=%d, want 403", resp.StatusCode)
	}
}

func TestListCommands_StablePagination(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	// One enqueue → 3 commands, all the same queued_at second.
	doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id": "edge-1", "targets": map[string]any{"kind": "endpoint", "values": []string{"h1", "h2", "h3"}},
		"command_type": "restart_service", "command_params": map[string]any{"service_name": "nginx"},
	}).Body.Close()

	seen := map[string]int{}
	for _, url := range []string{
		"/api/v1/commands?edge_id=edge-1&limit=2&offset=0",
		"/api/v1/commands?edge_id=edge-1&limit=2&offset=2",
	} {
		resp := doCmd(t, app, http.MethodGet, url, nil)
		var out struct {
			Data []CommandRow `json:"data"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		for _, r := range out.Data {
			seen[r.CorrelationID]++
		}
	}
	if len(seen) != 3 {
		t.Errorf("paged distinct correlation_ids=%d, want 3 (no skip)", len(seen))
	}
	for cid, n := range seen {
		if n != 1 {
			t.Errorf("%s appeared %d times across pages, want 1 (no dup)", cid, n)
		}
	}
}

func TestListCommands_FilterByEdgeAndState(t *testing.T) {
	app := commandAPIEnv(t, "super_admin")
	seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	seedEdgeForPoll(t, "edge-2", "tenant-y", time.Hour)
	doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id": "edge-1", "targets": map[string]any{"kind": "endpoint", "values": []string{"h1", "h2"}},
		"command_type": "restart_service", "command_params": map[string]any{"service_name": "nginx"},
	}).Body.Close()
	doCmd(t, app, http.MethodPost, "/api/v1/commands", map[string]any{
		"edge_id": "edge-2", "targets": map[string]any{"kind": "endpoint", "values": []string{"h3"}},
		"command_type": "restart_service", "command_params": map[string]any{"service_name": "nginx"},
	}).Body.Close()

	resp := doCmd(t, app, http.MethodGet, "/api/v1/commands?edge_id=edge-1&state=queued", nil)
	defer resp.Body.Close()
	var out struct {
		Data  []CommandRow `json:"data"`
		Total int          `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Total != 2 || len(out.Data) != 2 {
		t.Errorf("list edge-1/queued: total=%d len=%d, want 2/2", out.Total, len(out.Data))
	}
	for _, r := range out.Data {
		if r.EdgeID != "edge-1" {
			t.Errorf("filter leaked edge %s", r.EdgeID)
		}
	}
}
