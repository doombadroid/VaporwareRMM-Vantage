package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vaporrmm/vantage/internal/db"

	"github.com/gofiber/fiber/v2"
)

// seedQueuedCommand inserts a queued command_queue row directly (bypassing
// the operator API so these edge-side tests stay self-contained). Returns the
// correlation_id. operator_user_id references the seed-admin user that
// edgeFederationEnv creates.
func seedQueuedCommand(t *testing.T, correlationID, tenantID, edgeID, endpointID string, expiresAt int64) {
	t.Helper()
	now := time.Now().Unix()
	if _, err := db.DB.Exec(`
		INSERT INTO command_queue
			(correlation_id, tenant_id, edge_id, target_endpoint_id, command_type,
			 command_params, state, queued_at, expires_at, operator_user_id)
		VALUES ($1, $2, $3, $4, 'restart_service', '{"service_name":"nginx"}', 'queued', $5, $6, 'seed-admin')`,
		correlationID, tenantID, edgeID, endpointID, now, expiresAt); err != nil {
		t.Fatalf("seed command: %v", err)
	}
}

func cmdState(t *testing.T, correlationID string) string {
	t.Helper()
	var st string
	if err := db.DB.QueryRow(`SELECT state FROM command_queue WHERE correlation_id = $1`, correlationID).Scan(&st); err != nil {
		t.Fatalf("read state: %v", err)
	}
	return st
}

func callCommandsAck(t *testing.T, app *fiber.App, token string, ackedIDs []string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"acked_correlation_ids": ackedIDs})
	req := httptest.NewRequest(http.MethodPost, "/api/edge/commands/ack", bytes.NewReader(b))
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

func pollBody() map[string]any {
	return map[string]any{
		"edge_version":     "0.1.0",
		"audit_chain_head": map[string]any{"seq": 1, "signature": "edge-sig"},
	}
}

func TestPoll_DeliversPendingCommands(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	future := time.Now().Unix() + 3600
	seedQueuedCommand(t, "cid-1", "tenant-x", "edge-1", "host-a", future)
	seedQueuedCommand(t, "cid-2", "tenant-x", "edge-1", "host-b", future)

	resp := postEdgePoll(t, app, tok, pollBody())
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("poll status=%d", resp.StatusCode)
	}
	var out struct {
		Commands []struct {
			CorrelationID    string          `json:"correlation_id"`
			TargetEndpointID string          `json:"target_endpoint_id"`
			CommandType      string          `json:"command_type"`
			CommandParams    json.RawMessage `json:"command_params"`
		} `json:"commands"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Commands) != 2 {
		t.Fatalf("poll commands=%d, want 2", len(out.Commands))
	}
	// Poll must NOT transition state — both still queued.
	if s := cmdState(t, "cid-1"); s != "queued" {
		t.Errorf("cid-1 state after poll=%s, want queued (poll does not transition)", s)
	}
	// Command shape carries params for the agent.
	if out.Commands[0].CommandType != "restart_service" {
		t.Errorf("command_type=%s", out.Commands[0].CommandType)
	}
}

func TestPoll_ExcludesExpiredCommands(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	past := time.Now().Unix() - 10
	seedQueuedCommand(t, "cid-stale", "tenant-x", "edge-1", "host-a", past) // expired-but-not-yet-swept

	resp := postEdgePoll(t, app, tok, pollBody())
	defer resp.Body.Close()
	var out struct {
		Commands []json.RawMessage `json:"commands"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Commands) != 0 {
		t.Errorf("poll delivered %d commands, want 0 (expired excluded)", len(out.Commands))
	}
}

// TestPoll_RedeliversDeliveredToEdgePastTTL: a delivered_to_edge command whose
// queued TTL has lapsed must still be re-polled (round 1 #3) so an Edge that
// crashed before dispatch can recover it, rather than stranding it forever.
func TestPoll_RedeliversDeliveredToEdgePastTTL(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	seedQueuedCommand(t, "cid-acked", "tenant-x", "edge-1", "host-a", time.Now().Unix()-10) // expires_at in past
	db.DB.Exec(`UPDATE command_queue SET state='delivered_to_edge' WHERE correlation_id='cid-acked'`)

	resp := postEdgePoll(t, app, tok, pollBody())
	defer resp.Body.Close()
	var out struct {
		Commands []struct {
			CorrelationID string `json:"correlation_id"`
		} `json:"commands"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	found := false
	for _, c := range out.Commands {
		if c.CorrelationID == "cid-acked" {
			found = true
		}
	}
	if !found {
		t.Error("delivered_to_edge command past TTL was not re-polled (would strand on Edge crash)")
	}
}

func TestCommandsAck_TransitionsAndIsIdempotent(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	future := time.Now().Unix() + 3600
	seedQueuedCommand(t, "cid-1", "tenant-x", "edge-1", "host-a", future)

	// First ack: queued -> delivered_to_edge.
	resp := callCommandsAck(t, app, tok, []string{"cid-1"})
	var out struct {
		Acked int `json:"acked"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Acked != 1 {
		t.Fatalf("first ack acked=%d, want 1", out.Acked)
	}
	if s := cmdState(t, "cid-1"); s != "delivered_to_edge" {
		t.Errorf("state after ack=%s, want delivered_to_edge", s)
	}

	// Re-ack is idempotent: no transition, no error, acked=0.
	resp2 := callCommandsAck(t, app, tok, []string{"cid-1"})
	var out2 struct {
		Acked int `json:"acked"`
	}
	json.NewDecoder(resp2.Body).Decode(&out2)
	resp2.Body.Close()
	if resp2.StatusCode != 200 || out2.Acked != 0 {
		t.Errorf("re-ack: status=%d acked=%d, want 200/0 (idempotent)", resp2.StatusCode, out2.Acked)
	}
}

func TestCommandsAck_EdgeScoped(t *testing.T) {
	app := edgeFederationEnv(t)
	_ = seedEdgeForPoll(t, "edge-A", "tenant-x", time.Hour)
	tokB := seedEdgeForPoll(t, "edge-B", "tenant-x", time.Hour)
	future := time.Now().Unix() + 3600
	seedQueuedCommand(t, "cid-A", "tenant-x", "edge-A", "host-a", future) // belongs to edge-A

	// Edge B tries to ack edge A's command — must be a benign no-op.
	resp := callCommandsAck(t, app, tokB, []string{"cid-A"})
	var out struct {
		Acked int `json:"acked"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || out.Acked != 0 {
		t.Errorf("cross-edge ack: status=%d acked=%d, want 200/0", resp.StatusCode, out.Acked)
	}
	if s := cmdState(t, "cid-A"); s != "queued" {
		t.Errorf("edge-A command state=%s after edge-B ack, want queued (edge-scoped)", s)
	}
}
