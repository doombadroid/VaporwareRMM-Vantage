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

// TestPoll_ExcludesQueuedWithinAckGrace: a queued command whose TTL is within
// ackGraceSeconds of expiry is NOT delivered (round 2 #1), so it can't be
// handed out and then expired before its ack lands.
func TestPoll_ExcludesQueuedWithinAckGrace(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	now := time.Now().Unix()
	seedQueuedCommand(t, "cid-soon", "tenant-x", "edge-1", "host-a", now+30)  // within 60s grace → excluded
	seedQueuedCommand(t, "cid-far", "tenant-x", "edge-1", "host-b", now+3600) // ample TTL → delivered

	resp := postEdgePoll(t, app, tok, pollBody())
	defer resp.Body.Close()
	var out struct {
		Commands []struct {
			CorrelationID string `json:"correlation_id"`
		} `json:"commands"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	got := map[string]bool{}
	for _, c := range out.Commands {
		got[c.CorrelationID] = true
	}
	if got["cid-soon"] {
		t.Error("delivered a queued command within the ack-grace window (could expire before ack)")
	}
	if !got["cid-far"] {
		t.Error("did not deliver a queued command with ample TTL")
	}
}

// TestPoll_QueuedOrderedBeforeRedeliveries: queued commands are delivered ahead
// of delivered_to_edge redeliveries even when the redelivery is older, so a
// backlog of stuck redeliveries can't starve new commands (round 2 #5).
func TestPoll_QueuedOrderedBeforeRedeliveries(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	now := time.Now().Unix()
	// An OLDER delivered_to_edge redelivery (earlier queued_at).
	seedQueuedCommand(t, "cid-old-delivered", "tenant-x", "edge-1", "host-a", now+3600)
	db.DB.Exec(`UPDATE command_queue SET state='delivered_to_edge', queued_at=$1 WHERE correlation_id='cid-old-delivered'`, now-100)
	// A NEWER queued command.
	seedQueuedCommand(t, "cid-new-queued", "tenant-x", "edge-1", "host-b", now+3600)

	resp := postEdgePoll(t, app, tok, pollBody())
	defer resp.Body.Close()
	var out struct {
		Commands []struct {
			CorrelationID string `json:"correlation_id"`
		} `json:"commands"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Commands) < 1 || out.Commands[0].CorrelationID != "cid-new-queued" {
		t.Errorf("queued command not ordered first; got %+v", out.Commands)
	}
}

// TestPoll_MarksPollDelivered: poll stamps poll_delivered_at on a delivered
// command (atomically with handing it out) WITHOUT changing its state, so
// cancellation can tell the command was handed to an Edge (codex round 3 #1).
func TestPoll_MarksPollDelivered(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	seedQueuedCommand(t, "cid-m", "tenant-x", "edge-1", "host-a", time.Now().Unix()+3600)

	postEdgePoll(t, app, tok, pollBody()).Body.Close()

	var marked int
	db.DB.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE correlation_id='cid-m' AND poll_delivered_at IS NOT NULL`).Scan(&marked)
	if marked != 1 {
		t.Error("poll did not stamp poll_delivered_at")
	}
	if s := cmdState(t, "cid-m"); s != "queued" {
		t.Errorf("poll changed state to %s, want queued (poll marks delivery, not state)", s)
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

// TestPoll_IncludesCancelledCorrelationIDs: F4b cancel-signal restoration.
// Cancelled commands that have not reached delivered_to_endpoint must appear
// in the poll response so the Edge can drop them before dispatch.
func TestPoll_IncludesCancelledCorrelationIDs(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	now := time.Now().Unix()
	future := now + 3600
	// One cancelled-from-queued (Edge may have it via prior poll), one
	// cancelled-from-delivered_to_edge (Edge acked it locally), one live
	// queued (should arrive in commands, NOT cancelled list), one
	// delivered_to_endpoint-then-cancelled (must NOT appear — past the
	// Decision 6 cutoff; in practice MarkCancelled would never have
	// transitioned this, but we force-state it to verify the
	// delivered_to_endpoint_at IS NULL guard in the fetch query).
	seedQueuedCommand(t, "cid-cancel-from-queued", "tenant-x", "edge-1", "host-a", future)
	db.DB.Exec(`UPDATE command_queue SET state='cancelled', terminal_at=$1 WHERE correlation_id='cid-cancel-from-queued'`, now)

	seedQueuedCommand(t, "cid-cancel-from-dte", "tenant-x", "edge-1", "host-b", future)
	db.DB.Exec(`UPDATE command_queue SET state='cancelled', terminal_at=$1 WHERE correlation_id='cid-cancel-from-dte'`, now)

	seedQueuedCommand(t, "cid-live", "tenant-x", "edge-1", "host-c", future)

	seedQueuedCommand(t, "cid-cancelled-but-dispatched", "tenant-x", "edge-1", "host-d", future)
	db.DB.Exec(`UPDATE command_queue SET state='cancelled', terminal_at=$1, delivered_to_endpoint_at=$1 WHERE correlation_id='cid-cancelled-but-dispatched'`, now)

	resp := postEdgePoll(t, app, tok, pollBody())
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("poll status=%d", resp.StatusCode)
	}
	var out struct {
		Commands []struct {
			CorrelationID string `json:"correlation_id"`
		} `json:"commands"`
		CancelledCorrelationIDs []string `json:"cancelled_correlation_ids"`
	}
	json.NewDecoder(resp.Body).Decode(&out)

	got := map[string]bool{}
	for _, c := range out.CancelledCorrelationIDs {
		got[c] = true
	}
	if !got["cid-cancel-from-queued"] {
		t.Error("missing cancelled-from-queued in cancelled_correlation_ids")
	}
	if !got["cid-cancel-from-dte"] {
		t.Error("missing cancelled-from-delivered_to_edge in cancelled_correlation_ids")
	}
	if got["cid-cancelled-but-dispatched"] {
		t.Error("included cancelled-but-delivered_to_endpoint in cancelled_correlation_ids (delivered_to_endpoint_at IS NULL guard failed)")
	}
	// Live queued command must arrive in commands, not in cancelled.
	if got["cid-live"] {
		t.Error("live queued command appeared in cancelled_correlation_ids")
	}
	live := false
	for _, c := range out.Commands {
		if c.CorrelationID == "cid-live" {
			live = true
		}
	}
	if !live {
		t.Error("live queued command not delivered in commands list")
	}
}

// TestPoll_CancelledCorrelationIDs_EdgeScoped: the cancel-signal list must
// not leak cancellations from a different Edge.
func TestPoll_CancelledCorrelationIDs_EdgeScoped(t *testing.T) {
	app := edgeFederationEnv(t)
	_ = seedEdgeForPoll(t, "edge-A", "tenant-x", time.Hour)
	tokB := seedEdgeForPoll(t, "edge-B", "tenant-x", time.Hour)
	now := time.Now().Unix()
	seedQueuedCommand(t, "cid-A-cancelled", "tenant-x", "edge-A", "host-a", now+3600)
	db.DB.Exec(`UPDATE command_queue SET state='cancelled', terminal_at=$1 WHERE correlation_id='cid-A-cancelled'`, now)

	resp := postEdgePoll(t, app, tokB, pollBody())
	defer resp.Body.Close()
	var out struct {
		CancelledCorrelationIDs []string `json:"cancelled_correlation_ids"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	for _, c := range out.CancelledCorrelationIDs {
		if c == "cid-A-cancelled" {
			t.Error("edge-B poll leaked edge-A's cancellation")
		}
	}
}

// TestEdgeEvents_CommandResultCancelled_Accepted: F4b accepts
// command.result(status=cancelled) as informational confirmation from the
// Edge. Vantage's row is already cancelled (operator initiated), so the
// handler records an audit entry without re-transitioning state.
func TestEdgeEvents_CommandResultCancelled_Accepted(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	now := time.Now().Unix()
	seedQueuedCommand(t, "cid-conf", "tenant-x", "edge-1", "host-a", now+3600)
	db.DB.Exec(`UPDATE command_queue SET state='cancelled', terminal_at=$1 WHERE correlation_id='cid-conf'`, now)

	resp := postEdgeEventsHTTP(t, app, tok, map[string]any{
		"events": []map[string]any{
			{
				"correlation_id": "cid-conf",
				"type":           "command.result",
				"occurred_at":    now,
				"payload":        map[string]string{"status": "cancelled", "message": "dropped per cancel-signal"},
			},
		},
		"audit_chain_head": map[string]any{"seq": 1, "signature": "sig"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var out struct {
		Accepted int             `json:"accepted"`
		Rejected []map[string]any `json:"rejected"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Accepted != 1 || len(out.Rejected) != 0 {
		t.Fatalf("accepted=%d rejected=%+v, want 1/[]", out.Accepted, out.Rejected)
	}
	if s := cmdState(t, "cid-conf"); s != "cancelled" {
		t.Errorf("state after cancel-confirmation event=%s, want cancelled (state should not transition)", s)
	}
	var auditN int
	db.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='command.cancellation_confirmed' AND resource_id='cid-conf'`).Scan(&auditN)
	if auditN != 1 {
		t.Errorf("command.cancellation_confirmed audit entries=%d, want 1", auditN)
	}
}

// TestPoll_CancelSignal_BoundedByRetention: cancellations older than
// cancelSignalRetentionSeconds (7 days) drop out of the cancel signal so the
// poll response doesn't grow unbounded over a long-lived Edge (codex review
// of PR #3, finding 4). A confirmed-and-old cancellation is no-op locally on
// the Edge anyway, so dropping it has no correctness impact.
func TestPoll_CancelSignal_BoundedByRetention(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	now := time.Now().Unix()
	future := now + 3600
	old := now - cancelSignalRetentionSeconds - 60 // just past the bound

	seedQueuedCommand(t, "cid-recent", "tenant-x", "edge-1", "host-a", future)
	db.DB.Exec(`UPDATE command_queue SET state='cancelled', terminal_at=$1 WHERE correlation_id='cid-recent'`, now)

	seedQueuedCommand(t, "cid-old", "tenant-x", "edge-1", "host-b", future)
	db.DB.Exec(`UPDATE command_queue SET state='cancelled', terminal_at=$1 WHERE correlation_id='cid-old'`, old)

	resp := postEdgePoll(t, app, tok, pollBody())
	defer resp.Body.Close()
	var out struct {
		CancelledCorrelationIDs []string `json:"cancelled_correlation_ids"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	got := map[string]bool{}
	for _, c := range out.CancelledCorrelationIDs {
		got[c] = true
	}
	if !got["cid-recent"] {
		t.Error("recent cancellation missing from signal")
	}
	if got["cid-old"] {
		t.Error("cancellation older than retention window included in signal (bandwidth leak)")
	}
}

// TestEdgeEvents_CommandResultCancelled_RejectsUnowned: the cancel-confirmation
// path skips MarkTerminal's edge-scoped CAS, so it must independently verify
// the command belongs to the authenticated Edge AND is in cancelled state
// before writing audit (codex review of PR #3, finding 2). Without this an Edge
// could write audit rows against another Edge's commands or against
// non-cancelled commands.
func TestEdgeEvents_CommandResultCancelled_RejectsUnowned(t *testing.T) {
	app := edgeFederationEnv(t)
	_ = seedEdgeForPoll(t, "edge-A", "tenant-x", time.Hour)
	tokB := seedEdgeForPoll(t, "edge-B", "tenant-x", time.Hour)
	now := time.Now().Unix()
	// A command owned by edge-A and cancelled.
	seedQueuedCommand(t, "cid-A", "tenant-x", "edge-A", "host-a", now+3600)
	db.DB.Exec(`UPDATE command_queue SET state='cancelled', terminal_at=$1 WHERE correlation_id='cid-A'`, now)
	// A queued (non-cancelled) command owned by edge-B.
	seedQueuedCommand(t, "cid-B-queued", "tenant-x", "edge-B", "host-b", now+3600)
	// A bogus correlation_id with no row at all.
	bogusID := "cid-does-not-exist"

	// Edge-B tries to confirm cancellation for edge-A's command, for its own
	// non-cancelled command, and for a non-existent id. All three must reject.
	resp := postEdgeEventsHTTP(t, app, tokB, map[string]any{
		"events": []map[string]any{
			{"correlation_id": "cid-A", "type": "command.result", "occurred_at": now, "payload": map[string]string{"status": "cancelled", "message": "cross-edge"}},
			{"correlation_id": "cid-B-queued", "type": "command.result", "occurred_at": now, "payload": map[string]string{"status": "cancelled", "message": "wrong-state"}},
			{"correlation_id": bogusID, "type": "command.result", "occurred_at": now, "payload": map[string]string{"status": "cancelled", "message": "no-row"}},
		},
		"audit_chain_head": map[string]any{"seq": 1, "signature": "sig"},
	})
	defer resp.Body.Close()
	var out struct {
		Accepted int                       `json:"accepted"`
		Rejected []map[string]any          `json:"rejected"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Accepted != 0 {
		t.Errorf("accepted=%d, want 0 (all three should reject)", out.Accepted)
	}
	if len(out.Rejected) != 3 {
		t.Errorf("rejected=%d, want 3 (cross-edge, wrong-state, no-row)", len(out.Rejected))
	}
	// Audit must NOT have written cancellation_confirmed for any of the three.
	var auditN int
	db.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='command.cancellation_confirmed' AND resource_id IN ('cid-A','cid-B-queued',$1)`, bogusID).Scan(&auditN)
	if auditN != 0 {
		t.Errorf("cancellation_confirmed audit entries=%d, want 0 (ownership check failed)", auditN)
	}
}

// TestEdgeEvents_CommandResultBadStatus_Rejected: any status other than
// succeeded|failed|cancelled is rejected at parse stage.
func TestEdgeEvents_CommandResultBadStatus_Rejected(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", time.Hour)
	now := time.Now().Unix()
	seedQueuedCommand(t, "cid-bad", "tenant-x", "edge-1", "host-a", now+3600)

	resp := postEdgeEventsHTTP(t, app, tok, map[string]any{
		"events": []map[string]any{
			{
				"correlation_id": "cid-bad",
				"type":           "command.result",
				"occurred_at":    now,
				"payload":        map[string]string{"status": "weirdo", "message": "x"},
			},
		},
		"audit_chain_head": map[string]any{"seq": 1, "signature": "sig"},
	})
	defer resp.Body.Close()
	var out struct {
		Accepted int                       `json:"accepted"`
		Rejected []map[string]any          `json:"rejected"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Accepted != 0 || len(out.Rejected) != 1 {
		t.Errorf("bad status: accepted=%d rejected=%d, want 0/1", out.Accepted, len(out.Rejected))
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
