package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"vaporrmm/vantage/internal/db"
)

func cmdResult(t *testing.T, correlationID string) (state, resultStatus, resultMessage string) {
	t.Helper()
	if err := db.DB.QueryRow(
		`SELECT state, COALESCE(result_status,''), COALESCE(result_message,'') FROM command_queue WHERE correlation_id = $1`,
		correlationID,
	).Scan(&state, &resultStatus, &resultMessage); err != nil {
		t.Fatalf("read command: %v", err)
	}
	return
}

func eventsBody(edgeSeq int64, evs ...map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"events":           evs,
		"audit_chain_head": map[string]interface{}{"seq": edgeSeq, "signature": "edge-sig"},
	}
}

// TestEventsCommandLifecycle drives a command through its full Edge-reported
// lifecycle via /api/edge/events: ack -> delivered_to_endpoint -> executing
// -> succeeded, asserting state at each hop.
func TestEventsCommandLifecycle(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", 25*24*time.Hour)
	seedQueuedCommand(t, "cid-1", "tenant-x", "edge-1", "host-a", time.Now().Unix()+3600)

	// queued -> delivered_to_edge (ack)
	callCommandsAck(t, app, tok, []string{"cid-1"}).Body.Close()
	if s, _, _ := cmdResult(t, "cid-1"); s != "delivered_to_edge" {
		t.Fatalf("after ack: %s", s)
	}

	// delivered_to_edge -> delivered_to_endpoint
	r1 := postEdgeEventsHTTP(t, app, tok, eventsBody(1, map[string]interface{}{
		"correlation_id": "cid-1", "type": "command.delivered_to_endpoint", "occurred_at": time.Now().Unix(), "payload": map[string]string{},
	}))
	var o1 struct {
		Accepted int `json:"accepted"`
	}
	json.NewDecoder(r1.Body).Decode(&o1)
	r1.Body.Close()
	if o1.Accepted != 1 {
		t.Errorf("delivered_to_endpoint accepted=%d, want 1", o1.Accepted)
	}
	if s, _, _ := cmdResult(t, "cid-1"); s != "delivered_to_endpoint" {
		t.Fatalf("after delivered_to_endpoint event: %s", s)
	}

	// delivered_to_endpoint -> executing
	r2 := postEdgeEventsHTTP(t, app, tok, eventsBody(2, map[string]interface{}{
		"correlation_id": "cid-1", "type": "command.executing", "occurred_at": time.Now().Unix(), "payload": map[string]string{},
	}))
	r2.Body.Close()
	if s, _, _ := cmdResult(t, "cid-1"); s != "executing" {
		t.Fatalf("after executing event: %s", s)
	}

	// executing -> succeeded (with result message)
	r3 := postEdgeEventsHTTP(t, app, tok, eventsBody(3, map[string]interface{}{
		"correlation_id": "cid-1", "type": "command.result", "occurred_at": time.Now().Unix(),
		"payload": map[string]string{"status": "succeeded", "message": "service restarted"},
	}))
	r3.Body.Close()
	s, rs, rm := cmdResult(t, "cid-1")
	if s != "succeeded" || rs != "succeeded" || rm != "service restarted" {
		t.Errorf("terminal = (state=%s, result_status=%s, result_message=%q), want succeeded/succeeded/'service restarted'", s, rs, rm)
	}
}

// TestEventsCommandResult_OutOfOrderFromDeliveredToEdge: a command.result that
// arrives before the delivered_to_endpoint/executing progress events (out of
// order / lost progress) must still terminate the command — the result is
// authoritative (round 1 #1), not dropped as a benign no-op.
func TestEventsCommandResult_OutOfOrderFromDeliveredToEdge(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", 25*24*time.Hour)
	seedQueuedCommand(t, "cid-ooo", "tenant-x", "edge-1", "host-a", time.Now().Unix()+3600)
	db.DB.Exec(`UPDATE command_queue SET state='delivered_to_edge' WHERE correlation_id='cid-ooo'`)

	r := postEdgeEventsHTTP(t, app, tok, eventsBody(1, map[string]interface{}{
		"correlation_id": "cid-ooo", "type": "command.result", "occurred_at": time.Now().Unix(),
		"payload": map[string]string{"status": "succeeded", "message": "fast path"},
	}))
	r.Body.Close()
	if s, rs, _ := cmdResult(t, "cid-ooo"); s != "succeeded" || rs != "succeeded" {
		t.Errorf("out-of-order result from delivered_to_edge: (state=%s, result=%s), want succeeded (authoritative)", s, rs)
	}
}

// TestEventsCommandResult_Failed exercises the failed terminal path.
func TestEventsCommandResult_Failed(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", 25*24*time.Hour)
	seedQueuedCommand(t, "cid-f", "tenant-x", "edge-1", "host-a", time.Now().Unix()+3600)
	// Force into delivered_to_endpoint so the result transition is legal.
	db.DB.Exec(`UPDATE command_queue SET state='delivered_to_endpoint' WHERE correlation_id='cid-f'`)

	r := postEdgeEventsHTTP(t, app, tok, eventsBody(1, map[string]interface{}{
		"correlation_id": "cid-f", "type": "command.result", "occurred_at": time.Now().Unix(),
		"payload": map[string]string{"status": "failed", "message": "unit not found"},
	}))
	r.Body.Close()
	s, rs, rm := cmdResult(t, "cid-f")
	if s != "failed" || rs != "failed" || rm != "unit not found" {
		t.Errorf("failed terminal = (%s,%s,%q)", s, rs, rm)
	}
}

// TestEventsCommandResult_BadPayloadRejected: a command.result without a
// valid status is rejected (not accepted) and does not transition the row.
func TestEventsCommandResult_BadPayloadRejected(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", 25*24*time.Hour)
	seedQueuedCommand(t, "cid-bad", "tenant-x", "edge-1", "host-a", time.Now().Unix()+3600)
	db.DB.Exec(`UPDATE command_queue SET state='executing' WHERE correlation_id='cid-bad'`)

	r := postEdgeEventsHTTP(t, app, tok, eventsBody(1, map[string]interface{}{
		"correlation_id": "cid-bad", "type": "command.result", "occurred_at": time.Now().Unix(),
		"payload": map[string]string{"status": "weird"},
	}))
	defer r.Body.Close()
	var out struct {
		Accepted int `json:"accepted"`
		Rejected []struct {
			CorrelationID string `json:"correlation_id"`
		} `json:"rejected"`
	}
	json.NewDecoder(r.Body).Decode(&out)
	if out.Accepted != 0 || len(out.Rejected) != 1 {
		t.Errorf("bad result: accepted=%d rejected=%d, want 0/1", out.Accepted, len(out.Rejected))
	}
	if s, _, _ := cmdResult(t, "cid-bad"); s != "executing" {
		t.Errorf("bad result mutated row to %s, want executing unchanged", s)
	}
	if r.StatusCode != http.StatusOK {
		t.Errorf("status=%d, want 200 (per-event reject, not batch failure)", r.StatusCode)
	}
}

// TestEventsCommand_DuplicateIsIdempotent: replaying a delivered_to_endpoint
// event after the command already advanced is accepted as a benign no-op.
func TestEventsCommand_DuplicateIsIdempotent(t *testing.T) {
	app := edgeFederationEnv(t)
	tok := seedEdgeForPoll(t, "edge-1", "tenant-x", 25*24*time.Hour)
	seedQueuedCommand(t, "cid-dup", "tenant-x", "edge-1", "host-a", time.Now().Unix()+3600)
	db.DB.Exec(`UPDATE command_queue SET state='executing' WHERE correlation_id='cid-dup'`)

	// A late/duplicate delivered_to_endpoint (command is already executing).
	r := postEdgeEventsHTTP(t, app, tok, eventsBody(1, map[string]interface{}{
		"correlation_id": "cid-dup", "type": "command.delivered_to_endpoint", "occurred_at": time.Now().Unix(), "payload": map[string]string{},
	}))
	defer r.Body.Close()
	var out struct {
		Accepted int `json:"accepted"`
	}
	json.NewDecoder(r.Body).Decode(&out)
	if out.Accepted != 1 {
		t.Errorf("duplicate event accepted=%d, want 1 (benign no-op accepted)", out.Accepted)
	}
	if s, _, _ := cmdResult(t, "cid-dup"); s != "executing" {
		t.Errorf("duplicate event changed state to %s, want executing unchanged", s)
	}
}
