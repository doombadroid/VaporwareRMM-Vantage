package commands

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"

	_ "github.com/lib/pq"
)

const testEncryptionKey = "fmZn0pFd/f58gKeknlaECEbcMDh5oQ+nRhFB/sAMScY="

const dropAll = `DROP TABLE IF EXISTS command_queue, tags, tag_endpoint_membership, audit_checkpoints, enrollment_tokens, vantage_signing_key, tailscale_connection, audit_log, user_sessions, users, edges, schema_migrations CASCADE`

// setupCommandsTest brings up a clean schema against the operator-provided
// Postgres and seeds the FK targets (one user, one edge) the command_queue
// rows reference.
func setupCommandsTest(t *testing.T) {
	t.Helper()
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL to a Postgres connection string")
	}
	if err := crypto.SetKeyForTests(testEncryptionKey); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)

	conn, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := conn.Exec(dropAll); err != nil {
		t.Fatalf("drop: %v", err)
	}
	_ = conn.Close()

	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	t.Cleanup(func() {
		if db.DB != nil {
			_, _ = db.DB.Exec(dropAll)
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	now := time.Now().Unix()
	if _, err := db.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('op1', 'op@test.local', 'x', 'super_admin')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO edges (id, name, tenant_id, status, created_at) VALUES ('edge1', 'Edge', 'tenant1', 'active', $1)`, now); err != nil {
		t.Fatalf("seed edge: %v", err)
	}
}

// enqueueOne inserts a fresh queued command and returns its correlation_id.
func enqueueOne(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	cid, err := EnqueueCommand(ctx, tx, EnqueueRequest{
		TenantID:         "tenant1",
		EdgeID:           "edge1",
		TargetEndpointID: "host-abc",
		CommandType:      "restart_service",
		CommandParams:    json.RawMessage(`{"service_name":"nginx"}`),
		OperatorUserID:   "op1",
	})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("enqueue: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return cid
}

// forceState raw-sets a command's state for fixture construction (bypasses
// the lifecycle deliberately — we are constructing the "from" state under
// test, not exercising the path to it).
func forceState(t *testing.T, cid, state string) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE command_queue SET state = $2 WHERE correlation_id = $1`, cid, state); err != nil {
		t.Fatalf("force state %s: %v", state, err)
	}
}

func currentState(t *testing.T, cid string) string {
	t.Helper()
	var st string
	if err := db.DB.QueryRow(`SELECT state FROM command_queue WHERE correlation_id = $1`, cid).Scan(&st); err != nil {
		t.Fatalf("read state: %v", err)
	}
	return st
}

// allStates is the full state set. Adding a state here (and to the migration
// CHECK) forces every transition case below to be re-evaluated against it.
var allStates = []string{
	StateQueued, StateDeliveredToEdge, StateDeliveredToEndpoint, StateExecuting,
	StateSucceeded, StateFailed, StateExpired, StateCancelled,
}

// TestCommandLifecycle_AllTransitions is the forcing function for the state
// machine: every transition is exercised from EVERY state. A transition from
// a legal predecessor must succeed (and actually move the row); from any other
// state it must return the documented sentinel without mutating the row.
// Adding a state to allStates or a transition to the cases list forces new
// (transition × state) coverage here.
func TestCommandLifecycle_AllTransitions(t *testing.T) {
	setupCommandsTest(t)
	ctx := context.Background()

	cases := []struct {
		name      string
		toState   string          // expected state after a successful transition
		legalFrom map[string]bool // states the transition is legal from
		missErr   error           // sentinel expected when applied illegally
		apply     func(tx *sql.Tx, cid string) error
	}{
		{
			name: "MarkDeliveredToEdge", toState: StateDeliveredToEdge,
			legalFrom: map[string]bool{StateQueued: true}, missErr: ErrInvalidTransition,
			apply: func(tx *sql.Tx, cid string) error { return MarkDeliveredToEdge(ctx, tx, cid, "edge1") },
		},
		{
			name: "MarkDeliveredToEndpoint", toState: StateDeliveredToEndpoint,
			legalFrom: map[string]bool{StateDeliveredToEdge: true}, missErr: ErrInvalidTransition,
			apply: func(tx *sql.Tx, cid string) error { return MarkDeliveredToEndpoint(ctx, tx, cid, "edge1") },
		},
		{
			name: "MarkExecuting", toState: StateExecuting,
			legalFrom: map[string]bool{StateDeliveredToEndpoint: true}, missErr: ErrInvalidTransition,
			apply: func(tx *sql.Tx, cid string) error { return MarkExecuting(ctx, tx, cid, "edge1") },
		},
		{
			name: "MarkTerminal_succeeded", toState: StateSucceeded,
			legalFrom: map[string]bool{StateDeliveredToEndpoint: true, StateExecuting: true}, missErr: ErrInvalidTransition,
			apply: func(tx *sql.Tx, cid string) error { return MarkTerminal(ctx, tx, cid, "edge1", StateSucceeded, "ok") },
		},
		{
			name: "MarkTerminal_failed", toState: StateFailed,
			legalFrom: map[string]bool{StateDeliveredToEndpoint: true, StateExecuting: true}, missErr: ErrInvalidTransition,
			apply: func(tx *sql.Tx, cid string) error { return MarkTerminal(ctx, tx, cid, "edge1", StateFailed, "boom") },
		},
		{
			name: "MarkCancelled", toState: StateCancelled,
			legalFrom: map[string]bool{StateQueued: true, StateDeliveredToEdge: true}, missErr: ErrNotCancellable,
			apply: func(tx *sql.Tx, cid string) error { return MarkCancelled(ctx, tx, cid, "op1") },
		},
	}

	for _, tc := range cases {
		for _, from := range allStates {
			t.Run(tc.name+"/from_"+from, func(t *testing.T) {
				cid := enqueueOne(t)
				forceState(t, cid, from)

				tx, err := db.DB.BeginTx(ctx, nil)
				if err != nil {
					t.Fatalf("begin: %v", err)
				}
				applyErr := tc.apply(tx, cid)
				if err := tx.Commit(); err != nil {
					t.Fatalf("commit: %v", err)
				}

				if tc.legalFrom[from] {
					if applyErr != nil {
						t.Fatalf("legal transition from %s returned error: %v", from, applyErr)
					}
					if got := currentState(t, cid); got != tc.toState {
						t.Errorf("after %s from %s: state=%s, want %s", tc.name, from, got, tc.toState)
					}
				} else {
					if !errors.Is(applyErr, tc.missErr) {
						t.Fatalf("illegal transition from %s: err=%v, want %v", from, applyErr, tc.missErr)
					}
					if got := currentState(t, cid); got != from {
						t.Errorf("illegal transition mutated row: from %s -> %s", from, got)
					}
				}
			})
		}
	}
}

// TestRunExpirySweeper_StopsOnContextCancel: the sweeper goroutine returns
// promptly when its context is cancelled (server-shutdown path). No DB needed
// — the ticker won't fire before the cancelled context is observed.
func TestRunExpirySweeper_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunExpirySweeper(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunExpirySweeper did not return after context cancel")
	}
}

// TestMarkDeliveredToEdge_NotFound: a correlation_id with no row yields
// ErrNotFound (the ack endpoint tolerates this; here we assert the sentinel).
func TestMarkDeliveredToEdge_NotFound(t *testing.T) {
	setupCommandsTest(t)
	ctx := context.Background()
	tx, _ := db.DB.BeginTx(ctx, nil)
	defer tx.Rollback()
	if err := MarkDeliveredToEdge(ctx, tx, "no-such-correlation", "edge1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestMarkTerminal_RejectsBadStatus: only succeeded|failed are terminal
// results from execution.
func TestMarkTerminal_RejectsBadStatus(t *testing.T) {
	setupCommandsTest(t)
	ctx := context.Background()
	cid := enqueueOne(t)
	forceState(t, cid, StateExecuting)
	tx, _ := db.DB.BeginTx(ctx, nil)
	defer tx.Rollback()
	if err := MarkTerminal(ctx, tx, cid, "edge1", "expired", "nope"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("want ErrInvalidTransition for bad status, got %v", err)
	}
}

// TestExpireStaleQueued sweeps only queued commands past their TTL and leaves
// delivered/terminal commands untouched.
func TestExpireStaleQueued(t *testing.T) {
	setupCommandsTest(t)
	ctx := context.Background()

	stale := enqueueOne(t) // will be aged past TTL
	fresh := enqueueOne(t) // within TTL, stays queued
	delivered := enqueueOne(t)
	forceState(t, delivered, StateDeliveredToEdge) // not queued: must not expire

	past := time.Now().Unix() - 10
	if _, err := db.DB.Exec(`UPDATE command_queue SET expires_at = $1 WHERE correlation_id = $2`, past, stale); err != nil {
		t.Fatalf("age stale: %v", err)
	}

	n, err := ExpireStaleQueued(ctx)
	if err != nil {
		t.Fatalf("ExpireStaleQueued: %v", err)
	}
	if n != 1 {
		t.Errorf("expired count = %d, want 1", n)
	}
	if got := currentState(t, stale); got != StateExpired {
		t.Errorf("stale command state = %s, want expired", got)
	}
	if got := currentState(t, fresh); got != StateQueued {
		t.Errorf("fresh command state = %s, want queued (within TTL)", got)
	}
	if got := currentState(t, delivered); got != StateDeliveredToEdge {
		t.Errorf("delivered command state = %s, want delivered_to_edge (not queued)", got)
	}

	// Expiry result fields + audit entry.
	var rs, rm string
	if err := db.DB.QueryRow(`SELECT result_status, result_message FROM command_queue WHERE correlation_id = $1`, stale).Scan(&rs, &rm); err != nil {
		t.Fatalf("read expired result: %v", err)
	}
	if rs != StateExpired || rm != ExpireReason {
		t.Errorf("expired result = (%s,%s), want (expired,%s)", rs, rm, ExpireReason)
	}
	var auditN int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'command.expired' AND resource_id = $1`, stale).Scan(&auditN); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditN != 1 {
		t.Errorf("command.expired audit entries = %d, want 1", auditN)
	}
}
