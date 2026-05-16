package events

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
)

func setupEventsTest(t *testing.T) {
	t.Helper()
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL to a Postgres connection string to run this test")
	}
	if err := crypto.SetKeyForTests("fmZn0pFd/f58gKeknlaECEbcMDh5oQ+nRhFB/sAMScY="); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)
	// Drop any leftover tables BEFORE Init so the migration runner
	// re-applies cleanly each test.
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
}

// TestAuditLogSync_ChainContinuity verifies two synchronous audit
// writes produce chain_seq=1 then chain_seq=2 with signature
// chaining off each other's bytes. Requires a live Postgres at
// VANTAGE_TEST_PG_URL; skips otherwise.
func TestAuditLogSync_ChainContinuity(t *testing.T) {
	setupEventsTest(t)

	if err := AuditLogSync("user-1", "test.action.first", "test", "rid-1", "detail-1", "127.0.0.1"); err != nil {
		t.Fatalf("AuditLogSync 1: %v", err)
	}
	if err := AuditLogSync("user-1", "test.action.second", "test", "rid-2", "detail-2", "127.0.0.1"); err != nil {
		t.Fatalf("AuditLogSync 2: %v", err)
	}

	rows, err := db.DB.Query(`SELECT chain_seq, signature, action FROM audit_log ORDER BY chain_seq`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	type row struct {
		seq       int64
		signature string
		action    string
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.seq, &r.signature, &r.action); err != nil {
			t.Fatalf("scan: %v", err)
		}
		all = append(all, r)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(all))
	}
	if all[0].seq != 1 || all[1].seq != 2 {
		t.Errorf("chain_seq sequence wrong: got %d, %d, want 1, 2", all[0].seq, all[1].seq)
	}
	if all[0].signature == all[1].signature {
		t.Error("two adjacent rows have identical signature — chain is not chaining")
	}
	if len(all[0].signature) < 32 || len(all[1].signature) < 32 {
		t.Errorf("signature too short to be HMAC-SHA256 hex: %q / %q", all[0].signature, all[1].signature)
	}
	if all[0].action != "test.action.first" || all[1].action != "test.action.second" {
		t.Errorf("action mismatch: %+v", all)
	}
}

// TestRecordAuditCheckpoint_PersistsCounterpartyHead verifies that
// the helper writes a row with the right counterparty_type,
// counterparty_id, chain_seq, signature, and recorded_during fields.
// The verification CLI (Q9 v1.1) reads this exact shape.
func TestRecordAuditCheckpoint_PersistsCounterpartyHead(t *testing.T) {
	setupEventsTest(t)

	if err := RecordAuditCheckpointSync("edge", "edge-acme-1", 42, "abc123signaturehex", "poll"); err != nil {
		t.Fatalf("RecordAuditCheckpointSync: %v", err)
	}

	var ctyType, ctyID, signature, during string
	var chainSeq int64
	var recordedAt int64
	if err := db.DB.QueryRow(
		`SELECT counterparty_type, counterparty_id, chain_seq, signature, recorded_at, recorded_during
		   FROM audit_checkpoints WHERE counterparty_id = 'edge-acme-1'`,
	).Scan(&ctyType, &ctyID, &chainSeq, &signature, &recordedAt, &during); err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if ctyType != "edge" || ctyID != "edge-acme-1" {
		t.Errorf("counterparty mismatch: %s/%s", ctyType, ctyID)
	}
	if chainSeq != 42 || signature != "abc123signaturehex" {
		t.Errorf("chain head mismatch: seq=%d sig=%s", chainSeq, signature)
	}
	if during != "poll" {
		t.Errorf("recorded_during should be poll, got %s", during)
	}
	if recordedAt == 0 {
		t.Error("recorded_at should be non-zero")
	}
}

// TestRecordAuditCheckpoint_RejectsBadCounterpartyType: the CHECK
// constraint at the DB layer is what protects against a stray
// "device" or "agent" sneaking in. The helper now returns the
// error (codex round-3 #3) so callers can fail loudly.
func TestRecordAuditCheckpoint_RejectsBadCounterpartyType(t *testing.T) {
	setupEventsTest(t)

	err := RecordAuditCheckpointSync("agent", "x", 1, "sig", "noop")
	if err == nil {
		t.Error("CHECK constraint rejection should surface as an error from Sync")
	}

	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM audit_checkpoints`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("CHECK constraint should reject 'agent' counterparty_type; got %d rows", count)
	}
}

// TestAuditLogSync_DBError: drop audit_log; AuditLogSync must
// return an error (rather than logging-and-eating-it like the
// pre-round-6 implementation).
func TestAuditLogSync_DBError(t *testing.T) {
	setupEventsTest(t)
	if _, err := db.DB.Exec(`DROP TABLE audit_log CASCADE`); err != nil {
		t.Fatalf("drop audit_log: %v", err)
	}
	err := AuditLogSync("u", "test.action", "test", "rid", "details", "127.0.0.1")
	if err == nil {
		t.Error("AuditLogSync should return error when table is unavailable")
	}
}

// TestAuditLog_ChainIntegrityUnderConcurrent: N goroutines call
// AuditLogSync concurrently. Resulting rows must form a strict
// sequence (chain_seq 1..N with no gaps, no duplicates) and each
// row's signature must equal HMAC(prev_signature || canonical).
// Without the pg_advisory_xact_lock serialization, concurrent
// writers race on chain head reads and produce broken chains.
func TestAuditLog_ChainIntegrityUnderConcurrent(t *testing.T) {
	setupEventsTest(t)

	const N = 20
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = AuditLogSync("u", fmt.Sprintf("test.concurrent.%d", i), "test", fmt.Sprintf("r%d", i), "d", "127.0.0.1")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	rows, err := db.DB.Query(`SELECT chain_seq FROM audit_log ORDER BY chain_seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var seqs []int64
	for rows.Next() {
		var s int64
		rows.Scan(&s)
		seqs = append(seqs, s)
	}
	if len(seqs) != N {
		t.Fatalf("expected %d audit rows, got %d", N, len(seqs))
	}
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Errorf("chain_seq gap or duplicate at position %d: got %d, expected %d", i, s, i+1)
		}
	}
}

// TestAuditLogSync_SignedTimestampMatchesPersisted: codex round-10
// finding #3. A verifier reads the audit_log row and recomputes
// the signature using created_at-as-Unix-seconds. That recomputed
// signature MUST equal the persisted signature. Previously the
// code signed time.Now().Unix() but let Postgres' DEFAULT NOW()
// set created_at — at second boundaries the two diverged and
// verification failed.
func TestAuditLogSync_SignedTimestampMatchesPersisted(t *testing.T) {
	setupEventsTest(t)

	if err := AuditLogSync("u-verify", "test.verify.action", "test", "rid-v", "detail-v", "127.0.0.1"); err != nil {
		t.Fatalf("AuditLogSync: %v", err)
	}

	var seq int64
	var sig string
	var createdAtUnix int64
	if err := db.DB.QueryRow(`
		SELECT chain_seq, signature, EXTRACT(EPOCH FROM created_at)::BIGINT
		FROM audit_log ORDER BY chain_seq DESC LIMIT 1
	`).Scan(&seq, &sig, &createdAtUnix); err != nil {
		t.Fatalf("read row: %v", err)
	}

	// Recompute signature using created_at-as-Unix to simulate a
	// future verification CLI.
	canonical := canonicalRow(seq, "u-verify", "test.verify.action", "test", "rid-v", "detail-v", "127.0.0.1", createdAtUnix)
	// Genesis predecessor: previous signature is "" because this
	// is the first row.
	recomputed := crypto.HMACSHA256("audit", ""+"|"+canonical)
	if recomputed != sig {
		t.Errorf("signature verification failed:\n  stored:     %s\n  recomputed: %s\n  created_at(unix)=%d", sig, recomputed, createdAtUnix)
	}
}
