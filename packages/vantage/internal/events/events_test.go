package events

import (
	"database/sql"
	"os"
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

	AuditLogSync("user-1", "test.action.first", "test", "rid-1", "detail-1", "127.0.0.1")
	AuditLogSync("user-1", "test.action.second", "test", "rid-2", "detail-2", "127.0.0.1")

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

	RecordAuditCheckpointSync("edge", "edge-acme-1", 42, "abc123signaturehex", "poll")

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
// "device" or "agent" sneaking in. The helper passes the value
// straight through; the DB enforces.
func TestRecordAuditCheckpoint_RejectsBadCounterpartyType(t *testing.T) {
	setupEventsTest(t)

	// Synchronous variant returns void (writes are fire-and-forget
	// even in the Sync variant; only slog.Error indicates failure).
	// To assert the CHECK constraint engaged, we read back and
	// confirm no row was written.
	RecordAuditCheckpointSync("agent", "x", 1, "sig", "noop")

	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM audit_checkpoints`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("CHECK constraint should reject 'agent' counterparty_type; got %d rows", count)
	}
}
