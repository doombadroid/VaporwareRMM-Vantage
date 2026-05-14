package events

import (
	"os"
	"testing"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
)

// TestAuditLogSync_ChainContinuity verifies two synchronous audit
// writes produce chain_seq=1 then chain_seq=2 with chain_hash
// chaining off each other's bytes. Requires a live Postgres at
// VANTAGE_TEST_PG_URL; skips otherwise.
func TestAuditLogSync_ChainContinuity(t *testing.T) {
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL to a Postgres connection string to run this test")
	}
	if err := crypto.SetKeyForTests("fmZn0pFd/f58gKeknlaECEbcMDh5oQ+nRhFB/sAMScY="); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)
	t.Cleanup(func() {
		if db.DB != nil {
			_, _ = db.DB.Exec(`DROP TABLE IF EXISTS audit_log, user_sessions, users, edges, schema_migrations CASCADE`)
			_ = db.DB.Close()
			db.DB = nil
		}
	})
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}

	AuditLogSync("user-1", "test.action.first", "test", "rid-1", "detail-1", "127.0.0.1")
	AuditLogSync("user-1", "test.action.second", "test", "rid-2", "detail-2", "127.0.0.1")

	rows, err := db.DB.Query(`SELECT chain_seq, chain_hash, action FROM audit_log ORDER BY chain_seq`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	type row struct {
		seq    int64
		hash   string
		action string
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.seq, &r.hash, &r.action); err != nil {
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
	if all[0].hash == all[1].hash {
		t.Error("two adjacent rows have identical chain_hash — chain is not chaining")
	}
	if len(all[0].hash) < 32 || len(all[1].hash) < 32 {
		t.Errorf("chain_hash too short to be HMAC-SHA256 hex: %q / %q", all[0].hash, all[1].hash)
	}
	if all[0].action != "test.action.first" || all[1].action != "test.action.second" {
		t.Errorf("action mismatch: %+v", all)
	}
}
