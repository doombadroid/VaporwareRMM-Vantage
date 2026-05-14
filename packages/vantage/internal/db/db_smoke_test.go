package db

import (
	"os"
	"strings"
	"testing"
)

// TestInit_RequiresDatabaseURL verifies the refuse-on-empty
// behavior. Unset DATABASE_URL and any cached state, call Init,
// expect an error mentioning the env var name + the "Postgres-only"
// constraint so operators don't have to guess what went wrong.
func TestInit_RequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	err := Init()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL is required") {
		t.Errorf("error should mention DATABASE_URL: %v", err)
	}
	if !strings.Contains(err.Error(), "Postgres-only") {
		t.Errorf("error should mention Postgres-only constraint: %v", err)
	}
}

// TestInit_RefusesSQLiteURL covers the explicit no-SQLite gate.
// Edge supports SQLite; Vantage does not, and an operator copy-
// pasting from Edge docs MUST hit a clear error rather than a
// driver-level "unknown scheme" later in the connection path.
func TestInit_RefusesSQLiteURL(t *testing.T) {
	cases := []string{
		"sqlite:///tmp/vantage.db",
		"file:vantage.db",
		"/var/lib/vantage.db",
	}
	for _, url := range cases {
		t.Run(url, func(t *testing.T) {
			t.Setenv("DATABASE_URL", url)
			err := Init()
			if err == nil {
				t.Fatalf("expected error for %q, got nil", url)
			}
			// Either path produces an explicit message naming
			// Postgres. Empty/non-prefixed paths fall into the
			// generic prefix check; the other two hit the SQLite
			// explicit refusal — both surface "Postgres" in the
			// message so operators see the right answer.
			if !strings.Contains(err.Error(), "Postgres") && !strings.Contains(err.Error(), "postgres") {
				t.Errorf("error should mention Postgres: %v", err)
			}
		})
	}
}

// TestInit_AcceptsValidPostgresURL_AndAppliesMigrations spins up
// against a real Postgres (operator-provided VANTAGE_TEST_PG_URL)
// or skips. CI provides the URL via a docker:postgres service;
// local devs run a one-shot Postgres container. Confirms the
// migration runner actually creates the F1 tables.
func TestInit_AcceptsValidPostgresURL_AndAppliesMigrations(t *testing.T) {
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL to a Postgres connection string to run this test")
	}
	t.Setenv("DATABASE_URL", url)
	t.Cleanup(func() {
		if DB != nil {
			// Drop F1 tables so a re-run starts clean. The
			// schema_migrations row tracks the version — drop
			// that too so the migration re-applies.
			_, _ = DB.Exec(`DROP TABLE IF EXISTS tailscale_connection, audit_log, user_sessions, users, edges, schema_migrations CASCADE`)
			_ = DB.Close()
			DB = nil
		}
	})
	if err := Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if DB == nil {
		t.Fatal("DB is nil after successful Init")
	}
	// Confirm tables exist.
	for _, tbl := range []string{"users", "user_sessions", "edges", "audit_log", "schema_migrations"} {
		var exists bool
		if err := DB.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, tbl).Scan(&exists); err != nil {
			t.Errorf("check table %s: %v", tbl, err)
			continue
		}
		if !exists {
			t.Errorf("expected table %s to exist after migrations", tbl)
		}
	}
	// Migration 1 should be recorded.
	var ver int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&ver); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if ver != 1 {
		t.Errorf("expected 1 row in schema_migrations for version 1, got %d", ver)
	}
}

// TestRedactURL covers the password-stripping helper that's called
// when Ping fails. Operator-facing logs must never include the DB
// password — easy to forget when adding new error paths.
func TestRedactURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"postgres://user:secret@host:5432/db", "postgres://<redacted>@host:5432/db"},
		{"postgresql://user:secret@host/db", "postgresql://<redacted>@host/db"},
		{"postgres://host:5432/db", "postgres://host:5432/db"}, // no @ → unchanged
	}
	for _, tc := range cases {
		got := redactURL(tc.in)
		if got != tc.want {
			t.Errorf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
