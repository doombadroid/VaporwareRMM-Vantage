// Package db is Vantage's Postgres-only data access layer.
//
// Edge supports both SQLite and Postgres via a placeholder-rewriting
// wrapper around database/sql. Vantage is Postgres-only by design
// (federation needs the concurrency story, multi-node-capable
// architecture, and bigint/jsonb types that SQLite can't provide
// uniformly). The simplification: no placeholder rewriting,
// $1/$2/... directly. Same migration runner pattern but reading
// from an embed.FS of .sql files instead of inline string literals.
//
// Required env vars:
//   - DATABASE_URL — postgres:// or postgresql:// connection string.
//                    Absent or non-postgres → refuse to boot.
package db

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// DB is the package-level database handle. Set by Init() at startup.
var DB *sql.DB

//go:embed migrations/*.sql
var migrationFS embed.FS

// Init opens the Postgres connection and runs migrations. Refuses to
// proceed if DATABASE_URL is missing or pointed at any non-postgres
// engine. The refusal happens BEFORE any other startup work so a
// misconfigured deployment fails on the loudest possible error.
func Init() error {
	url := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if url == "" {
		return errors.New(
			"DATABASE_URL is required for Vantage. Vantage is Postgres-only — no SQLite support. " +
				"Example: DATABASE_URL=postgres://vantage:password@localhost:5432/vantage?sslmode=disable",
		)
	}
	if !strings.HasPrefix(url, "postgres://") && !strings.HasPrefix(url, "postgresql://") {
		return errors.New(
			"Vantage requires Postgres; SQLite is not supported. " +
				"Set DATABASE_URL to a postgres:// connection string.",
		)
	}

	conn, err := sql.Open("postgres", url)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)
	if err := conn.Ping(); err != nil {
		return fmt.Errorf("ping postgres: %w (DATABASE_URL=%s)", err, redactURL(url))
	}
	DB = conn
	slog.Info("db: connected to postgres")

	if err := runMigrations(); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	return nil
}

// redactURL strips the password from a postgres:// URL so the
// connection string can land in log messages on failure without
// leaking the credential.
func redactURL(s string) string {
	at := strings.LastIndex(s, "@")
	if at == -1 {
		return s
	}
	scheme := strings.Index(s, "://")
	if scheme == -1 {
		return s
	}
	return s[:scheme+3] + "<redacted>" + s[at:]
}

// runMigrations executes pending migration files in numerical order.
// Each successful application is recorded in schema_migrations so
// re-runs are no-ops.
func runMigrations() error {
	// Ensure the tracking table exists. This is the only DDL that
	// runs unconditionally — every subsequent migration is gated
	// on its absence from schema_migrations.
	if _, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	type mig struct {
		version int
		name    string
		sql     string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// File names: NNN_description.sql. Strip prefix and
		// description to get the version int.
		base := strings.TrimSuffix(e.Name(), ".sql")
		parts := strings.SplitN(base, "_", 2)
		if len(parts) < 1 {
			return fmt.Errorf("migration filename %q does not match NNN_*.sql", e.Name())
		}
		ver, err := parseInt(parts[0])
		if err != nil {
			return fmt.Errorf("migration filename %q version not numeric: %w", e.Name(), err)
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		migs = append(migs, mig{version: ver, name: e.Name(), sql: string(body)})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	applied := 0
	for _, m := range migs {
		var exists int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = $1`, m.version).Scan(&exists); err != nil {
			return fmt.Errorf("check migration %d: %w", m.version, err)
		}
		if exists > 0 {
			continue
		}
		if _, err := DB.Exec(m.sql); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		if _, err := DB.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			return fmt.Errorf("record migration %d applied: %w", m.version, err)
		}
		slog.Info("migration applied", "version", m.version, "name", m.name)
		applied++
	}
	slog.Info("migrations complete", "applied", applied, "total_known", len(migs))
	return nil
}

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q in %q", c, s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
