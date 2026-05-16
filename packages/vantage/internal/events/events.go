// Package events handles state-change side effects: audit logging
// with tamper-evident hash chain (F1), real-time WebSocket fan-out
// (stub in F1, real in F2-F8).
//
// The audit chain mirrors Edge's pattern from PR #5 / Codex #6:
//
//   - Each row carries chain_seq (monotonic, gap-free per chain) and
//     signature (HMAC-SHA256(SECRETS_ENCRYPTION_KEY, previous_signature
//     || canonical(row))). Edge's audit_logs table uses the same
//     column name so the cross-system verification CLI (Q9 v1.1) can
//     read both chains without dialect translation.
//   - HMAC key derived from SECRETS_ENCRYPTION_KEY with a domain
//     tag (crypto.HMACSHA256 handles this) so an attacker who
//     recovers a signature can't reuse it as ciphertext or vice
//     versa.
//   - Chain writes serialize via a transaction-scoped Postgres
//     advisory lock (pg_advisory_xact_lock with auditChainLockID).
//     A within-process mutex is insufficient under #22 Q10 multi-
//     node — the advisory lock spans every connection to the DB.
//
// `*Sync` contract (codex round-6 audit):
//   - AuditLogSync       — durability before return. Returns error.
//   - AuditLogSyncTx     — same, but participates in caller's tx.
//   - AuditLog           — fire-and-forget. Discards error.
//   - RecordAuditCheckpointSync — durability before return. Returns error.
//   - RecordAuditCheckpoint     — fire-and-forget. Discards error.
package events

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
)

// auditChainLockID is the pg_advisory_xact_lock key used to
// serialize audit-chain writes. Any int8 works; this constant
// distinguishes it from other advisory locks the codebase might
// add later.
const auditChainLockID int64 = 0xA0D17

// AuditLog records an admin action asynchronously. Errors are
// logged at slog.Error level. Use AuditLogSync (or
// AuditLogSyncTx) for code paths that must observe the row landed
// before returning.
func AuditLog(userID, action, resourceType, resourceID, details, ip string) {
	go func() {
		if err := AuditLogSync(userID, action, resourceType, resourceID, details, ip); err != nil {
			slog.Error("audit: async write failed", "error", err, "action", action)
		}
	}()
}

// AuditLogSync writes an audit row in its own transaction and
// returns the error to the caller. Codex round-6 #2/#3: callers
// that must enforce "audit landed before response" need the error
// to propagate up.
func AuditLogSync(userID, action, resourceType, resourceID, details, ip string) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := AuditLogSyncTx(tx, userID, action, resourceType, resourceID, details, ip); err != nil {
		return err
	}
	return tx.Commit()
}

// AuditLogSyncTx writes an audit row inside the caller's
// transaction. Use when an audit write must be atomic with other
// state changes (e.g., enrollment_tokens INSERT + audit row land
// together so a failure rolls back both).
//
// The chain head is read with the transaction-scoped advisory lock
// held, so concurrent writers in other transactions block until
// this one commits. Chain integrity (monotonic seq + correct
// predecessor signature) is preserved across processes per #22 Q10.
func AuditLogSyncTx(tx *sql.Tx, userID, action, resourceType, resourceID, details, ip string) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, auditChainLockID); err != nil {
		return fmt.Errorf("audit: acquire chain lock: %w", err)
	}

	prevSeq, prevSignature, err := loadChainHeadTx(tx)
	if err != nil {
		return fmt.Errorf("audit: read chain head: %w", err)
	}

	// Codex round-10 finding #3: capture the timestamp ONCE and
	// use it for both the canonicalization (signed) and the row
	// persistence. The previous code used time.Now().Unix() for
	// the signature and let Postgres' DEFAULT NOW() set
	// created_at — those two timestamps differ at second
	// boundaries, breaking verification (a verifier reading the
	// row gets created_at and recomputes against the signed ts).
	//
	// to_timestamp(BIGINT) converts Unix seconds → TIMESTAMPTZ
	// deterministically; verification reads it back via
	// EXTRACT(EPOCH FROM created_at)::BIGINT.
	seq := prevSeq + 1
	nowUnix := time.Now().Unix()
	canonical := canonicalRow(seq, userID, action, resourceType, resourceID, details, ip, nowUnix)
	signature := crypto.HMACSHA256("audit", prevSignature+"|"+canonical)

	if _, err := tx.Exec(
		`INSERT INTO audit_log (chain_seq, signature, user_id, action, resource_type, resource_id, details, ip, created_at)
		     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, to_timestamp($9))`,
		seq, signature, nullable(userID), action, resourceType, nullable(resourceID), nullable(details), nullable(ip), nowUnix,
	); err != nil {
		return fmt.Errorf("audit: write row: %w", err)
	}
	return nil
}

// LatestChainHead returns Vantage's current chain head without
// taking a lock. Read-only; safe for handlers that need to surface
// the head to a counterparty.
func LatestChainHead() (int64, string, error) { return loadChainHead() }

func loadChainHead() (int64, string, error) {
	var seq sql.NullInt64
	var signature sql.NullString
	err := db.DB.QueryRow(`SELECT chain_seq, signature FROM audit_log ORDER BY chain_seq DESC LIMIT 1`).
		Scan(&seq, &signature)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	return seq.Int64, signature.String, nil
}

func loadChainHeadTx(tx *sql.Tx) (int64, string, error) {
	var seq sql.NullInt64
	var signature sql.NullString
	err := tx.QueryRow(`SELECT chain_seq, signature FROM audit_log ORDER BY chain_seq DESC LIMIT 1`).
		Scan(&seq, &signature)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	return seq.Int64, signature.String, nil
}

// canonicalRow renders the audit row as a deterministic byte
// sequence for hashing. Fields joined with a separator that cannot
// appear in any single field (pipe + newline). Stable across
// processes / architectures.
func canonicalRow(seq int64, userID, action, resourceType, resourceID, details, ip string, ts int64) string {
	return fmt.Sprintf(
		"seq=%d\n|user=%s\n|action=%s\n|rtype=%s\n|rid=%s\n|details=%s\n|ip=%s\n|ts=%d",
		seq, userID, action, resourceType, resourceID, details, ip, ts,
	)
}

func nullable(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// RecordAuditCheckpoint persists a counterparty's audit-chain
// head for cross-attestation. Fire-and-forget — checkpoint failures
// are logged but the caller doesn't observe them. Use the Sync
// variant from handlers that must guarantee the checkpoint landed
// before responding.
func RecordAuditCheckpoint(counterpartyType, counterpartyID string, chainSeq int64, signature, duringEvent string) {
	go func() {
		_ = RecordAuditCheckpointSync(counterpartyType, counterpartyID, chainSeq, signature, duringEvent)
	}()
}

// RecordAuditCheckpointSync writes a checkpoint row synchronously
// and returns the error to the caller. Codex round-3 finding #3:
// previously this function only logged failures, which meant
// "Sync" callers (poll/events) couldn't enforce durability-
// before-response.
//
// Callers should fail the request when this returns non-nil so the
// Edge knows the checkpoint didn't land and can retry. Otherwise
// the cross-attestation contract from #22 Q9 silently degrades.
func RecordAuditCheckpointSync(counterpartyType, counterpartyID string, chainSeq int64, signature, duringEvent string) error {
	if _, err := db.DB.Exec(
		`INSERT INTO audit_checkpoints
		     (counterparty_type, counterparty_id, chain_seq, signature, recorded_at, recorded_during)
		     VALUES ($1, $2, $3, $4, $5, $6)`,
		counterpartyType, nullable(counterpartyID), chainSeq, signature, time.Now().Unix(), nullable(duringEvent),
	); err != nil {
		slog.Error("audit_checkpoint: write failed",
			"error", err,
			"counterparty_type", counterpartyType,
			"counterparty_id", counterpartyID,
			"chain_seq", chainSeq,
			"during", duringEvent,
		)
		return fmt.Errorf("checkpoint write: %w", err)
	}
	return nil
}

// WSBroadcastMessage is the placeholder for the F2 real-time fan-out.
// F1 logs the payload at info level so the call sites are exercised
// (and the contract is visible in commit-history grep) without
// shipping a websocket hub. F2 replaces the body with the actual
// hub + connection multiplex.
func WSBroadcastMessage(payload map[string]interface{}) {
	slog.Info("ws: broadcast (F1 stub — no listeners yet)", "type", payload["type"], "size", len(payload))
}
