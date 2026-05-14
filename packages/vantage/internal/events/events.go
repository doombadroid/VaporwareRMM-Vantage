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
//   - Within-process serialization via auditChainMu so concurrent
//     callers see a well-defined chain. Postgres handles
//     cross-instance serialization via row-level locking in F2 when
//     multi-node Vantage becomes a real scenario.
//   - HMAC key derived from SECRETS_ENCRYPTION_KEY with a domain
//     tag (crypto.HMACSHA256 handles this) so an attacker who
//     recovers a signature can't reuse it as ciphertext or vice
//     versa.
//
// AuditLog is fire-and-forget: handler latency does not block on
// the chain mutex or the INSERT. Operators who need synchronous
// audit (post-action ack-on-audit) call AuditLogSync directly.
package events

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
)

var auditChainMu sync.Mutex

// AuditLog records an admin action asynchronously. Errors are
// logged at slog.Error level — silent audit-write failures are
// exactly the gap the audit log exists to prevent, so they get
// loud visibility.
func AuditLog(userID, action, resourceType, resourceID, details, ip string) {
	go AuditLogSync(userID, action, resourceType, resourceID, details, ip)
}

// AuditLogSync is the synchronous variant. Used directly by code
// paths that must observe the row landed before returning to the
// caller (e.g., the future F2 federation pairing handler that
// audits a new Edge registration; the operator UI confirms the
// pairing only after the audit row is durable).
func AuditLogSync(userID, action, resourceType, resourceID, details, ip string) {
	auditChainMu.Lock()
	defer auditChainMu.Unlock()

	prevSeq, prevSignature, err := loadChainHead()
	if err != nil {
		slog.Warn("audit: failed to load chain head; row will write but chain may be discontinuous", "error", err)
	}
	seq := prevSeq + 1
	canonical := canonicalRow(seq, userID, action, resourceType, resourceID, details, ip, time.Now().Unix())
	signature := crypto.HMACSHA256("audit", prevSignature+"|"+canonical)

	if _, err := db.DB.Exec(
		`INSERT INTO audit_log (chain_seq, signature, user_id, action, resource_type, resource_id, details, ip)
		   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		seq, signature, nullable(userID), action, resourceType, nullable(resourceID), nullable(details), nullable(ip),
	); err != nil {
		slog.Error("audit: write failed",
			"error", err,
			"action", action,
			"user", userID,
			"resource_type", resourceType,
		)
	}
}

// loadChainHead returns the highest (chain_seq, signature) pair
// currently in the table, or (0, "") if the table is empty (the
// genesis-row case). The HMAC over prev_signature="" + canonical(row=1)
// is the genesis signature for the chain.
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

// WSBroadcastMessage is the placeholder for the F2 real-time fan-out.
// F1 logs the payload at info level so the call sites are exercised
// (and the contract is visible in commit-history grep) without
// shipping a websocket hub. F2 replaces the body with the actual
// hub + connection multiplex.
func WSBroadcastMessage(payload map[string]interface{}) {
	slog.Info("ws: broadcast (F1 stub — no listeners yet)", "type", payload["type"], "size", len(payload))
}
