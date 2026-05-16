# F2 sweep — round-6 mandatory audit

Six rounds of Codex review on PR #1 surfaced the same anti-patterns
repeatedly. This document records the comprehensive sweep mandated
in round 6: every handler/helper in `packages/vantage` checked
against six checkpoints, with explicit dispositions.

## Checkpoint 1 — `*Sync` functions return errors; callers propagate

`*Sync` in the function name implies durability-before-return. The
caller must observe the row landed.

| Function | Returns error | Disposition |
|---|---|---|
| `events.AuditLogSync` | yes (FA2) | compliant |
| `events.AuditLogSyncTx` | yes (FA2) | compliant |
| `events.RecordAuditCheckpointSync` | yes (round-3 #3) | compliant |

Caller audit:

| Caller | Function | Error checked |
|---|---|---|
| `enrollment.go:152` | `AuditLogSync` | yes — 500 audit_write_failed |
| `edge_federation.go:583` | `AuditLogSyncTx` | yes — 500 audit_write_failed, rolls back tx |
| `edge_federation.go:165` | `RecordAuditCheckpointSync` | yes — 500 checkpoint_write_failed |

Fire-and-forget variants (`AuditLog`, `RecordAuditCheckpoint`) wrap
the Sync variants with `go func() { _ = ... }()` and log async
failures at slog.Error.

## Checkpoint 2 — UPDATE on previously-read row uses compare-and-set

Every UPDATE where this handler earlier read state about the row
must include that state as a WHERE predicate.

| Location | UPDATE | CAS predicate | Disposition |
|---|---|---|---|
| `enrollment.go:130` | `tailscale_auth_key_id` | `AND tailscale_auth_key_id IS NULL` (FA4 sweep) | compliant |
| `handlers.go:88` | `users.last_login_at` | n/a — idempotent timestamp, no prior read | compliant |
| `tailscale.go:339` | `tailscale_connection` rotate | `AND tailnet = $existingTailnet` (FA3) | compliant |
| `auth.go:488` | `edges.last_seen_at` | n/a — idempotent heartbeat, no prior read | compliant |
| `edge_federation.go:345` | rotation `token_hash`+expiry | `AND token_hash = $presentedHash` + FOR UPDATE row lock | compliant |
| `edge_federation.go:369` | `edges.edge_version` | inside FOR UPDATE tx, follows rotation in same lock | compliant |
| `edge_federation.go:503` | enrollment consume | `AND consumed_at IS NULL AND expires_at > $now` (round-1 #6) | compliant |
| `edge_federation.go:572` | enrollment link `consumed_by_edge_id` | n/a — operates on row this handler just consumed within same tx | compliant |

## Checkpoint 3 — Singleton INSERT uses ON CONFLICT DO NOTHING + RowsAffected

| Table | Statement location | ON CONFLICT | RowsAffected | Disposition |
|---|---|---|---|---|
| `tailscale_connection` | `tailscale.go:192` | `(id) DO NOTHING` (round-3 #4) | yes — 409 already_connected | compliant |
| `vantage_signing_key` | `signing.go:80` | `(id) DO NOTHING` (round-1 #5) | implicit via SELECT after | compliant |
| `users` (BootstrapAdmin) | `auth.go:543` | `(email) DO NOTHING` (FA4 sweep) | yes — race-loser skips banner | compliant |

Non-singleton INSERTs (PK is UUID/SERIAL, no semantic singleton
constraint): `enrollment_tokens`, `audit_checkpoints`, `edges`,
`user_sessions`, `audit_log`. UNIQUE constraints catch genuine
duplicates; no ON CONFLICT needed.

## Checkpoint 4 — Phase-ordered handlers: parse → reads → tx(writes) → response

Every handler with DB writes:

| Handler | Structure | Disposition |
|---|---|---|
| `pollEdge` | Phase 1 parse + version check, Phase 2 LatestChainHead read, Phase 3 single tx (rotation + edge_version + checkpoint INSERT), commit, Phase 4 response (FZ2) | compliant |
| `registerEdge` | parse + validate, BEGIN tx, consume + edge INSERT + audit INSIDE tx (FA2), commit, response | compliant |
| `postEdgeEvents` | parse + validate audit_chain_head, RecordAuditCheckpointSync, process events, audit-log batch (async), response | compliant |
| `mintEnrollmentToken` | DB INSERT (orphan-tolerant NULL key), external Tailscale mint, UPDATE with CAS, AuditLogSync (own tx). Tailscale network call sits between DB writes by design (round-3 #4) so orphan-on-failure is documented behavior | compliant w/ documented trade-off |
| `connectTailscale` | parse + validate, network calls, BEGIN tx (implicit via single ON CONFLICT exec), commit, audit, response | compliant |
| `rotateTailscaleConnection` | parse + read existing, network calls (validate new), CAS UPDATE, RowsAffected diagnose, audit, response | compliant |
| `disconnectTailscale` | read existing, DELETE, audit, response. Single-statement DELETE; no race exposure | compliant |
| `loginHandler` | bcrypt verify, CreateSession (own tx), best-effort last_login_at, response | compliant |
| `logoutHandler` | RevokeSession (DELETE by token_hash), audit, response | compliant |
| `listEdgesHandler` | read-only | n/a |

## Checkpoint 5 — Audit chain writes serialize via FOR UPDATE / advisory lock

`AuditLogSyncTx` calls `pg_advisory_xact_lock(auditChainLockID)` at
the start of every chain write (FA2). Lock is transaction-scoped,
held across nodes, released on COMMIT or ROLLBACK. Concurrent
writers in other transactions block until the holder commits.
Chain integrity (monotonic `chain_seq`, signatures referencing
correct predecessors) preserved.

`TestAuditLog_ChainIntegrityUnderConcurrent` verifies: 20
concurrent `AuditLogSync` calls produce `chain_seq` 1..20 with no
gaps or duplicates.

## Checkpoint 6 — Rate limiters: per-IP + per-resource + trusted proxy

| Endpoint | Per-IP | Per-resource | TrustedProxies | Disposition |
|---|---|---|---|---|
| `POST /api/edge/register` | yes, Max=30/min (FA1) | yes, per-enrollment-token-hash, Max=5/min (FA1) | wired via `TRUSTED_PROXIES` env (FA1) | compliant |
| `POST /api/edge/poll` | n/a — authed via Bearer; brute force not the threat | per-edge-token via `EdgeAuthMiddleware` | n/a | compliant |
| `POST /api/edge/events` | n/a — authed via Bearer | per-edge-token via `EdgeAuthMiddleware` | n/a | compliant |
| `POST /api/v1/auth/login` | none (F1) | none (F1) | n/a | follow-up — add limiter in F3+ when fail2ban-style abuse is in scope |
| Other `/api/v1/*` endpoints | session-cookie-gated; CSRF double-submit | n/a | n/a | n/a |

## Sweep findings (fixed in same commit set as the four specific round-6 findings)

1. **`BootstrapAdmin` users INSERT** — race-prone on multi-process boot. Fixed: `ON CONFLICT (email) DO NOTHING` + RowsAffected check + race-loser logs without printing the first-run password banner.

2. **`enrollment.go:130` UPDATE `tailscale_auth_key_id`** — no CAS predicate. Fixed: `AND tailscale_auth_key_id IS NULL`. Defense-in-depth; single-handler INSERT-then-UPDATE shouldn't race in practice.

No other violations found.

## Follow-up (out of scope for F2)

- `loginHandler` lacks a rate limiter. Fail2ban-style brute-force protection on login is in F3+ scope per #22 Q11.
- `mintEnrollmentToken` deliberately has a Tailscale network call between two DB writes. The orphan-on-mint-failure trade-off is documented in the round-3 #4 commit and SWEEP. A "two-phase" minting approach (provisional row, mint, finalize via UPDATE + audit) is plausible future hardening if orphans become operationally noisy.
