# Production deployment guide

**Status: deferred to Phase F8 (production-readiness pass).**

Until F8 lands, treat Vantage as alpha-of-alpha. Do not point it at real
fleets, do not store production data in it, do not expose it on the
public internet without a network-layer barrier (Tailscale or VPN).

## What F8 will document

- Backup + restore procedures for the Postgres data
- TLS hardening checklist (HSTS, OCSP stapling, cert rotation cadence)
- Disaster recovery drills
- Monitoring / alerting recipes
- Capacity planning (Edges per Vantage, request rates, storage growth)
- Upgrade path between minor / major versions
- Audit log retention + archival policy

## Until F8

- Run on a host you control with restricted SSH access.
- Use Tailscale for operator access to the Vantage HTTPS endpoint
  rather than exposing port 443 publicly.
- Back up the Postgres volume manually (`pg_dump` to encrypted off-host
  storage) before any update.
- Watch the audit_log table — every state change writes there. The
  chain_hash makes tampering detectable but the table can grow; no
  retention policy yet.

## Related issues

- doombadroid/VaporwareRMM-Edge#17 — Auto-update design (Vantage needs
  its own design pass for the master side).
- doombadroid/VaporwareRMM-Edge#21 — Federation design lock referenced
  by F1's implementation.
