-- F2 cross-system consistency: Edge's audit_logs table uses
-- `signature` (TEXT) for the per-row HMAC. F1 created Vantage's
-- audit_log with `chain_hash` (the same value, different name).
-- F2 renames so the verification CLI (Q9 v1.1) can read both
-- systems' chains with the same column references.
--
-- This is a pure column-rename. The chain semantics, key
-- derivation, and canonicalization are unchanged.

ALTER TABLE audit_log RENAME COLUMN chain_hash TO signature;
