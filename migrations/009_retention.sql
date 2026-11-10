-- Retention (docs/ARCHITECTURE.md "Known limits" → now handled): finished scans are deleted after a while
-- (findings, unchecked deps and idempotency keys go with them via ON DELETE CASCADE), and idempotency keys
-- expire on their own sooner. These indexes keep the periodic deletes from scanning whole tables.
CREATE INDEX scans_completed_at_idx ON scans (completed_at) WHERE completed_at IS NOT NULL;
CREATE INDEX idempotency_keys_created_at_idx ON idempotency_keys (created_at);
