-- Lockfile entries whose package name (or alias) isn't a valid npm name: not checked and never put into commands
-- (they come from a repository-controlled file and could carry shell syntax). Listed so the user can review them.
ALTER TABLE unchecked_deps DROP CONSTRAINT unchecked_deps_reason_check;
ALTER TABLE unchecked_deps ADD CONSTRAINT unchecked_deps_reason_check
  CHECK (reason IN ('unsupported_source', 'lookup_failed', 'invalid_name'));
