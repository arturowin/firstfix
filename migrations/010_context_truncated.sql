-- Dependency context (direct parents, install paths) was cut to bound work: paths deeper than the cap are
-- abbreviated around "…", or the graph walk stopped early. The finding itself is complete; the report says
-- the "how it got here" part is incomplete.
ALTER TABLE findings ADD COLUMN context_truncated boolean NOT NULL DEFAULT false;
