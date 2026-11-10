-- Ecosystem seams (docs/ARCHITECTURE.md "Ecosystems"). Existing rows are npm: the default backfills them.

ALTER TABLE findings ADD COLUMN ecosystem text NOT NULL DEFAULT 'npm';
ALTER TABLE findings DROP CONSTRAINT findings_unique;
-- The same name@version can exist in two ecosystems; they are different packages.
ALTER TABLE findings ADD CONSTRAINT findings_unique UNIQUE (scan_id, ecosystem, package, installed_version, advisory_id);

ALTER TABLE unchecked_deps ADD COLUMN ecosystem text NOT NULL DEFAULT 'npm';

-- Which lockfile was scanned, e.g. 'package-lock.json'. Set once the file is found.
ALTER TABLE scans ADD COLUMN lockfile_path text;
