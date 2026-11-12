-- Source checks (docs/ARCHITECTURE.md "Source checks"): two targeted JavaScript/TypeScript checks run by the same
-- job after the dependency check. Each check keeps its own outcome, so a missing lockfile no longer has to be the
-- scan's status. Older scans keep NULL in every new column ("source checks were not run").

ALTER TABLE scans DROP CONSTRAINT scans_stage_check;
ALTER TABLE scans ADD CONSTRAINT scans_stage_check CHECK (stage IN ('fetching', 'scanning', 'analyzing', 'source'));

ALTER TABLE scans
  ADD COLUMN dependency_status text CHECK (dependency_status IN ('complete', 'unsupported', 'failed')),
  ADD COLUMN dependency_error_code text,
  ADD COLUMN dependency_error_message text,
  ADD COLUMN source_status text CHECK (source_status IN ('complete', 'partial', 'no_files', 'failed')),
  ADD COLUMN source_counts jsonb,
  ADD COLUMN source_error_code text,
  ADD COLUMN source_error_message text;

-- A completed scan still says how much of its dependencies was checked, unless the dependency check itself
-- couldn't run (no lockfile, or it failed) and the scan completed on its source check.
ALTER TABLE scans DROP CONSTRAINT completed_has_coverage;
ALTER TABLE scans ADD CONSTRAINT completed_has_coverage CHECK (
  status <> 'completed' OR coverage IS NOT NULL OR dependency_status IN ('unsupported', 'failed')
);

-- Source findings stay apart from dependency findings: never counted as packages or upgrades.
-- The excerpt is the matched code rebuilt from its tokens (no comments, no other string literals), bounded.
CREATE TABLE source_findings (
  id           bigserial PRIMARY KEY,
  scan_id      uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
  rule_id      text NOT NULL,
  rule_version integer NOT NULL CHECK (rule_version >= 1),
  path         text NOT NULL,
  start_line   integer NOT NULL CHECK (start_line >= 1),
  start_col    integer NOT NULL CHECK (start_col >= 1),
  end_line     integer NOT NULL CHECK (end_line >= start_line),
  end_col      integer NOT NULL CHECK (end_col >= 1),
  excerpt      text NOT NULL CHECK (char_length(excerpt) <= 200),
  severity     text NOT NULL CHECK (severity IN ('high', 'medium'))
);
CREATE INDEX source_findings_scan_id_idx ON source_findings (scan_id);
