-- Initial schema. See docs/ARCHITECTURE.md "Data model" and "Lifecycle".
-- pg-boss manages its own schema; it is not part of these migrations.

CREATE TABLE scans (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id              uuid NOT NULL,          -- pg-boss job id, written in the submission transaction
  repo_owner          text NOT NULL,
  repo_name           text NOT NULL,
  repo_url_normalized text NOT NULL,
  commit_sha          text,

  status   text NOT NULL DEFAULT 'queued'
           CHECK (status IN ('queued', 'running', 'retrying', 'completed', 'unsupported', 'failed')),
  stage    text CHECK (stage IN ('fetching', 'scanning', 'analyzing')),
  attempt  integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),

  total_deps       integer NOT NULL DEFAULT 0 CHECK (total_deps >= 0),
  checked_deps     integer NOT NULL DEFAULT 0 CHECK (checked_deps >= 0),
  unsupported_deps integer NOT NULL DEFAULT 0 CHECK (unsupported_deps >= 0),
  failed_lookups   integer NOT NULL DEFAULT 0 CHECK (failed_lookups >= 0),

  coverage           text CHECK (coverage IN ('full', 'partial')),
  explanation_source text CHECK (explanation_source IN ('ai', 'template')),
  summary_line       text,
  error_code         text,
  error_message      text,

  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,

  -- Stage only describes a running attempt.
  CONSTRAINT stage_only_while_running CHECK (stage IS NULL OR status = 'running'),
  -- A completed scan always says how much was checked.
  CONSTRAINT completed_has_coverage CHECK (status <> 'completed' OR coverage IS NOT NULL),
  -- Terminal states carry a completion time; non-terminal ones don't.
  CONSTRAINT terminal_has_completed_at CHECK (
    (status IN ('completed', 'unsupported', 'failed')) = (completed_at IS NOT NULL)
  )
);

-- Status bookkeeping lives in the database so that no status change can be refused over a side field.
-- In particular the dead-letter handler and sweeper only set status = 'failed'; if that UPDATE could fail
-- on stage/completed_at, the scan would stay stuck in 'running', which they exist to prevent.
--   * updated_at: set on every update (the sweeper selects on it)
--   * stage: cleared whenever the scan is not running
--   * completed_at: stamped when the scan enters a terminal state
--   * terminal states are final: leaving one is an error (a rescan is a new scan)
CREATE FUNCTION scans_before_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status IN ('completed', 'unsupported', 'failed') AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'scan % is %, a terminal state; it cannot become %', OLD.id, OLD.status, NEW.status
      USING ERRCODE = 'check_violation';
  END IF;

  NEW.updated_at := now();

  IF NEW.status <> 'running' THEN
    NEW.stage := NULL;
  END IF;

  IF NEW.status IN ('completed', 'unsupported', 'failed') THEN
    NEW.completed_at := COALESCE(NEW.completed_at, now());
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER scans_before_update
  BEFORE UPDATE ON scans
  FOR EACH ROW EXECUTE FUNCTION scans_before_update();

CREATE UNIQUE INDEX scans_job_id_key ON scans (job_id);
-- Sweeper: non-terminal scans not updated recently.
CREATE INDEX scans_in_progress_idx ON scans (updated_at)
  WHERE status IN ('queued', 'running', 'retrying');

CREATE TABLE findings (
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id           uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
  package           text NOT NULL,
  installed_version text NOT NULL,
  scope             text NOT NULL CHECK (scope IN ('runtime', 'optional', 'dev')),  -- most exposed path
  is_direct         boolean NOT NULL,                                              -- any install path direct
  direct_parents    text[] NOT NULL DEFAULT '{}',                                  -- empty if direct only
  install_paths     jsonb NOT NULL DEFAULT '[]',                                   -- capped list of paths
  advisory_id       text NOT NULL,
  aliases           text[] NOT NULL DEFAULT '{}',
  severity          text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
  is_malicious      boolean NOT NULL DEFAULT false,
  title             text,
  affected_ranges   jsonb NOT NULL DEFAULT '[]',
  candidate_version text,                                                          -- never "fixed", only candidate
  "references"      jsonb NOT NULL DEFAULT '[]',
  explanation       text,

  -- One finding per package@version x advisory (install paths are aggregated onto it).
  CONSTRAINT findings_unique UNIQUE (scan_id, package, installed_version, advisory_id)
);

CREATE TABLE unchecked_deps (
  scan_id uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
  package text NOT NULL,
  version text,
  reason  text NOT NULL CHECK (reason IN ('unsupported_source', 'lookup_failed'))
);

CREATE INDEX unchecked_deps_scan_id_idx ON unchecked_deps (scan_id);

CREATE TABLE idempotency_keys (
  key          text PRIMARY KEY,
  request_hash text NOT NULL,
  scan_id      uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
  created_at   timestamptz NOT NULL DEFAULT now()
);
