-- Why a finding has or lacks a candidate version (src/domain/candidate.ts): 'candidate', 'no_fix'
-- ("no fixed version published") or 'unknown' (no version scheme, or ranges don't place the version).
ALTER TABLE findings ADD COLUMN fix_status text NOT NULL DEFAULT 'unknown'
  CHECK (fix_status IN ('candidate', 'no_fix', 'unknown'));
ALTER TABLE findings ADD CONSTRAINT candidate_matches_status
  CHECK ((fix_status = 'candidate') = (candidate_version IS NOT NULL));
