-- Private repositories (docs/ARCHITECTURE.md "Private repositories"). A private scan is bound to the GitHub
-- repository id and installation id recorded at submit; its visibility never changes afterwards.
ALTER TABLE scans
  ADD COLUMN visibility text NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'private')),
  ADD COLUMN github_repo_id bigint,
  ADD COLUMN installation_id bigint,
  ADD COLUMN submitted_by bigint,
  ADD CONSTRAINT scans_private_ids CHECK (
    visibility = 'public' OR (github_repo_id IS NOT NULL AND installation_id IS NOT NULL)
  );

-- Visibility is fixed at submit, also for retries and completion.
CREATE FUNCTION scans_visibility_fixed() RETURNS trigger AS $$
BEGIN
  IF NEW.visibility IS DISTINCT FROM OLD.visibility
     OR NEW.github_repo_id IS DISTINCT FROM OLD.github_repo_id
     OR NEW.installation_id IS DISTINCT FROM OLD.installation_id THEN
    RAISE EXCEPTION 'scan % visibility and repository binding cannot change', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER scans_visibility_fixed BEFORE UPDATE ON scans
  FOR EACH ROW EXECUTE FUNCTION scans_visibility_fixed();

-- Sign-in sessions. The cookie holds a random token; only its SHA-256 is stored. The user's GitHub token is
-- AES-256-GCM encrypted by the application (key from SESSION_SECRET).
CREATE TABLE sessions (
  key_hash bytea PRIMARY KEY,
  github_user_id bigint NOT NULL,
  github_login text NOT NULL,
  token_encrypted bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- OAuth sign-in attempts: one-time, short-lived, bound to the browser that started them (hash of a nonce kept
-- in a cookie). The PKCE verifier is encrypted like the session token.
CREATE TABLE oauth_states (
  state_hash bytea PRIMARY KEY,
  binding_hash bytea NOT NULL,
  verifier_encrypted bytea NOT NULL,
  return_to text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX oauth_states_expires_at_idx ON oauth_states (expires_at);
