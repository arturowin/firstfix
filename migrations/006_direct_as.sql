-- The names under which the project itself declares a package (root or workspace). Each is a separate
-- declaration that needs its own update: two aliases of one vulnerable version both need changing.
-- Empty for transitive-only installs; rows from before this migration fall back to is_direct (report side).
ALTER TABLE findings ADD COLUMN direct_as text[] NOT NULL DEFAULT '{}';
