-- Names a package is installed under when they differ from its real name (npm aliases, e.g. "my-lodash" for
-- npm:lodash@4.17.20). `package` stays the real name: the one advisories are published under.
ALTER TABLE findings ADD COLUMN installed_as text[] NOT NULL DEFAULT '{}';
