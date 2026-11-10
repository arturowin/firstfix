-- Which advisory data source a completed scan used (docs/ARCHITECTURE.md "Advisory source"). Stored per scan
-- so an old report keeps naming the source it was built from.
ALTER TABLE scans ADD COLUMN advisory_source text;

-- From here on findings.affected_ranges holds the neutral AffectedRange[] shape. Rows written earlier keep raw
-- OSV ranges; the report never reads this column back (candidates are stored per finding).
