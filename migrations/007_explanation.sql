-- Explanations are per action (one per package), not per finding: stored on the scan as
-- { source, summary, actions: { "<ecosystem>:<package>": { text, source } }, fallbackReason? }.
-- explanation_source (from 001) says whether the summary came from the AI or the template.
ALTER TABLE scans ADD COLUMN explanation jsonb;
ALTER TABLE findings DROP COLUMN explanation;
