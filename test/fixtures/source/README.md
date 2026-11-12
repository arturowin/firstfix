Source-check fixtures (M7). `flagged.ts` must produce exactly three findings (one `FF-TLS-001`, two `FF-TLS-002`);
`safe.ts` must produce none. These files are only read as text by tests; they are never executed or imported.
