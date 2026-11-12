Source-check fixtures (M7). `flagged.ts.txt` must produce exactly three findings (one `FF-TLS-001`, two
`FF-TLS-002`); `safe.ts.txt` must produce none. Tests read them as text and give them to the scanner under a `.ts`
path; they are never executed or imported.

They are stored as `.txt` on purpose: the insecure patterns are test data, so they are not compiled or linted, and
a scan of this repository doesn't report them as findings in its own code.
