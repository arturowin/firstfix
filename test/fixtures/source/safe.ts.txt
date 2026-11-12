// Fixture: code that mentions the same names but must NOT be flagged. Never run.
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'  (in a comment)
/* rejectUnauthorized: false (in a block comment) */
const docs = "Never set process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' in production.";
const example = `{ rejectUnauthorized: false }`;
const pattern = /rejectUnauthorized:\s*false/;

export const strict = { rejectUnauthorized: true };
export const fromConfig = (insecure: boolean) => ({ rejectUnauthorized: !insecure });
export const isOff = (o: { rejectUnauthorized?: boolean }) => o.rejectUnauthorized === false;
if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') console.warn(docs, example, pattern);
