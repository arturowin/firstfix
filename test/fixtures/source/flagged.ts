// Fixture: code the source checks must flag. Never run.
import https from 'node:https';

// FF-TLS-001: process-wide
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

export const agent = new https.Agent({
  keepAlive: true,
  rejectUnauthorized: false, // FF-TLS-002: property form
});

export function legacy(options: { rejectUnauthorized?: boolean }) {
  options.rejectUnauthorized = false; // FF-TLS-002: member assignment
  return options;
}
