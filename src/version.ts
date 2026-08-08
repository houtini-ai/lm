import { readFileSync } from 'node:fs';

/**
 * The single source of truth for the server version.
 *
 * Read from package.json at runtime rather than hardcoded, so the MCP handshake
 * can never drift from the published version.
 */
export const SERVER_VERSION: string = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;
