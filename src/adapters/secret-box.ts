import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';

const VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * AES-256-GCM for secrets at rest (user tokens, PKCE verifiers). The key is derived from SESSION_SECRET with
 * HKDF, so the secret itself is never used as a key. Layout: version (1) | iv (12) | tag (16) | ciphertext.
 */
export class SecretBox {
  private readonly key: Buffer;

  constructor(secret: string) {
    if (secret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters (e.g. openssl rand -hex 32)');
    this.key = Buffer.from(hkdfSync('sha256', secret, 'firstfix', 'firstfix secrets at rest v1', 32));
  }

  seal(plaintext: string): Buffer {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return Buffer.concat([Buffer.from([VERSION]), iv, cipher.getAuthTag(), body]);
  }

  /** Throws when the data was tampered with or sealed with another key. */
  open(sealed: Buffer): string {
    if (sealed.length < 1 + IV_BYTES + TAG_BYTES || sealed[0] !== VERSION) throw new Error('unrecognised sealed value');
    const iv = sealed.subarray(1, 1 + IV_BYTES);
    const tag = sealed.subarray(1 + IV_BYTES, 1 + IV_BYTES + TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(sealed.subarray(1 + IV_BYTES + TAG_BYTES)), decipher.final()]).toString('utf8');
  }
}

/** A random URL-safe token (256 bits). */
export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

export function sha256(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}
