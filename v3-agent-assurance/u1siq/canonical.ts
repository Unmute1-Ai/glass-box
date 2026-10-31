/**
 * Canonical JSON for hashing and signing.
 *
 * Follows RFC 8785 (JCS) ordering and number formatting for the value types we
 * accept. Anything JSON cannot represent faithfully is rejected instead of being
 * silently coerced: `undefined` inside arrays, non-finite numbers, bigint,
 * functions, symbols, and non-plain objects (Date, Map, class instances).
 * Object properties whose value is `undefined` are omitted, matching JSON.
 */
export class CanonicalizationError extends Error {}

export function canonicalize(value: unknown): string {
  return encode(value, '$');
}

function encode(value: unknown, path: string): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new CanonicalizationError(`non_finite_number at ${path}`);
      return JSON.stringify(value); // ES number formatting; -0 becomes "0"
    case 'object':
      break;
    default:
      throw new CanonicalizationError(`unsupported_type_${typeof value} at ${path}`);
  }
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      if (!(i in value) || value[i] === undefined) {
        throw new CanonicalizationError(`undefined_array_element at ${path}[${i}]`);
      }
      parts.push(encode(value[i], `${path}[${i}]`));
    }
    return `[${parts.join(',')}]`;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new CanonicalizationError(`non_plain_object at ${path}`);
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${encode(obj[k], `${path}.${k}`)}`).join(',')}}`;
}

const encoder = new TextEncoder();

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Buffer.from(digest).toString('hex');
}

export async function hashCanonical(value: unknown): Promise<string> {
  return sha256Hex(canonicalize(value));
}

export function utf8(s: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(s);
}

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  return Buffer.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).toString('base64url');
}

export function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

export async function keyIdFor(publicKey: CryptoKey): Promise<string> {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  return (await sha256Hex(raw)).slice(0, 32);
}
