/**
 * Append-only receipt ledger, consumed-receipt store, and chain verification.
 *
 * File-backed variants write one JSON object per line and fsync on append so a
 * restart keeps the chain and the replay set. They are single-writer reference
 * stores; multi-process or multi-region use needs a transactional shared store.
 */
import { appendFileSync, closeSync, existsSync, fsyncSync, openSync, readFileSync } from 'node:fs';
import { canonicalize, fromB64url, hashCanonical, utf8 } from './canonical.ts';
import { GENESIS_HASH, type ReceiptBody, type SignedReceipt } from './types.ts';

export interface ReceiptLedger {
  append(receipt: SignedReceipt): void;
  /** Returns a copy. Index i holds sequence i + 1. */
  entries(): SignedReceipt[];
  length(): number;
}

export class MemoryLedger implements ReceiptLedger {
  #rows: SignedReceipt[] = [];
  append(receipt: SignedReceipt): void {
    this.#rows.push(structuredClone(receipt));
  }
  entries(): SignedReceipt[] {
    return this.#rows.map((r) => structuredClone(r));
  }
  length(): number {
    return this.#rows.length;
  }
  /** Test hook to simulate tampering by whoever controls storage. */
  unsafeRows(): SignedReceipt[] {
    return this.#rows;
  }
}

function appendLine(path: string, line: string): void {
  const fd = openSync(path, 'a');
  try {
    appendFileSync(fd, line + '\n');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function readLines(path: string): string[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').split('\n').filter((l) => l.trim() !== '');
}

export class JsonlLedger implements ReceiptLedger {
  readonly path: string;
  #rows: SignedReceipt[];
  constructor(path: string) {
    this.path = path;
    this.#rows = readLines(path).map((l) => JSON.parse(l) as SignedReceipt);
  }
  append(receipt: SignedReceipt): void {
    appendLine(this.path, JSON.stringify(receipt));
    this.#rows.push(structuredClone(receipt));
  }
  entries(): SignedReceipt[] {
    return this.#rows.map((r) => structuredClone(r));
  }
  length(): number {
    return this.#rows.length;
  }
}

export interface ConsumedStore {
  has(id: string): boolean;
  add(id: string): void;
}

export class MemoryConsumedStore implements ConsumedStore {
  #ids = new Set<string>();
  has(id: string): boolean {
    return this.#ids.has(id);
  }
  add(id: string): void {
    this.#ids.add(id);
  }
}

export class JsonlConsumedStore implements ConsumedStore {
  readonly path: string;
  #ids: Set<string>;
  constructor(path: string) {
    this.path = path;
    this.#ids = new Set(readLines(path).map((l) => JSON.parse(l) as string));
  }
  has(id: string): boolean {
    return this.#ids.has(id);
  }
  add(id: string): void {
    if (this.#ids.has(id)) return;
    appendLine(this.path, JSON.stringify(id));
    this.#ids.add(id);
  }
}

/** keyId -> public key. Keep retired keys here so old receipts stay verifiable. */
export type Keyring = ReadonlyMap<string, CryptoKey>;

export function receiptBody(r: SignedReceipt): ReceiptBody {
  const { receiptHash: _h, signature: _s, ...body } = r;
  return body;
}

/** Checks one receipt's own hash and signature. Does not check chain position. */
export async function verifyReceipt(r: SignedReceipt, keyring: Keyring): Promise<string | null> {
  let expected: string;
  try {
    expected = await hashCanonical(receiptBody(r));
  } catch {
    return 'receipt_not_canonicalizable';
  }
  if (expected !== r.receiptHash) return 'receipt_hash_mismatch';
  const key = keyring.get(r.keyId);
  if (!key) return 'unknown_signing_key';
  try {
    const ok = await crypto.subtle.verify('Ed25519', key, fromB64url(r.signature), utf8(r.receiptHash));
    return ok ? null : 'bad_signature';
  } catch {
    return 'bad_signature';
  }
}

export interface ChainResult {
  ok: boolean;
  /** 1-based sequence of the first bad entry. */
  brokenAt?: number;
  reason?: string;
  headHash: string;
}

/**
 * Verifies entries[from..] link to `prevHash` and to each other, with
 * contiguous sequence numbers and valid signatures.
 */
export async function verifyChain(
  entries: SignedReceipt[],
  keyring: Keyring,
  from = 0,
  prevHash = GENESIS_HASH,
): Promise<ChainResult> {
  let prev = prevHash;
  for (let i = from; i < entries.length; i++) {
    const r = entries[i];
    const seq = i + 1;
    if (r.sequence !== seq) return { ok: false, brokenAt: seq, reason: 'sequence_gap_or_reorder', headHash: prev };
    if (r.previousReceiptHash !== prev) return { ok: false, brokenAt: seq, reason: 'previous_hash_mismatch', headHash: prev };
    const bad = await verifyReceipt(r, keyring);
    if (bad) return { ok: false, brokenAt: seq, reason: bad, headHash: prev };
    prev = r.receiptHash;
  }
  return { ok: true, headHash: prev };
}

export function exportLedgerJsonl(entries: SignedReceipt[]): string {
  return entries.map((r) => canonicalize(r) + '\n').join('');
}
