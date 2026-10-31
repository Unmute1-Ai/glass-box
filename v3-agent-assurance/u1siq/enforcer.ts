/**
 * U1SiQ enforcer: the only path to an effect. Holds public keys only.
 *
 * Before running an effect it checks, in order:
 *   1. not halted by an earlier chain break
 *   2. receipt hash and signature against the keyring
 *   3. decision is ALLOW and the receipt has not expired
 *   4. receipt.envelopeHash equals the hash of the envelope being executed
 *   5. the ledger chain is intact and contains this exact receipt
 *   6. the receipt has not been consumed (replay)
 * A chain break halts the enforcer permanently until an operator rebuilds it.
 * The receipt is marked consumed before the effect runs (at-most-once): a
 * crash mid-effect needs a fresh evaluation rather than a silent retry.
 */
import { hashCanonical } from './canonical.ts';
import {
  receiptBody,
  verifyChain,
  verifyReceipt,
  type ConsumedStore,
  type Keyring,
  type ReceiptLedger,
} from './ledger.ts';
import { GENESIS_HASH, type ActionEnvelope, type SignedReceipt } from './types.ts';

export class EnforcementError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export interface EnforcerOptions {
  keyring: Keyring;
  /** Read access to the gate's ledger, or a replica of it. */
  ledger: ReceiptLedger;
  consumed: ConsumedStore;
  now?: () => number;
}

export class U1SiQEnforcer {
  #keyring: Keyring;
  #ledger: ReceiptLedger;
  #consumed: ConsumedStore;
  #now: () => number;
  /** The enforcer's own record of verified receipt hashes, index i = sequence i + 1. */
  #verified: string[] = [];
  #halted: string | null = null;
  #queue: Promise<unknown> = Promise.resolve();

  constructor(o: EnforcerOptions) {
    this.#keyring = new Map(o.keyring);
    this.#ledger = o.ledger;
    this.#consumed = o.consumed;
    this.#now = o.now ?? Date.now;
  }

  get halted(): string | null {
    return this.#halted;
  }

  /** Serialized so two concurrent calls cannot both pass the replay check. */
  execute<T>(envelope: ActionEnvelope, receipt: SignedReceipt, effect: () => T | Promise<T>): Promise<T> {
    const run = this.#queue.then(() => this.#execute(envelope, receipt, effect));
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #execute<T>(envelope: ActionEnvelope, receipt: SignedReceipt, effect: () => T | Promise<T>): Promise<T> {
    if (this.#halted) throw new EnforcementError(`halted:${this.#halted}`);

    const bad = await verifyReceipt(receipt, this.#keyring);
    if (bad) throw new EnforcementError(bad);
    if (receipt.decision !== 'ALLOW') throw new EnforcementError('receipt_not_allow');
    if (this.#now() > receipt.expiresAt) throw new EnforcementError('receipt_expired');

    let envelopeHash: string;
    try {
      envelopeHash = await hashCanonical(envelope);
    } catch {
      throw new EnforcementError('envelope_not_canonicalizable');
    }
    if (receipt.proposalId !== envelope.proposalId) throw new EnforcementError('proposal_mismatch');
    if (receipt.envelopeHash !== envelopeHash) throw new EnforcementError('envelope_hash_mismatch');

    await this.#checkChain();
    if (this.#verified[receipt.sequence - 1] !== receipt.receiptHash) throw new EnforcementError('receipt_not_in_ledger');

    if (this.#consumed.has(receipt.receiptId)) throw new EnforcementError('receipt_replayed');
    this.#consumed.add(receipt.receiptId);
    return effect();
  }

  /**
   * Full re-verification of every entry against what this enforcer verified
   * before. Per-execute checks only re-hash the newest verified entry, so run
   * this at startup and on a schedule to catch edits deeper in the ledger.
   */
  async verifyFullChain(): Promise<void> {
    if (this.#halted) throw new EnforcementError(`halted:${this.#halted}`);
    const entries = this.#ledger.entries();
    const res = await verifyChain(entries, this.#keyring);
    if (!res.ok) return this.#halt(`chain_broken_at_${res.brokenAt}:${res.reason}`);
    for (let i = 0; i < this.#verified.length; i++) {
      if (entries[i]?.receiptHash !== this.#verified[i]) return this.#halt('verified_prefix_rewritten');
    }
    this.#verified = entries.map((r) => r.receiptHash);
  }

  async #checkChain(): Promise<void> {
    const entries = this.#ledger.entries();
    const n = this.#verified.length;
    if (entries.length < n) return this.#halt('ledger_truncated');
    if (n > 0) {
      // Re-hash the newest verified entry from its body, not its stored hash field.
      const last = entries[n - 1];
      let h: string | null = null;
      try {
        h = await hashCanonical(receiptBody(last));
      } catch {
        h = null;
      }
      if (h !== this.#verified[n - 1] || last.receiptHash !== this.#verified[n - 1]) {
        return this.#halt('verified_prefix_rewritten');
      }
    }
    const prev = n > 0 ? this.#verified[n - 1] : GENESIS_HASH;
    const res = await verifyChain(entries, this.#keyring, n, prev);
    if (!res.ok) return this.#halt(`chain_broken_at_${res.brokenAt}:${res.reason}`);
    for (let i = n; i < entries.length; i++) this.#verified.push(entries[i].receiptHash);
  }

  #halt(reason: string): never {
    this.#halted = reason;
    throw new EnforcementError(`halted:${reason}`);
  }
}
