/**
 * Human consent, authenticated.
 *
 * An Approver holds a private key that is meant to live on the human's device
 * (passkey, hardware token, phone secure enclave). The gate only knows the
 * approver's public key, registered at construction. The agent cannot mint
 * consent because it never holds an approver key, and the gate exposes no
 * "issue consent" method.
 *
 * Consent binds to the envelope hash, not just the proposal id, so approving
 * one set of parameters does not approve another under the same id.
 */
import { b64url, canonicalize, fromB64url, utf8 } from './canonical.ts';
import type { ConsentClaims, ConsentToken, RiskTier } from './types.ts';

export interface RegisteredApprover {
  publicKey: CryptoKey;
  /** Highest tier this person may approve. */
  maxTier: RiskTier;
}

export class Approver {
  readonly approverId: string;
  readonly publicKey: CryptoKey;
  #privateKey: CryptoKey;
  #now: () => number;

  private constructor(approverId: string, pair: CryptoKeyPair, now: () => number) {
    this.approverId = approverId;
    this.publicKey = pair.publicKey;
    this.#privateKey = pair.privateKey;
    this.#now = now;
  }

  static async create(approverId: string, now: () => number = Date.now): Promise<Approver> {
    if (!approverId.trim()) throw new Error('approver_id_required');
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair;
    return new Approver(approverId, pair, now);
  }

  /** Called after the human has reviewed the exact envelope whose hash is passed in. */
  async approve(proposalId: string, envelopeHash: string, ttlMs: number): Promise<ConsentToken> {
    const issuedAt = this.#now();
    const claims: ConsentClaims = {
      proposalId,
      envelopeHash,
      approverId: this.approverId,
      issuedAt,
      expiresAt: issuedAt + ttlMs,
      nonce: crypto.randomUUID(),
    };
    const sig = await crypto.subtle.sign('Ed25519', this.#privateKey, utf8(canonicalize(claims)));
    return { ...claims, signature: b64url(sig) };
  }
}

export async function verifyConsentSignature(token: ConsentToken, publicKey: CryptoKey): Promise<boolean> {
  const { signature, ...claims } = token;
  try {
    return await crypto.subtle.verify('Ed25519', publicKey, fromB64url(signature), utf8(canonicalize(claims)));
  } catch {
    return false;
  }
}
