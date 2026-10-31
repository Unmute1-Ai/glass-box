/**
 * U1SiQ gate: evaluates an untrusted ActionEnvelope and issues a signed receipt.
 *
 * Trust model (see README):
 * - Nothing the proposer asserts is trusted. Risk tier comes from policy
 *   (max with any declared tier), epistemic status is derived from verified
 *   evidence, and consent must carry a registered approver's signature over the
 *   exact envelope hash. So calling evaluate() directly with a fabricated
 *   envelope yields the same answer as the front door: it cannot buy an ALLOW.
 * - The signing key is non-extractable and held in a private field. In the
 *   same process that stops casual access, not a hostile agent that can patch
 *   globals or read memory. Real isolation needs the gate in its own process or
 *   service. That is a deployment requirement, not something this file solves.
 */
import { b64url, canonicalize, hashCanonical, keyIdFor, sha256Hex, utf8 } from './canonical.ts';
import { verifyConsentSignature, type RegisteredApprover } from './consent.ts';
import { MemoryConsumedStore, type ConsumedStore, type ReceiptLedger } from './ledger.ts';
import {
  GENESIS_HASH,
  TIER_RANK,
  isRiskTier,
  maxTier,
  type ActionEnvelope,
  type ConsentToken,
  type EpistemicStatus,
  type GatePolicy,
  type ReceiptBody,
  type RiskTier,
  type SignedReceipt,
} from './types.ts';

const HEX64 = /^[0-9a-f]{64}$/;
const CLOCK_SKEW_MS = 5_000;

/**
 * Evidence registered by a trusted ingest path (sensor pipeline, document
 * store). The store computes the hash itself, so a caller cannot register a
 * hash without the content. Whoever can call register() is trusted; keep it
 * off the agent's tool surface.
 */
export class EvidenceStore {
  #hashes = new Set<string>();
  async register(content: string | Uint8Array): Promise<string> {
    const h = await sha256Hex(content);
    this.#hashes.add(h);
    return h;
  }
  has(hash: string): boolean {
    return this.#hashes.has(hash);
  }
}

export interface GateOptions {
  policy: GatePolicy;
  ledger: ReceiptLedger;
  evidence: EvidenceStore;
  approvers: ReadonlyMap<string, RegisteredApprover>;
  /** Consent nonces already used. Persist it, or consent can be replayed after restart. */
  consentNonces?: ConsumedStore;
  /** Supply a KMS/HSM-backed pair in production. Default: fresh non-extractable Ed25519. */
  signingKeyPair?: CryptoKeyPair;
  now?: () => number;
}

export class U1SiQGate {
  readonly policy: GatePolicy;
  readonly keyId: string;
  readonly publicKey: CryptoKey;
  #privateKey: CryptoKey;
  #ledger: ReceiptLedger;
  #evidence: EvidenceStore;
  #approvers: ReadonlyMap<string, RegisteredApprover>;
  #consentNonces: ConsumedStore;
  #now: () => number;
  #headHash: string;
  #queue: Promise<unknown> = Promise.resolve();

  private constructor(o: Required<Omit<GateOptions, 'signingKeyPair'>>, pair: CryptoKeyPair, keyId: string) {
    this.policy = deepFreeze(structuredClone(o.policy));
    this.keyId = keyId;
    this.publicKey = pair.publicKey;
    this.#privateKey = pair.privateKey;
    this.#ledger = o.ledger;
    this.#evidence = o.evidence;
    this.#approvers = new Map(o.approvers);
    this.#consentNonces = o.consentNonces;
    this.#now = o.now;
    const rows = o.ledger.entries();
    this.#headHash = rows.length ? rows[rows.length - 1].receiptHash : GENESIS_HASH;
  }

  static async create(o: GateOptions): Promise<U1SiQGate> {
    validatePolicy(o.policy);
    const pair =
      o.signingKeyPair ??
      ((await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair);
    const keyId = await keyIdFor(pair.publicKey);
    return new U1SiQGate(
      {
        policy: o.policy,
        ledger: o.ledger,
        evidence: o.evidence,
        approvers: o.approvers,
        consentNonces: o.consentNonces ?? new MemoryConsumedStore(),
        now: o.now ?? Date.now,
      },
      pair,
      keyId,
    );
  }

  /** Evaluations are serialized so the receipt chain has one well-defined order. */
  evaluate(envelope: ActionEnvelope, consent?: ConsentToken): Promise<SignedReceipt> {
    const run = this.#queue.then(() => this.#evaluate(envelope, consent));
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #evaluate(envelope: ActionEnvelope, consent?: ConsentToken): Promise<SignedReceipt> {
    const now = this.#now();
    const reasons: string[] = [];

    // Gate 1: shape and policy membership.
    let envelopeHash = 'unhashable';
    try {
      envelopeHash = await hashCanonical(envelope);
    } catch {
      reasons.push('envelope_not_canonicalizable');
    }
    reasons.push(...shapeErrors(envelope));
    const actionPolicy = typeof envelope?.action === 'string' ? this.policy.actions[envelope.action] : undefined;
    if (!actionPolicy || !Object.hasOwn(this.policy.actions, envelope.action)) {
      reasons.push('action_not_in_policy');
    } else if (actionPolicy.allowedResources && !actionPolicy.allowedResources.includes(envelope.targetResource)) {
      reasons.push('resource_not_allowed_for_action');
    }

    // Gate 2: risk tier. Policy sets the floor; declaring lower changes nothing.
    let tier: RiskTier = actionPolicy && Object.hasOwn(this.policy.actions, envelope.action) ? actionPolicy.tier : 'TIER_3_IRREVERSIBLE';
    if (envelope?.declaredRiskTier !== undefined) {
      if (isRiskTier(envelope.declaredRiskTier)) tier = maxTier(tier, envelope.declaredRiskTier);
      else reasons.push('declared_risk_tier_invalid');
    }
    const atLeast = (t: RiskTier) => TIER_RANK[tier] >= TIER_RANK[t];

    // Gate 3: evidence must be registered, not merely present.
    const hashes = Array.isArray(envelope?.evidenceHashes) ? envelope.evidenceHashes : [];
    const unverified = hashes.filter((h) => typeof h !== 'string' || !this.#evidence.has(h));
    for (const h of unverified) reasons.push(`evidence_unverified:${String(h).slice(0, 12)}`);
    const verifiedCount = hashes.length - unverified.length;
    if (atLeast(this.policy.evidenceRequiredFrom) && verifiedCount === 0) reasons.push('evidence_required');
    const epistemicStatus: EpistemicStatus =
      verifiedCount > 0 && unverified.length === 0 ? 'VERIFIED_FACT' : 'UNVERIFIED';

    // Gate 4: acoustic context. Missing, malformed, degraded, or stale signal denies.
    if (atLeast(this.policy.acousticRequiredFrom)) reasons.push(...this.#acousticErrors(envelope, now));

    // Gate 5: authenticated human consent bound to this exact envelope.
    let consentApproverId: string | undefined;
    let consentNonce: string | undefined;
    if (atLeast(this.policy.consentRequiredFrom)) {
      const err = await this.#consentError(consent, envelope, envelopeHash, tier, now);
      if (err) reasons.push(err);
      else {
        consentApproverId = consent!.approverId;
        consentNonce = consent!.nonce;
      }
    }

    const decision = reasons.length === 0 ? 'ALLOW' : 'DENY';
    // Burn the consent only when it is actually used, so an unrelated denial
    // (for example stale telemetry) does not force the human to re-approve.
    if (decision === 'ALLOW' && consentNonce) this.#consentNonces.add(consentNonce);

    const body: ReceiptBody = {
      receiptId: crypto.randomUUID(),
      sequence: this.#ledger.length() + 1,
      previousReceiptHash: this.#headHash,
      proposalId: typeof envelope?.proposalId === 'string' ? envelope.proposalId : '',
      envelopeHash,
      decision,
      reasons,
      effectiveRiskTier: tier,
      epistemicStatus,
      policyVersion: this.policy.version,
      keyId: this.keyId,
      issuedAt: now,
      expiresAt: now + this.policy.receiptTtlMs,
      ...(consentApproverId ? { consentApproverId } : {}),
    };
    const receiptHash = await hashCanonical(body);
    const signature = b64url(await crypto.subtle.sign('Ed25519', this.#privateKey, utf8(receiptHash)));
    const receipt: SignedReceipt = { ...body, receiptHash, signature };
    this.#ledger.append(receipt);
    this.#headHash = receiptHash;
    return receipt;
  }

  #acousticErrors(e: ActionEnvelope, now: number): string[] {
    const a = e?.acousticContext;
    const p = this.policy.acoustic;
    if (a === undefined || a === null) return ['acoustic_telemetry_missing'];
    const nums = [a.vocalTensionScore, a.signalQuality, a.capturedAt];
    if (!nums.every((n) => typeof n === 'number' && Number.isFinite(n))) return ['acoustic_telemetry_malformed'];
    if (a.vocalTensionScore < 0 || a.vocalTensionScore > 1 || a.signalQuality < 0 || a.signalQuality > 1) {
      return ['acoustic_telemetry_out_of_range'];
    }
    const out: string[] = [];
    if (a.signalQuality < p.minSignalQuality) out.push('acoustic_signal_degraded');
    if (now - a.capturedAt > p.maxAgeMs || a.capturedAt - now > CLOCK_SKEW_MS) out.push('acoustic_telemetry_stale');
    if (a.vocalTensionScore > p.maxTension) out.push('acoustic_tension_exceeds_threshold');
    return out;
  }

  async #consentError(
    c: ConsentToken | undefined,
    e: ActionEnvelope,
    envelopeHash: string,
    tier: RiskTier,
    now: number,
  ): Promise<string | null> {
    if (!c) return 'human_consent_required';
    const approver = typeof c.approverId === 'string' ? this.#approvers.get(c.approverId) : undefined;
    if (!approver) return 'consent_approver_unknown';
    if (typeof c.signature !== 'string' || !(await verifyConsentSignature(c, approver.publicKey))) {
      return 'consent_signature_invalid';
    }
    if (c.proposalId !== e.proposalId) return 'consent_proposal_mismatch';
    if (c.envelopeHash !== envelopeHash) return 'consent_envelope_mismatch';
    if (!(now >= c.issuedAt - CLOCK_SKEW_MS && now <= c.expiresAt)) return 'consent_expired';
    if (TIER_RANK[approver.maxTier] < TIER_RANK[tier]) return 'consent_approver_tier_insufficient';
    if (this.#consentNonces.has(c.nonce)) return 'consent_replayed';
    return null;
  }
}

function shapeErrors(e: ActionEnvelope): string[] {
  if (!e || typeof e !== 'object') return ['envelope_not_object'];
  const out: string[] = [];
  for (const k of ['proposalId', 'agentId', 'action', 'targetResource'] as const) {
    if (typeof e[k] !== 'string' || !e[k].trim()) out.push(`${k}_required`);
  }
  if (!e.parameters || typeof e.parameters !== 'object' || Array.isArray(e.parameters)) out.push('parameters_invalid');
  if (!Array.isArray(e.evidenceHashes) || !e.evidenceHashes.every((h) => typeof h === 'string' && HEX64.test(h))) {
    out.push('evidence_hashes_invalid');
  }
  if (typeof e.createdAt !== 'number' || !Number.isFinite(e.createdAt)) out.push('created_at_invalid');
  return out;
}

function validatePolicy(p: GatePolicy): void {
  if (!p?.version?.trim()) throw new Error('policy_version_required');
  for (const [name, a] of Object.entries(p.actions ?? {})) {
    if (!isRiskTier(a.tier)) throw new Error(`policy_action_tier_invalid:${name}`);
  }
  for (const t of [p.evidenceRequiredFrom, p.acousticRequiredFrom, p.consentRequiredFrom]) {
    if (!isRiskTier(t)) throw new Error('policy_threshold_tier_invalid');
  }
  const { maxTension, minSignalQuality, maxAgeMs } = p.acoustic ?? ({} as GatePolicy['acoustic']);
  if (![maxTension, minSignalQuality, maxAgeMs, p.receiptTtlMs].every((n) => Number.isFinite(n) && n >= 0)) {
    throw new Error('policy_numeric_invalid');
  }
  canonicalize(p); // policy must be hashable for audit
}

function deepFreeze<T>(v: T): T {
  if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) deepFreeze((v as Record<string, unknown>)[k]);
    Object.freeze(v);
  }
  return v;
}
