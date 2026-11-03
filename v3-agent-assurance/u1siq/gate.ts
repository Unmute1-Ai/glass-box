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
  DURESS_MODALITIES,
  TIER_RANK,
  isRiskTier,
  maxTier,
  type ActionEnvelope,
  type ConsentToken,
  type DuressModality,
  type DuressSignal,
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
  /** Compiled parameter rules per action. */
  #paramRules = new Map<string, Map<string, { re: RegExp; maxLength: number }>>();
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
    for (const [name, a] of Object.entries(this.policy.actions)) {
      if (!a.parameters) continue;
      const m = new Map<string, { re: RegExp; maxLength: number }>();
      for (const [k, r] of Object.entries(a.parameters)) m.set(k, { re: new RegExp(`^(?:${r.pattern})$`, 'u'), maxLength: r.maxLength ?? 256 });
      this.#paramRules.set(name, m);
    }
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
    } else {
      if (actionPolicy.allowedResources && !actionPolicy.allowedResources.includes(envelope.targetResource)) {
        reasons.push('resource_not_allowed_for_action');
      }
      const rules = this.#paramRules.get(envelope.action);
      if (rules) reasons.push(...parameterErrors(envelope.parameters, rules));
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

    // Gate 4: duress signal from any modality. Malformed input or a tense
    // reading denies. No usable signal steps up to a strong-presence approval
    // (or denies, per policy) instead of being read as calm.
    let duressPath: ReceiptBody['duressPath'];
    let needStrongPresence = false;
    if (atLeast(this.policy.duressRequiredFrom)) {
      const d = this.#duressCheck(envelope, now);
      reasons.push(...d.errors);
      if (d.usable) duressPath = 'signal';
      else if (this.policy.duress.onNoUsableSignal === 'deny') reasons.push('duress_signal_unavailable');
      else {
        needStrongPresence = true;
        duressPath = 'strong_presence';
      }
    }

    // Gate 5: authenticated human consent bound to this exact envelope.
    let consentApproverId: string | undefined;
    let consentNonce: string | undefined;
    if (atLeast(this.policy.consentRequiredFrom) || needStrongPresence) {
      const err = await this.#consentError(consent, envelope, envelopeHash, tier, now);
      if (err) reasons.push(err);
      else if (needStrongPresence && consent!.presence !== 'strong') {
        reasons.push('duress_signal_unavailable_strong_presence_required');
      } else {
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
      ...(duressPath ? { duressPath } : {}),
    };
    const receiptHash = await hashCanonical(body);
    const signature = b64url(await crypto.subtle.sign('Ed25519', this.#privateKey, utf8(receiptHash)));
    const receipt: SignedReceipt = { ...body, receiptHash, signature };
    this.#ledger.append(receipt);
    this.#headHash = receiptHash;
    return receipt;
  }

  #duressCheck(e: ActionEnvelope, now: number): { errors: string[]; usable: boolean } {
    const p = this.policy.duress;
    const signals: unknown[] = [];
    const a = e?.acousticContext;
    if (a !== undefined && a !== null) {
      signals.push({ modality: 'acoustic', tensionScore: a.vocalTensionScore, signalQuality: a.signalQuality, capturedAt: a.capturedAt });
    }
    if (e?.duressSignals !== undefined) {
      if (!Array.isArray(e.duressSignals)) return { errors: ['duress_signals_invalid'], usable: false };
      signals.push(...e.duressSignals);
    }
    const errors: string[] = [];
    let usable = 0;
    for (const raw of signals) {
      const sig = raw as Partial<DuressSignal> | null;
      const m = sig && typeof sig === 'object' && DURESS_MODALITIES.includes(sig.modality as DuressModality) ? sig.modality : null;
      if (!m) {
        errors.push('duress_signal_modality_invalid');
        continue;
      }
      const nums = [sig!.tensionScore, sig!.signalQuality, sig!.capturedAt];
      if (!nums.every((n) => typeof n === 'number' && Number.isFinite(n))) {
        errors.push(`duress_signal_malformed:${m}`);
        continue;
      }
      const { tensionScore, signalQuality, capturedAt } = sig as DuressSignal;
      if (tensionScore < 0 || tensionScore > 1 || signalQuality < 0 || signalQuality > 1) {
        errors.push(`duress_signal_out_of_range:${m}`);
        continue;
      }
      const fresh = now - capturedAt <= p.maxAgeMs && capturedAt - now <= CLOCK_SKEW_MS;
      if (signalQuality < p.minSignalQuality || !fresh) continue; // degraded or stale: not usable, not calm
      usable++;
      if (tensionScore > p.maxTension) errors.push(`duress_tension_exceeds_threshold:${m}`);
    }
    return { errors, usable: usable > 0 };
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

function parameterErrors(
  params: Record<string, unknown>,
  rules: Map<string, { re: RegExp; maxLength: number }>,
): string[] {
  if (!params || typeof params !== 'object' || Array.isArray(params)) return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    const rule = rules.get(k);
    if (!rule) out.push(`parameter_not_allowed:${k}`);
    else if (typeof v !== 'string' || v.length > rule.maxLength || !rule.re.test(v)) out.push(`parameter_invalid:${k}`);
  }
  return out;
}

function validatePolicy(p: GatePolicy): void {
  if (!p?.version?.trim()) throw new Error('policy_version_required');
  for (const [name, a] of Object.entries(p.actions ?? {})) {
    if (!isRiskTier(a.tier)) throw new Error(`policy_action_tier_invalid:${name}`);
    if (a.parameters) {
      for (const [k, r] of Object.entries(a.parameters)) {
        try {
          new RegExp(`^(?:${r.pattern})$`, 'u');
        } catch {
          throw new Error(`policy_parameter_pattern_invalid:${name}.${k}`);
        }
      }
    }
    if (a.egress && !a.parameters && isRiskTier(p.consentRequiredFrom) && TIER_RANK[a.tier] < TIER_RANK[p.consentRequiredFrom]) {
      throw new Error(`policy_egress_without_consent_requires_parameters:${name}`);
    }
  }
  for (const t of [p.evidenceRequiredFrom, p.duressRequiredFrom, p.consentRequiredFrom]) {
    if (!isRiskTier(t)) throw new Error('policy_threshold_tier_invalid');
  }
  const { maxTension, minSignalQuality, maxAgeMs, onNoUsableSignal } = p.duress ?? ({} as GatePolicy['duress']);
  if (onNoUsableSignal !== 'deny' && onNoUsableSignal !== 'require_strong_presence') {
    throw new Error('policy_duress_on_no_usable_signal_invalid');
  }
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
