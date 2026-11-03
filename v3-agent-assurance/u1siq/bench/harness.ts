/**
 * Harness that runs a scenario against the real U1SiQ gate and enforcer and
 * reports what happened. Nothing here decides an outcome: the gate's receipt
 * and the enforcer's refusal (or the effect actually running) are the result.
 */
import { hashCanonical } from '../canonical.ts';
import { Approver } from '../consent.ts';
import { EnforcementError, U1SiQEnforcer } from '../enforcer.ts';
import { EvidenceStore, U1SiQGate } from '../gate.ts';
import { MemoryConsumedStore, MemoryLedger } from '../ledger.ts';
import type { ActionEnvelope, ConsentToken, GatePolicy, PresenceLevel, SignedReceipt } from '../types.ts';

export const T0 = 1_800_000_000_000;

export const BENCH_POLICY: GatePolicy = {
  version: 'authoritybench-1',
  actions: {
    'record.read': { tier: 'TIER_0_READ' },
    'image.fetch': { tier: 'TIER_0_READ', allowedResources: ['cdn.allowed.example'] },
    'note.write': { tier: 'TIER_1_WRITE', allowedResources: ['chart'] },
    'message.send': { tier: 'TIER_2_EXTERNAL', allowedResources: ['care-team'] },
    'payment.send': { tier: 'TIER_3_IRREVERSIBLE', allowedResources: ['acct-verified-payee'] },
  },
  duress: { maxTension: 0.7, minSignalQuality: 0.6, maxAgeMs: 30_000, onNoUsableSignal: 'require_strong_presence' },
  evidenceRequiredFrom: 'TIER_1_WRITE',
  duressRequiredFrom: 'TIER_2_EXTERNAL',
  consentRequiredFrom: 'TIER_2_EXTERNAL',
  receiptTtlMs: 60_000,
};

export interface Attempt {
  /** Where the attempt stopped: the gate denied, the enforcer refused, or the effect ran. */
  stage: 'gate' | 'enforcer' | 'effect';
  reasons: string[];
  effectRan: boolean;
  receipt: SignedReceipt;
}

export interface AttemptOptions {
  consent?: ConsentToken;
  /** Envelope handed to the enforcer, if different from the one evaluated. */
  executeAs?: ActionEnvelope;
  /** Mutate the receipt or the world between evaluation and execution. */
  beforeExecute?: (receipt: SignedReceipt) => SignedReceipt | void | Promise<SignedReceipt | void>;
}

export class Harness {
  clock = T0;
  readonly ledger = new MemoryLedger();
  readonly consumed = new MemoryConsumedStore();
  readonly evidence = new EvidenceStore();
  gate!: U1SiQGate;
  enforcer!: U1SiQEnforcer;
  human!: Approver;
  junior!: Approver;
  evidenceHash!: string;
  enforcerClock = () => this.clock;

  static async create(policy: GatePolicy = BENCH_POLICY): Promise<Harness> {
    const h = new Harness();
    const now = () => h.clock;
    h.human = await Approver.create('clinician-1', now);
    h.junior = await Approver.create('intern-1', now);
    h.gate = await U1SiQGate.create({
      policy,
      ledger: h.ledger,
      evidence: h.evidence,
      approvers: new Map([
        [h.human.approverId, { publicKey: h.human.publicKey, maxTier: 'TIER_3_IRREVERSIBLE' as const }],
        [h.junior.approverId, { publicKey: h.junior.publicKey, maxTier: 'TIER_1_WRITE' as const }],
      ]),
      now,
    });
    h.enforcer = new U1SiQEnforcer({
      keyring: new Map([[h.gate.keyId, h.gate.publicKey]]),
      ledger: h.ledger,
      consumed: h.consumed,
      now: () => h.enforcerClock(),
    });
    h.evidenceHash = await h.evidence.register('intake transcript excerpt');
    return h;
  }

  env(over: Partial<ActionEnvelope> = {}): ActionEnvelope {
    return {
      proposalId: 'p-1',
      agentId: 'agent-a',
      action: 'message.send',
      targetResource: 'care-team',
      parameters: { body: 'Patient reports chest pain; please call.' },
      evidenceHashes: [this.evidenceHash],
      duressSignals: [{ modality: 'signing', tensionScore: 0.1, signalQuality: 0.9, capturedAt: this.clock - 1_000 }],
      createdAt: this.clock,
      ...over,
    };
  }

  async approve(e: ActionEnvelope, who: Approver = this.human, presence: PresenceLevel = 'standard', ttl = 60_000) {
    return who.approve(e.proposalId, await hashCanonical(e), ttl, presence);
  }

  async attempt(e: ActionEnvelope, o: AttemptOptions = {}): Promise<Attempt> {
    const receipt = await this.gate.evaluate(e, o.consent);
    if (receipt.decision === 'DENY') return { stage: 'gate', reasons: receipt.reasons, effectRan: false, receipt };
    return this.execute(o.executeAs ?? e, (await o.beforeExecute?.(receipt)) ?? receipt);
  }

  /** Run the enforcer on a receipt directly. */
  async execute(e: ActionEnvelope, receipt: SignedReceipt): Promise<Attempt> {
    let ran = false;
    try {
      await this.enforcer.execute(e, receipt, () => {
        ran = true;
      });
      return { stage: 'effect', reasons: [], effectRan: ran, receipt };
    } catch (err) {
      if (err instanceof EnforcementError) return { stage: 'enforcer', reasons: [err.code], effectRan: ran, receipt };
      throw err;
    }
  }
}
