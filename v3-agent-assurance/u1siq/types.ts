export type RiskTier = 'TIER_0_READ' | 'TIER_1_WRITE' | 'TIER_2_EXTERNAL' | 'TIER_3_IRREVERSIBLE';

export const TIER_RANK: Readonly<Record<RiskTier, number>> = Object.freeze({
  TIER_0_READ: 0,
  TIER_1_WRITE: 1,
  TIER_2_EXTERNAL: 2,
  TIER_3_IRREVERSIBLE: 3,
});

export function isRiskTier(v: unknown): v is RiskTier {
  return typeof v === 'string' && Object.hasOwn(TIER_RANK, v);
}

export function maxTier(a: RiskTier, b: RiskTier): RiskTier {
  return TIER_RANK[a] >= TIER_RANK[b] ? a : b;
}

/** Derived by the gate. Never accepted from the proposer. */
export type EpistemicStatus = 'VERIFIED_FACT' | 'UNVERIFIED';

export interface AcousticContext {
  /** 0 (calm) .. 1 (maximum tension). */
  vocalTensionScore: number;
  /** 0 (no usable signal) .. 1 (clean signal). */
  signalQuality: number;
  /** Epoch milliseconds when the sample was captured. */
  capturedAt: number;
}

/** What the agent proposes. Every field here is untrusted input. */
export interface ActionEnvelope {
  proposalId: string;
  agentId: string;
  action: string;
  targetResource: string;
  parameters: Record<string, unknown>;
  /** Optional hint. The gate uses max(declared, policy) so under-declaring buys nothing. */
  declaredRiskTier?: RiskTier;
  /** sha256 hex of evidence registered through the trusted evidence ingest path. */
  evidenceHashes: string[];
  acousticContext?: AcousticContext;
  createdAt: number;
}

export interface ActionPolicy {
  tier: RiskTier;
  /** Resources this action may touch. Omit to allow any. */
  allowedResources?: string[];
}

export interface GatePolicy {
  version: string;
  /** Unknown actions are denied. */
  actions: Record<string, ActionPolicy>;
  acoustic: {
    /** Deny when vocalTensionScore is above this. */
    maxTension: number;
    /** Treat signal below this as degraded and deny. */
    minSignalQuality: number;
    /** Treat samples older than this as stale and deny. */
    maxAgeMs: number;
  };
  /** Minimum tier at which Gate 3 requires at least one verified evidence hash. */
  evidenceRequiredFrom: RiskTier;
  /** Minimum tier at which Gate 4 (acoustic) applies. */
  acousticRequiredFrom: RiskTier;
  /** Minimum tier at which Gate 5 (human consent) applies. */
  consentRequiredFrom: RiskTier;
  receiptTtlMs: number;
}

export type Decision = 'ALLOW' | 'DENY';

export interface ReceiptBody {
  receiptId: string;
  sequence: number;
  previousReceiptHash: string;
  proposalId: string;
  /** Hash of the exact envelope evaluated. The enforcer requires the executed envelope to match. */
  envelopeHash: string;
  decision: Decision;
  reasons: string[];
  effectiveRiskTier: RiskTier;
  epistemicStatus: EpistemicStatus;
  policyVersion: string;
  keyId: string;
  issuedAt: number;
  expiresAt: number;
  consentApproverId?: string;
}

export interface SignedReceipt extends ReceiptBody {
  /** sha256 hex of canonicalize(ReceiptBody). */
  receiptHash: string;
  /** Ed25519 over the utf8 bytes of receiptHash, base64url. */
  signature: string;
}

export interface ConsentClaims {
  proposalId: string;
  envelopeHash: string;
  approverId: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
}

export interface ConsentToken extends ConsentClaims {
  /** Ed25519 by the approver's key over canonicalize(ConsentClaims), base64url. */
  signature: string;
}

export const GENESIS_HASH = '0'.repeat(64);
