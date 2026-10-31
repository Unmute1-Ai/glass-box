/**
 * Regression tests: one or more per finding in the implementation review.
 * Run: node --test (Node 22.18+ strips types natively).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize, CanonicalizationError, hashCanonical, keyIdFor } from './canonical.ts';
import { Approver } from './consent.ts';
import { EnforcementError, U1SiQEnforcer } from './enforcer.ts';
import { EvidenceStore, U1SiQGate } from './gate.ts';
import {
  JsonlConsumedStore,
  JsonlLedger,
  MemoryConsumedStore,
  MemoryLedger,
  verifyChain,
  type ReceiptLedger,
} from './ledger.ts';
import type { ActionEnvelope, ConsentToken, GatePolicy, SignedReceipt } from './types.ts';

const T0 = 1_800_000_000_000;

const POLICY: GatePolicy = {
  version: 'test-1',
  actions: {
    'record.read': { tier: 'TIER_0_READ' },
    'note.write': { tier: 'TIER_1_WRITE' },
    'message.send': { tier: 'TIER_2_EXTERNAL', allowedResources: ['care-team'] },
    'payment.send': { tier: 'TIER_3_IRREVERSIBLE' },
  },
  acoustic: { maxTension: 0.7, minSignalQuality: 0.6, maxAgeMs: 30_000 },
  evidenceRequiredFrom: 'TIER_1_WRITE',
  acousticRequiredFrom: 'TIER_2_EXTERNAL',
  consentRequiredFrom: 'TIER_2_EXTERNAL',
  receiptTtlMs: 60_000,
};

async function setup<L extends ReceiptLedger = MemoryLedger>(opts: { ledger?: L } = {}) {
  let now = T0;
  const clock = () => now;
  const ledger = (opts.ledger ?? new MemoryLedger()) as L;
  const evidence = new EvidenceStore();
  const human = await Approver.create('clinician-1', clock);
  const junior = await Approver.create('intern-1', clock);
  const gate = await U1SiQGate.create({
    policy: POLICY,
    ledger,
    evidence,
    approvers: new Map([
      [human.approverId, { publicKey: human.publicKey, maxTier: 'TIER_3_IRREVERSIBLE' as const }],
      [junior.approverId, { publicKey: junior.publicKey, maxTier: 'TIER_2_EXTERNAL' as const }],
    ]),
    now: clock,
  });
  const enforcer = new U1SiQEnforcer({
    keyring: new Map([[gate.keyId, gate.publicKey]]),
    ledger,
    consumed: new MemoryConsumedStore(),
    now: clock,
  });
  const ev = await evidence.register('intake transcript excerpt #1');
  const env = (over: Partial<ActionEnvelope> = {}): ActionEnvelope => ({
    proposalId: 'p-1',
    agentId: 'agent-a',
    action: 'message.send',
    targetResource: 'care-team',
    parameters: { body: 'Patient reports chest pain; please call.' },
    evidenceHashes: [ev],
    acousticContext: { vocalTensionScore: 0.2, signalQuality: 0.9, capturedAt: T0 - 1_000 },
    createdAt: T0,
    ...over,
  });
  const approve = async (e: ActionEnvelope, who = human, ttl = 60_000): Promise<ConsentToken> =>
    who.approve(e.proposalId, await hashCanonical(e), ttl);
  return { gate, enforcer, ledger, evidence, human, junior, env, approve, ev, advance: (ms: number) => (now += ms) };
}

const effectSpy = () => {
  let calls = 0;
  return { run: () => (calls++, 'done'), get calls() { return calls; } };
};

async function rejects(p: Promise<unknown>, code: string | RegExp) {
  await assert.rejects(p, (err: unknown) => {
    assert.ok(err instanceof EnforcementError, `expected EnforcementError, got ${err}`);
    if (typeof code === 'string') assert.equal(err.code, code);
    else assert.match(err.code, code);
    return true;
  });
}

// --- Happy paths -----------------------------------------------------------

test('tier 0 read is allowed and executes once', async () => {
  const s = await setup();
  const e = s.env({ action: 'record.read', acousticContext: undefined, evidenceHashes: [] });
  const r = await s.gate.evaluate(e);
  assert.equal(r.decision, 'ALLOW', r.reasons.join());
  const fx = effectSpy();
  assert.equal(await s.enforcer.execute(e, r, fx.run), 'done');
  assert.equal(fx.calls, 1);
});

test('tier 2 with verified evidence, calm telemetry and bound consent is allowed', async () => {
  const s = await setup();
  const e = s.env();
  const r = await s.gate.evaluate(e, await s.approve(e));
  assert.equal(r.decision, 'ALLOW', r.reasons.join());
  assert.equal(r.epistemicStatus, 'VERIFIED_FACT');
  assert.equal(r.consentApproverId, 'clinician-1');
  assert.equal(await s.enforcer.execute(e, r, () => 'sent'), 'sent');
});

// --- Finding: agent can mint its own approvals ----------------------------

test('fabricated envelope via direct evaluate(): self-declared tier and status buy nothing', async () => {
  const s = await setup();
  const forged = {
    ...s.env({ action: 'payment.send', targetResource: 'acct-9', declaredRiskTier: 'TIER_0_READ' }),
    epistemicStatus: 'VERIFIED_FACT', // the old field; ignored, and changes the hash
    evidenceHashes: ['f'.repeat(64)],
    acousticContext: undefined,
  } as ActionEnvelope;
  const r = await s.gate.evaluate(forged);
  assert.equal(r.decision, 'DENY');
  assert.equal(r.effectiveRiskTier, 'TIER_3_IRREVERSIBLE');
  assert.equal(r.epistemicStatus, 'UNVERIFIED');
  for (const reason of ['evidence_unverified:ffffffffffff', 'acoustic_telemetry_missing', 'human_consent_required']) {
    assert.ok(r.reasons.includes(reason), `missing ${reason} in ${r.reasons}`);
  }
});

test('gate exposes no consent-issuing method and no key material beyond the public key', async () => {
  const s = await setup();
  const g = s.gate as unknown as Record<string, unknown>;
  assert.equal(g.issueHumanConsentToken, undefined);
  const exposed = Object.keys(s.gate).map((k) => g[k]);
  const keys = exposed.filter((v) => v instanceof CryptoKey) as CryptoKey[];
  assert.deepEqual(keys.map((k) => k.type), ['public']);
});

test('consent signed by an unregistered key is rejected', async () => {
  const s = await setup();
  const rogue = await Approver.create('clinician-1'); // same id, different key
  const e = s.env();
  const r = await s.gate.evaluate(e, await s.approve(e, rogue));
  assert.equal(r.decision, 'DENY');
  assert.ok(r.reasons.includes('consent_signature_invalid'));
});

test('consent token with edited claims fails signature check', async () => {
  const s = await setup();
  const e = s.env();
  const c = await s.approve(e);
  const r = await s.gate.evaluate(e, { ...c, expiresAt: c.expiresAt + 10 ** 9 });
  assert.ok(r.reasons.includes('consent_signature_invalid'));
});

test('approver below the action tier cannot approve it', async () => {
  const s = await setup();
  const e = s.env({ action: 'payment.send', targetResource: 'acct-9' });
  const r = await s.gate.evaluate(e, await s.approve(e, s.junior));
  assert.ok(r.reasons.includes('consent_approver_tier_insufficient'));
});

// --- Finding: consent not tied to content ---------------------------------

test('consent for one envelope does not cover changed parameters under the same proposalId', async () => {
  const s = await setup();
  const approved = s.env();
  const c = await s.approve(approved);
  const swapped = s.env({ parameters: { body: 'Wire $5,000 to acct 9' } });
  const r = await s.gate.evaluate(swapped, c);
  assert.equal(r.decision, 'DENY');
  assert.ok(r.reasons.includes('consent_envelope_mismatch'));
});

test('consent cannot be replayed after it has been used', async () => {
  const s = await setup();
  const e = s.env();
  const c = await s.approve(e);
  assert.equal((await s.gate.evaluate(e, c)).decision, 'ALLOW');
  const again = await s.gate.evaluate(e, c);
  assert.ok(again.reasons.includes('consent_replayed'));
});

test('a valid consent is not reported as failing when another gate denies', async () => {
  const s = await setup();
  const e1 = s.env({ acousticContext: undefined });
  // Consent is over the envelope hash, so a different envelope needs its own consent.
  const r1 = await s.gate.evaluate(e1, await s.approve(e1));
  assert.ok(r1.reasons.includes('acoustic_telemetry_missing'));
  assert.ok(!r1.reasons.some((x) => x.startsWith('consent_')));
});

test('expired consent is rejected', async () => {
  const s = await setup();
  const e = s.env();
  const c = await s.approve(e, s.human, 1_000);
  s.advance(2_000);
  const r = await s.gate.evaluate({ ...e }, c);
  assert.ok(r.reasons.includes('consent_expired'));
});

// --- Finding: acoustic check fails open ------------------------------------

for (const [name, ctx, reason] of [
  ['missing', undefined, 'acoustic_telemetry_missing'],
  ['degraded', { vocalTensionScore: 0.1, signalQuality: 0.2, capturedAt: T0 }, 'acoustic_signal_degraded'],
  ['stale', { vocalTensionScore: 0.1, signalQuality: 0.9, capturedAt: T0 - 120_000 }, 'acoustic_telemetry_stale'],
  ['future-dated', { vocalTensionScore: 0.1, signalQuality: 0.9, capturedAt: T0 + 60_000 }, 'acoustic_telemetry_stale'],
  ['tense', { vocalTensionScore: 0.95, signalQuality: 0.9, capturedAt: T0 }, 'acoustic_tension_exceeds_threshold'],
  ['NaN score', { vocalTensionScore: NaN, signalQuality: 0.9, capturedAt: T0 }, 'acoustic_telemetry_malformed'],
  ['negative score', { vocalTensionScore: -1, signalQuality: 0.9, capturedAt: T0 }, 'acoustic_telemetry_out_of_range'],
] as const) {
  test(`acoustic gate fails closed: ${name}`, async () => {
    const s = await setup();
    const e = s.env({ acousticContext: ctx as ActionEnvelope['acousticContext'] });
    let consent: ConsentToken | undefined;
    try {
      consent = await s.approve(e);
    } catch {
      consent = undefined; // NaN is not canonicalizable; the gate must still deny
    }
    const r = await s.gate.evaluate(e, consent);
    assert.equal(r.decision, 'DENY');
    assert.ok(r.reasons.includes(reason), `${r.reasons}`);
  });
}

// --- Finding: evidence unverified; risk tier self-declared ----------------

test('evidence must be registered, not just non-empty', async () => {
  const s = await setup();
  const e = s.env({ action: 'note.write', targetResource: 'chart', evidenceHashes: ['a'.repeat(64)] });
  const r = await s.gate.evaluate(e);
  assert.equal(r.decision, 'DENY');
  assert.ok(r.reasons.includes('evidence_unverified:aaaaaaaaaaaa'));
});

test('one unverified hash among verified ones still denies and marks UNVERIFIED', async () => {
  const s = await setup();
  const e = s.env({ action: 'note.write', targetResource: 'chart', evidenceHashes: [s.ev, 'b'.repeat(64)] });
  const r = await s.gate.evaluate(e);
  assert.equal(r.decision, 'DENY');
  assert.equal(r.epistemicStatus, 'UNVERIFIED');
});

test('under-declared tier is raised to the policy tier', async () => {
  const s = await setup();
  const e = s.env({ declaredRiskTier: 'TIER_0_READ', acousticContext: undefined });
  const r = await s.gate.evaluate(e);
  assert.equal(r.effectiveRiskTier, 'TIER_2_EXTERNAL');
  assert.ok(r.reasons.includes('acoustic_telemetry_missing'));
  assert.ok(r.reasons.includes('human_consent_required'));
});

test('over-declared tier is honored (proposer may ask for more scrutiny)', async () => {
  const s = await setup();
  const e = s.env({ action: 'record.read', declaredRiskTier: 'TIER_2_EXTERNAL' });
  const r = await s.gate.evaluate(e);
  assert.equal(r.effectiveRiskTier, 'TIER_2_EXTERNAL');
  assert.ok(r.reasons.includes('human_consent_required'));
});

test('unknown action and disallowed resource are denied', async () => {
  const s = await setup();
  assert.ok((await s.gate.evaluate(s.env({ action: 'shell.exec' }))).reasons.includes('action_not_in_policy'));
  assert.ok((await s.gate.evaluate(s.env({ action: 'toString' }))).reasons.includes('action_not_in_policy'));
  const e = s.env({ targetResource: 'press-desk' });
  assert.ok((await s.gate.evaluate(e, await s.approve(e))).reasons.includes('resource_not_allowed_for_action'));
});

// --- Finding: receipt not bound to the envelope ---------------------------

test('enforcer refuses a valid ALLOW receipt for different parameters', async () => {
  const s = await setup();
  const e = s.env({ action: 'record.read', acousticContext: undefined });
  const r = await s.gate.evaluate(e);
  const fx = effectSpy();
  await rejects(s.enforcer.execute({ ...e, parameters: { all: true } }, r, fx.run), 'envelope_hash_mismatch');
  await rejects(s.enforcer.execute({ ...e, targetResource: 'other' }, r, fx.run), 'envelope_hash_mismatch');
  assert.equal(fx.calls, 0);
});

// --- Finding: no replay protection ----------------------------------------

test('enforcer refuses to execute the same receipt twice', async () => {
  const s = await setup();
  const e = s.env({ action: 'record.read', acousticContext: undefined });
  const r = await s.gate.evaluate(e);
  const fx = effectSpy();
  await s.enforcer.execute(e, r, fx.run);
  await rejects(s.enforcer.execute(e, r, fx.run), 'receipt_replayed');
  assert.equal(fx.calls, 1);
});

test('concurrent executes of one receipt run the effect exactly once', async () => {
  const s = await setup();
  const e = s.env({ action: 'record.read', acousticContext: undefined });
  const r = await s.gate.evaluate(e);
  const fx = effectSpy();
  const results = await Promise.allSettled(Array.from({ length: 10 }, () => s.enforcer.execute(e, r, fx.run)));
  assert.equal(results.filter((x) => x.status === 'fulfilled').length, 1);
  assert.equal(fx.calls, 1);
});

// --- Receipt integrity -----------------------------------------------------

test('enforcer refuses DENY, expired, tampered, and foreign-key receipts', async () => {
  const s = await setup();
  const e = s.env({ action: 'record.read', acousticContext: undefined });

  const denied = await s.gate.evaluate(s.env({ acousticContext: undefined }));
  await rejects(s.enforcer.execute(s.env({ acousticContext: undefined }), denied, () => 1), 'receipt_not_allow');

  const r = await s.gate.evaluate(e);
  const flipped: SignedReceipt = { ...denied, decision: 'ALLOW' };
  await rejects(s.enforcer.execute(s.env({ acousticContext: undefined }), flipped, () => 1), 'receipt_hash_mismatch');

  const other = await setup();
  const foreign = await other.gate.evaluate(e);
  await rejects(s.enforcer.execute(e, foreign, () => 1), 'unknown_signing_key');

  s.advance(POLICY.receiptTtlMs + 1);
  await rejects(s.enforcer.execute(e, r, () => 1), 'receipt_expired');
});

test('a validly signed receipt that is not in the ledger is refused', async () => {
  const s = await setup();
  const e = s.env({ action: 'record.read', acousticContext: undefined });
  const r = await s.gate.evaluate(e);
  s.ledger.unsafeRows().pop();
  // Enforcer has not verified anything yet, so this reads as "not in ledger".
  await rejects(s.enforcer.execute(e, r, () => 1), 'receipt_not_in_ledger');
});

// --- Finding: chain not checked across receipts ---------------------------

test('deleting a ledger entry halts the enforcer, including for later valid receipts', async () => {
  const s = await setup();
  const read = (id: string) => s.env({ proposalId: id, action: 'record.read', acousticContext: undefined });
  const r1 = await s.gate.evaluate(read('a'));
  await s.enforcer.execute(read('a'), r1, () => 1);
  await s.gate.evaluate(read('b'));
  const r3 = await s.gate.evaluate(read('c'));
  s.ledger.unsafeRows().splice(1, 1); // delete entry 2
  await rejects(s.enforcer.execute(read('c'), r3, () => 1), /^halted:chain_broken_at_2/);
  assert.match(s.enforcer.halted!, /chain_broken_at_2/);
  const r4 = await s.gate.evaluate(read('d'));
  await rejects(s.enforcer.execute(read('d'), r4, () => 1), /^halted:/);
});

test('reordering ledger entries is detected', async () => {
  const s = await setup();
  const read = (id: string) => s.env({ proposalId: id, action: 'record.read', acousticContext: undefined });
  await s.gate.evaluate(read('a'));
  const r2 = await s.gate.evaluate(read('b'));
  const rows = s.ledger.unsafeRows();
  [rows[0], rows[1]] = [rows[1], rows[0]];
  await rejects(s.enforcer.execute(read('b'), r2, () => 1), /^halted:chain_broken_at_1:sequence_gap_or_reorder/);
});

test('rewriting the already-verified prefix is detected', async () => {
  const s = await setup();
  const read = (id: string) => s.env({ proposalId: id, action: 'record.read', acousticContext: undefined });
  const r1 = await s.gate.evaluate(read('a'));
  await s.enforcer.execute(read('a'), r1, () => 1);
  s.ledger.unsafeRows()[0] = { ...s.ledger.unsafeRows()[0], reasons: ['edited'] };
  const r2 = await s.gate.evaluate(read('b'));
  await rejects(s.enforcer.execute(read('b'), r2, () => 1), 'halted:verified_prefix_rewritten');
});

test('edits deep in the verified prefix are caught by the scheduled full check', async () => {
  const s = await setup();
  const read = (id: string) => s.env({ proposalId: id, action: 'record.read', acousticContext: undefined });
  for (const id of ['a', 'b', 'c']) await s.enforcer.execute(read(id), await s.gate.evaluate(read(id)), () => 1);
  s.ledger.unsafeRows()[0] = { ...s.ledger.unsafeRows()[0], reasons: ['edited'] };
  await rejects(s.enforcer.verifyFullChain(), /^halted:chain_broken_at_1:receipt_hash_mismatch/);
});

test('verifyChain accepts an intact chain that includes DENY receipts', async () => {
  const s = await setup();
  await s.gate.evaluate(s.env({ acousticContext: undefined }));
  await s.gate.evaluate(s.env({ action: 'record.read', acousticContext: undefined }));
  const res = await verifyChain(s.ledger.entries(), new Map([[s.gate.keyId, s.gate.publicKey]]));
  assert.deepEqual({ ok: res.ok }, { ok: true });
});

// --- Finding: not durable --------------------------------------------------

test('file-backed ledger and replay set survive restart; old receipts verify after key rotation', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'u1siq-'));
  try {
    const ledgerPath = join(dir, 'ledger.jsonl');
    const consumedPath = join(dir, 'consumed.jsonl');

    const first = await setup({ ledger: new JsonlLedger(ledgerPath) });
    const e = first.env({ action: 'record.read', acousticContext: undefined });
    const r1 = await first.gate.evaluate(e);
    const enf1 = new U1SiQEnforcer({
      keyring: new Map([[first.gate.keyId, first.gate.publicKey]]),
      ledger: new JsonlLedger(ledgerPath),
      consumed: new JsonlConsumedStore(consumedPath),
      now: () => T0,
    });
    await enf1.execute(e, r1, () => 1);

    // "Restart": new gate with a new key, reloading the same ledger.
    const reloaded = new JsonlLedger(ledgerPath);
    const second = await setup({ ledger: reloaded });
    assert.notEqual(second.gate.keyId, first.gate.keyId);
    const e2 = second.env({ proposalId: 'p-2', action: 'record.read', acousticContext: undefined });
    const r2 = await second.gate.evaluate(e2);
    assert.equal(r2.sequence, 2);
    assert.equal(r2.previousReceiptHash, r1.receiptHash);

    const keyring = new Map([
      [first.gate.keyId, first.gate.publicKey], // retired key kept for verification
      [second.gate.keyId, second.gate.publicKey],
    ]);
    const enf2 = new U1SiQEnforcer({
      keyring,
      ledger: new JsonlLedger(ledgerPath),
      consumed: new JsonlConsumedStore(consumedPath),
      now: () => T0,
    });
    await enf2.verifyFullChain();
    await rejects(enf2.execute(e, r1, () => 1), 'receipt_replayed'); // replay set persisted
    assert.equal(await enf2.execute(e2, r2, () => 'ok'), 'ok');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('keyId is derived from the public key', async () => {
  const s = await setup();
  assert.equal(s.gate.keyId, await keyIdFor(s.gate.publicKey));
});

// --- Finding: canonicalization edge case ----------------------------------

test('canonicalize rejects undefined in arrays and other non-JSON values', () => {
  assert.throws(() => canonicalize([1, undefined, 2]), CanonicalizationError);
  assert.throws(() => canonicalize(new Array(3)), CanonicalizationError); // holes
  assert.throws(() => canonicalize({ a: NaN }), CanonicalizationError);
  assert.throws(() => canonicalize({ a: Infinity }), CanonicalizationError);
  assert.throws(() => canonicalize({ a: 1n }), CanonicalizationError);
  assert.throws(() => canonicalize({ a: new Date(0) }), CanonicalizationError);
  assert.throws(() => canonicalize({ a: () => 1 }), CanonicalizationError);
});

test('canonicalize is key-order independent, omits undefined props, and emits valid JSON', () => {
  const a = canonicalize({ b: [1, { y: 2, x: 'é' }], a: null, z: undefined, n: -0 });
  const b = canonicalize({ n: 0, a: null, b: [1, { x: 'é', y: 2 }] });
  assert.equal(a, b);
  assert.equal(a, '{"a":null,"b":[1,{"x":"é","y":2}],"n":0}');
  JSON.parse(a);
});

test('envelope with undefined in an array is denied, not hashed as text', async () => {
  const s = await setup();
  const e = s.env({ action: 'record.read', acousticContext: undefined, parameters: { ids: [1, undefined] } });
  const r = await s.gate.evaluate(e);
  assert.equal(r.decision, 'DENY');
  assert.ok(r.reasons.includes('envelope_not_canonicalizable'));
});

test('policy is frozen after construction', async () => {
  const s = await setup();
  assert.throws(() => {
    (s.gate.policy.actions['payment.send'] as { tier: string }).tier = 'TIER_0_READ';
  }, TypeError);
});
