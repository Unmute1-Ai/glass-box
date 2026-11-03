/**
 * Runs AuthorityBench against the U1SiQ gate and writes measured results.
 *
 *   node bench/run.ts [--out-dir bench/out] [--check]
 *
 * --check exits non-zero if any outcome differs from the suite's prediction
 * or any control is wrongly denied, so CI flags behaviour changes either way.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize } from '../canonical.ts';
import { verifyChain } from '../ledger.ts';
import { Harness } from './harness.ts';
import { BLOCKED_BY, SUITES } from './suites.ts';

interface Row {
  suite_id: string;
  suite_name: string;
  case: 'attack' | 'control' | 'none';
  status: 'executed' | 'not_covered';
  coverage: string | null;
  expected: string | null;
  outcome: 'BLOCKED' | 'BYPASSED' | 'ALLOWED' | 'FALSE_POSITIVE' | 'NOT_COVERED';
  matches_expected: boolean | null;
  /** For blocked attacks: whether the block came from the reason the suite targets. */
  blocked_for_intended_reason: boolean | null;
  stopped_at: 'gate' | 'enforcer' | 'effect' | null;
  reasons: string[];
  effect_ran: boolean | null;
  receipt_hash: string | null;
  ledger_chain_ok: boolean | null;
  note: string | null;
}

const args = process.argv.slice(2);
const outDir = args.includes('--out-dir') ? args[args.indexOf('--out-dir') + 1] : join(import.meta.dirname, 'out');
const check = args.includes('--check');

const rows: Row[] = [];
for (const s of SUITES) {
  if (s.status === 'not_covered') {
    rows.push({
      suite_id: s.id, suite_name: s.name, case: 'none', status: s.status, coverage: null, expected: null,
      outcome: 'NOT_COVERED', matches_expected: null, blocked_for_intended_reason: null, stopped_at: null, reasons: [], effect_ran: null,
      receipt_hash: null, ledger_chain_ok: null, note: s.why,
    });
    continue;
  }
  for (const kind of ['attack', 'control'] as const) {
    const h = await Harness.create(); // fresh gate, keys and ledger per case
    const a = await (kind === 'attack' ? s.attack(h) : s.control(h));
    const chain = await verifyChain(h.ledger.entries(), new Map([[h.gate.keyId, h.gate.publicKey]]));
    const outcome = kind === 'attack' ? (a.effectRan ? 'BYPASSED' : 'BLOCKED') : a.effectRan ? 'ALLOWED' : 'FALSE_POSITIVE';
    const expected = kind === 'attack' ? s.expected : 'ALLOWED';
    const intended = BLOCKED_BY[s.id];
    const blockedForIntended = kind === 'attack' && outcome === 'BLOCKED' ? !!intended && a.reasons.some((x) => intended.test(x)) : null;
    rows.push({
      suite_id: s.id, suite_name: s.name, case: kind, status: s.status, coverage: s.coverage, expected,
      outcome, matches_expected: outcome === expected && blockedForIntended !== false,
      blocked_for_intended_reason: blockedForIntended, stopped_at: a.stage, reasons: a.reasons, effect_ran: a.effectRan,
      receipt_hash: a.receipt.receiptHash, ledger_chain_ok: chain.ok, note: kind === 'attack' ? s.note ?? null : null,
    });
  }
}

const count = (f: (r: Row) => boolean) => rows.filter(f).length;
const attacks = rows.filter((r) => r.case === 'attack');
const summary = {
  bench: 'AuthorityBench (U1SiQ gate)',
  policy_version: 'authoritybench-1',
  suites_total: SUITES.length,
  suites_executed: SUITES.filter((s) => s.status === 'executed').length,
  suites_not_covered: SUITES.filter((s) => s.status === 'not_covered').length,
  attacks_blocked: count((r) => r.case === 'attack' && r.outcome === 'BLOCKED'),
  attacks_bypassed: count((r) => r.case === 'attack' && r.outcome === 'BYPASSED'),
  attacks_blocked_direct: count((r) => r.case === 'attack' && r.outcome === 'BLOCKED' && r.coverage === 'direct'),
  attacks_blocked_consequence_only: count((r) => r.case === 'attack' && r.outcome === 'BLOCKED' && r.coverage === 'consequence_only'),
  controls_allowed: count((r) => r.case === 'control' && r.outcome === 'ALLOWED'),
  controls_false_positive: count((r) => r.case === 'control' && r.outcome === 'FALSE_POSITIVE'),
  mismatches_vs_expected: count((r) => r.matches_expected === false),
  bypassed_suites: attacks.filter((r) => r.outcome === 'BYPASSED').map((r) => r.suite_id),
  not_covered_suites: rows.filter((r) => r.status === 'not_covered').map((r) => r.suite_id),
  limits: [
    'Synthetic scenarios against a reference implementation, not a deployed system.',
    'not_covered suites are untested here, not passed.',
    'consequence_only means the attack itself is not detected; only its consequential action is blocked.',
    'Receipt hashes differ per run because signing keys are generated per run; outcomes are deterministic.',
  ],
};

mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'authoritybench-results.jsonl'), rows.map((r) => canonicalize(r)).join('\n') + '\n');
writeFileSync(join(outDir, 'authoritybench-summary.json'), JSON.stringify(summary, null, 2) + '\n');

console.log(
  `[AuthorityBench] ${summary.suites_total} suites: ${summary.suites_executed} executed, ${summary.suites_not_covered} not covered`,
);
console.log(
  `[AuthorityBench] attacks: ${summary.attacks_blocked} blocked (${summary.attacks_blocked_direct} direct, ${summary.attacks_blocked_consequence_only} consequence-only), ${summary.attacks_bypassed} bypassed ${JSON.stringify(summary.bypassed_suites)}`,
);
console.log(
  `[AuthorityBench] controls: ${summary.controls_allowed} allowed, ${summary.controls_false_positive} false positives; mismatches vs expected: ${summary.mismatches_vs_expected}`,
);
for (const r of rows.filter((r) => r.matches_expected === false)) {
  const why = r.blocked_for_intended_reason === false ? ' (blocked, but not for the intended reason)' : '';
  console.log(`  MISMATCH ${r.suite_id} ${r.case}: expected ${r.expected}, got ${r.outcome}${why} at ${r.stopped_at} ${JSON.stringify(r.reasons)}`);
}
if (check && summary.mismatches_vs_expected > 0) process.exit(1);
