# U1SiQ gate: hardened reference

A TypeScript reference for the U1SiQ five-gate authority check and its tool-side enforcer. It is a rewrite that closes the gaps found in the implementation review. It has no runtime dependencies; it uses only WebCrypto (Ed25519), `node:fs` and `node:test`.

    cd v3-agent-assurance/u1siq
    node --test            # Node 22.18+; 39 regression tests
    npm run typecheck      # needs @types/node and TypeScript 5.8+

## What changed versus the reviewed code

| Review finding | Fix here | Test |
|---|---|---|
| Agent can call `evaluate()` with a fabricated envelope and get ALLOW | The gate trusts no proposer assertion: tier = max(policy, declared); `epistemicStatus` is derived from verified evidence and not read from the envelope; consent must be signed by a registered approver. Calling `evaluate()` directly gives the same answer as the front door. | `fabricated envelope via direct evaluate()` |
| `issueHumanConsentToken()` is unauthenticated | Removed. An `Approver` holds a private key meant for the human's device. The gate holds only approver public keys, fixed at construction, each with a maximum tier. | `consent signed by an unregistered key`, `approver below the action tier` |
| Receipt not bound to envelope | The enforcer recomputes the hash of the envelope being executed and requires `receipt.envelopeHash` to match. | `refuses a valid ALLOW receipt for different parameters` |
| No replay protection | A consumed-receipt store is checked and written before the effect, with serialized execution. | `same receipt twice`, `concurrent executes ... exactly once` |
| Chain not checked across receipts | The enforcer verifies sequence, `previousReceiptHash` and signature for every new ledger entry, and re-hashes the newest verified entry on each call. Any break halts it permanently. `verifyFullChain()` catches edits deeper in the ledger. | `deleting`, `reordering`, `rewriting`, `edits deep in the verified prefix` |
| Acoustic check fails open (`?? 0`) | Missing, malformed, out-of-range, degraded, stale or future-dated telemetry denies. | `acoustic gate fails closed: *` (7 cases) |
| Consent tied only to `proposalId` | Consent signs `{proposalId, envelopeHash, approverId, issuedAt, expiresAt, nonce}`. A nonce is burned only on ALLOW. | `does not cover changed parameters`, `cannot be replayed`, `expired consent` |
| Evidence only checked as non-empty | Each hash must exist in an `EvidenceStore` that computes the hash from content itself. One unknown hash denies. | `evidence must be registered` |
| Risk tier self-declared | Policy sets the floor per action. Unknown actions are denied, including prototype names like `toString`. | `under-declared tier is raised`, `unknown action` |
| Not durable; restart orphans receipts | JSONL ledger and consumed stores with fsync on append. Receipts carry `keyId`; verifiers keep a keyring including retired keys. You can pass in a KMS-backed key pair. | `file-backed ledger ... survive restart` |
| `undefined` in arrays canonicalizes to bare `undefined` | RFC 8785 ordering and number format; non-JSON values (`undefined` in arrays, holes, NaN, Infinity, bigint, Date, functions) throw, and the gate denies. | `canonicalize rejects ...`, `envelope with undefined in an array` |

## What this does not claim

- **The gate and the agent still share a process.** The signing key is non-extractable and kept in a `#private` field, and the gate's verdict no longer depends on anything the agent asserts. But code running in the same process can still monkeypatch `crypto.subtle`, patch the `U1SiQEnforcer` prototype, or call the effect function without going through the enforcer. Approvals are only as trustworthy as the process isolation around the gate, and that isolation is not built yet. The production requirement: the gate (and its key, ideally KMS/HSM) runs in a separate process or service; the enforcer runs where the tool runs; the agent can only send envelopes over an authenticated channel.
- **`EvidenceStore.register()` and approver registration are trusted paths.** Keep them off the agent's tool surface.
- **Approver keys are generated in-process here, for the tests.** In production they live on the human's device (WebAuthn / passkey or hardware token), and the approval UI must show the exact envelope being signed.
- **The acoustic score itself is not authenticated.** The gate fails closed on missing or bad telemetry but cannot tell a real calm sample from a fabricated one. Signed sensor attestations are the next step.
- **The file stores are single-writer.** Multi-process or multi-region use needs a transactional shared store. `entries()` copies the ledger on every call, which is fine for a reference and too slow at scale; use an indexed store with checkpointed heads.
- **An administrator who rewrites the whole ledger and holds the signing key can forge history.** Export signed checkpoints to a separate trust domain, as in the Watchtower README.
- **Execution is at-most-once.** A crash during an effect needs a fresh evaluation, not a retry with the same receipt.
- **Tests are synthetic.** They show the listed attacks are refused in this code. They are not evidence of deployed performance or certification.

## Status

A working reference with tests, run in CI (`.github/workflows/agent-assurance.yml`). It is not deployed, not integrated with a client, and not production-ready.

## Files

- `types.ts`: envelope, policy, receipt and consent types.
- `canonical.ts`: canonical JSON, hashing, key ids.
- `gate.ts`: `U1SiQGate` (Gates 1–5, signed receipts) and `EvidenceStore`.
- `consent.ts`: `Approver` and consent signature verification.
- `enforcer.ts`: `U1SiQEnforcer`, the only path to an effect.
- `ledger.ts`: memory and JSONL ledgers, consumed stores, `verifyChain`.
- `u1siq.test.ts`: regression tests, one or more per review finding.
