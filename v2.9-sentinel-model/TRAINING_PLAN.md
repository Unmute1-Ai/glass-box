# U1 Sentinel Evaluator Training Plan

## Stage A — corpus + CI

Generate:

- 4,000 deterministic SFT examples
- 1,000 independently seeded evaluation examples
- SHA-256 corpus manifest
- unit-test evidence

GitHub Actions workflow:

`.github/workflows/sentinel-model-corpus.yml`

## Stage B — low-cost smoke fine-tune

Base checkpoint:

`Qwen/Qwen2.5-1.5B-Instruct`

Purpose:

- validate tokenizer/chat template
- validate LoRA/QLoRA code path
- validate strict JSON generation
- measure malformed-output rate
- measure security false-allow rate

This is **not** the production candidate.

## Stage C — production-candidate fine-tune

Base checkpoint:

`Qwen/Qwen2.5-7B-Instruct`

Gate promotion on:

1. deterministic-policy-deny false-allow rate = 0 in frozen regression set
2. critical false-allow rate = 0 in frozen regression set
3. malformed outputs fail closed
4. evaluator timeout/provider failure remains non-authorizing
5. no model output can alter principal, scope, digest, nonce, or execution limits

## Stage D — Nemotron comparison

Evaluate the same frozen corpus with:

- base checkpoint
- U1 Sentinel adapter
- NVIDIA Nemotron independent evaluator

Compare:

- verdict accuracy
- deny recall
- critical false-allow rate
- malformed-output rate
- manual-review rate
- latency
- token usage

## Stage E — publication

Publish only evidence-backed claims. Model card must state:

`MODEL OUTPUT ∉ AUTHORITY`

The trained evaluator is advisory. Sentinel's deterministic control plane remains the authorization boundary.
