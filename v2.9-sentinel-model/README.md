# U1 Sentinel Evaluator Model v0.1

A trainable, advisory-only security evaluator for U1 Sentinel, with a Daybreak continuity pre-effect adapter.

## Core invariant

```text
MODEL OUTPUT ∉ AUTHORITY
```

The model may identify hazards, recommend denial, or request manual review. It never grants permissions, creates approval tokens, mutates policy, or authorizes execution.

## What this package does

- generates deterministic synthetic training data from Sentinel-style policy facts
- formats examples for supervised fine-tuning
- fine-tunes a configurable open-weight causal LM with LoRA/QLoRA
- evaluates the model on security-critical false-allow metrics
- exports a strict JSON contract compatible with the Sentinel advisory layer
- combines model vetoes with explicit Daybreak continuity-state checks before a proposed effect

## Directory

```text
v2.9-sentinel-model/
├── README.md
├── pyproject.toml
├── configs/
│   └── sft.example.yaml
├── src/u1_sentinel_model/
│   ├── schema.py
│   ├── oracle.py
│   ├── dataset.py
│   ├── train.py
│   ├── eval.py
│   ├── promotion_gate.py
│   └── daybreak.py
└── tests/
    ├── test_oracle.py
    ├── test_dataset.py
    ├── test_promotion_gate.py
    └── test_daybreak.py
```

## Training target

The evaluator must output exactly:

```json
{
  "verdict": "allow|deny|manual_review",
  "risk": "low|medium|high|critical",
  "findings": ["..."]
}
```

The most important evaluation metric is **critical false-allow rate**. Generic accuracy is secondary.

## Quick start

Create a synthetic dataset:

```bash
python -m u1_sentinel_model.dataset --output data/train.jsonl --count 4000 --seed 7
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

Fine-tune:

```bash
python -m u1_sentinel_model.train --base-model Qwen/Qwen2.5-7B-Instruct --train-file data/train.jsonl --output-dir artifacts/u1-sentinel-evaluator-v0.1 --load-in-4bit
```

Evaluate and save the metrics output:

```bash
python -m u1_sentinel_model.eval --model artifacts/u1-sentinel-evaluator-v0.1 --eval-file data/eval.jsonl > artifacts/eval-metrics.json
```

Run the fail-closed promotion gate against that metrics file:

```bash
python -m u1_sentinel_model.promotion_gate --metrics artifacts/eval-metrics.json --report artifacts/promotion-report.json
```

The gate exits non-zero unless the evaluation includes deny and critical-risk cases and records zero false allows, zero critical false allows, and zero malformed outputs. This is a mechanical threshold check for the supplied metrics, not a certification; keep the evaluation corpus frozen, inspect its provenance, and retain the full run artifacts. A model passing this gate remains advisory and never gains execution authority.

## Daybreak continuity adapter

`u1_sentinel_model.daybreak.evaluate_pre_effect` combines a deterministic policy result, continuity-plane health facts, and the evaluator's advisory result. It returns a versioned decision record; it does not execute tools, mint capabilities, or consume confirmations.

For an effect to be considered, the trusted caller must supply current, authenticated continuity facts. The adapter fails closed when the deterministic policy is missing/invalid or denies, when a continuity flag is malformed, or when any required recovery condition is not satisfied. A frozen authority graph, invalid capability grant, unverified clean checkpoint, invalid receipt chain, or unpromoted continuity plane routes to manual review. Model deny and manual-review outputs can veto an effect; a model allow cannot override deterministic denial or continuity failure, and only a low-risk model allow can pass this adapter.

Example:

```python
from u1_sentinel_model.daybreak import ContinuitySnapshot, evaluate_pre_effect
from u1_sentinel_model.schema import Evaluation

snapshot = ContinuitySnapshot(
    deterministic_policy="allow",
    authority_graph_frozen=False,
    capability_grant_valid=True,
    clean_checkpoint_verified=True,
    receipt_chain_valid=True,
    continuity_plane_promoted=True,
)
advisory = Evaluation("allow", "low", ("No policy-boundary hazard detected.",))
decision = evaluate_pre_effect(snapshot, advisory)
print(decision.to_dict())
```

**Integration boundary:** the adapter's boolean fields are assertions supplied by its caller, not cryptographic evidence. Production wiring must derive them from authenticated control-plane state, independently verify checkpoint/receipt integrity, bind decisions to a proposal digest and nonce, and recheck immediately before the effect. Until that wiring is present and tested, this module is a policy adapter, not a production enforcement boundary.

## Data design

Synthetic cases cover:

- canonical path escape
- principal mismatch
- scope mismatch
- privileged targets
- destructive effects
- persistence effects
- proposal digest mismatch
- confirmation mismatch
- nonce replay
- stale/expired confirmation
- policy disagreement
- bounded low-risk writes
- manual-review ambiguity

The deterministic oracle is deliberately conservative. It produces labels for training and regression, not runtime authorization.

## Production architecture

```text
caller
  -> authenticated proposal lookup
  -> deterministic policy engine
  -> evaluator model (advisory/veto only)
  -> Daybreak continuity pre-effect checks
  -> bound confirmation + atomic nonce consumption
  -> deterministic pre-effect recheck
  -> executor
  -> immutable receipt
```

A model `allow` can never override deterministic `deny`.

## Base model

The training pipeline is model-agnostic. Pass any compatible Hugging Face causal language model through `--base-model`. Do not assume that a specific checkpoint license permits redistribution of derivative weights; verify the selected model's license before publishing trained artifacts.

## Safety boundary

This project trains a defensive evaluator on authorization-boundary examples. It does not include autonomous exploitation, persistence, credential theft, or unrestricted tool execution.
