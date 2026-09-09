# U1 Sentinel Evaluator Model v0.1

A trainable, advisory-only security evaluator for U1 Sentinel.

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
- exports a strict JSON contract compatible with the Sentinel v2.8 advisory layer

## Directory

```text
v2.9-sentinel-model/
├── README.md
├── pyproject.toml
├── configs/
│   └── sft.example.yaml
├── src/u1_sentinel_model/
│   ├── __init__.py
│   ├── schema.py
│   ├── oracle.py
│   ├── dataset.py
│   ├── train.py
│   └── eval.py
└── tests/
    ├── test_oracle.py
    └── test_dataset.py
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
python -m u1_sentinel_model.dataset   --output data/train.jsonl   --count 4000   --seed 7
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

Fine-tune:

```bash
python -m u1_sentinel_model.train   --base-model Qwen/Qwen2.5-7B-Instruct   --train-file data/train.jsonl   --output-dir artifacts/u1-sentinel-evaluator-v0.1   --load-in-4bit
```

Evaluate:

```bash
python -m u1_sentinel_model.eval   --model artifacts/u1-sentinel-evaluator-v0.1   --eval-file data/eval.jsonl
```

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
  -> evaluator model
  -> bound confirmation
  -> atomic nonce consumption
  -> deterministic pre-effect recheck
  -> executor
  -> receipt
```

A model `allow` can never override deterministic `deny`.

## Base model

The training pipeline is model-agnostic. Pass any compatible Hugging Face causal language model through `--base-model`. Do not assume that a specific checkpoint license permits redistribution of derivative weights; verify the selected model's license before publishing trained artifacts.

## Safety boundary

This project trains a defensive evaluator on authorization-boundary examples. It does not include autonomous exploitation, persistence, credential theft, or unrestricted tool execution.
