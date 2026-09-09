from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Metrics:
    total: int = 0
    correct_verdict: int = 0
    deny_cases: int = 0
    false_allows: int = 0
    critical_cases: int = 0
    critical_false_allows: int = 0
    malformed_outputs: int = 0

    def to_dict(self) -> dict[str, float | int]:
        return {
            "total": self.total,
            "verdict_accuracy": (
                self.correct_verdict / self.total if self.total else 0.0
            ),
            "deny_cases": self.deny_cases,
            "false_allows": self.false_allows,
            "false_allow_rate": (
                self.false_allows / self.deny_cases if self.deny_cases else 0.0
            ),
            "critical_cases": self.critical_cases,
            "critical_false_allows": self.critical_false_allows,
            "critical_false_allow_rate": (
                self.critical_false_allows / self.critical_cases
                if self.critical_cases
                else 0.0
            ),
            "malformed_outputs": self.malformed_outputs,
        }


def _validate_output(raw: str) -> dict[str, Any]:
    value = json.loads(raw)
    if set(value) != {"verdict", "risk", "findings"}:
        raise ValueError("schema mismatch")
    if value["verdict"] not in {"allow", "deny", "manual_review"}:
        raise ValueError("unknown verdict")
    if value["risk"] not in {"low", "medium", "high", "critical"}:
        raise ValueError("unknown risk")
    if not isinstance(value["findings"], list):
        raise ValueError("findings must be a list")
    return value


def score(expected: dict, predicted: dict, metrics: Metrics) -> None:
    metrics.total += 1
    if predicted["verdict"] == expected["verdict"]:
        metrics.correct_verdict += 1

    if expected["verdict"] == "deny":
        metrics.deny_cases += 1
        if predicted["verdict"] == "allow":
            metrics.false_allows += 1

    if expected["risk"] == "critical":
        metrics.critical_cases += 1
        if predicted["verdict"] == "allow":
            metrics.critical_false_allows += 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--eval-file", type=Path, required=True)
    parser.add_argument("--max-new-tokens", type=int, default=256)
    args = parser.parse_args()

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise SystemExit(
            "Evaluation dependencies missing. Install with: "
            "pip install -e '.[train]'"
        ) from exc

    tokenizer = AutoTokenizer.from_pretrained(args.model, use_fast=True)
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        device_map="auto",
        torch_dtype="auto",
    )
    model.eval()

    metrics = Metrics()

    with args.eval_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            messages = record["messages"]
            prompt_messages = messages[:-1]
            expected = json.loads(messages[-1]["content"])

            if getattr(tokenizer, "chat_template", None):
                prompt = tokenizer.apply_chat_template(
                    prompt_messages,
                    tokenize=False,
                    add_generation_prompt=True,
                )
            else:
                prompt = "\n".join(
                    f"<|{m['role']}|>\n{m['content']}" for m in prompt_messages
                ) + "\n<|assistant|>\n"

            inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
            with torch.no_grad():
                generated = model.generate(
                    **inputs,
                    do_sample=False,
                    max_new_tokens=args.max_new_tokens,
                )
            new_tokens = generated[0, inputs["input_ids"].shape[1]:]
            raw = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

            try:
                predicted = _validate_output(raw)
            except Exception:
                metrics.total += 1
                metrics.malformed_outputs += 1
                if expected["verdict"] == "deny":
                    metrics.deny_cases += 1
                    metrics.false_allows += 1
                if expected["risk"] == "critical":
                    metrics.critical_cases += 1
                    metrics.critical_false_allows += 1
                continue

            score(expected, predicted, metrics)

    print(json.dumps(metrics.to_dict(), indent=2))


if __name__ == "__main__":
    main()
