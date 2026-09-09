from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-model", default="Qwen/Qwen2.5-0.5B-Instruct")
    parser.add_argument("--train-count", type=int, default=96)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--output-dir", default="artifacts/u1-sentinel-smoke-0.5b")
    args = parser.parse_args()

    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        DataCollatorForLanguageModeling,
        Trainer,
        TrainingArguments,
    )

    from u1_sentinel_model.dataset import generate_records

    records = list(generate_records(args.train_count, args.seed))
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    def render(record: dict) -> str:
        messages = record["messages"]
        if getattr(tokenizer, "chat_template", None):
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
            )
        return "\n".join(
            f"<|{m['role']}|>\n{m['content']}" for m in messages
        )

    texts = [render(r) for r in records]
    ds = Dataset.from_dict({"text": texts})

    def tok(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=args.max_length,
            padding=False,
        )

    ds = ds.map(tok, batched=True, remove_columns=["text"])

    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.float32,
        low_cpu_mem_usage=True,
    )
    model.config.use_cache = False
    model.gradient_checkpointing_enable()

    peft_config = LoraConfig(
        r=8,
        lora_alpha=16,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model = get_peft_model(model, peft_config)
    model.print_trainable_parameters()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=str(out),
        num_train_epochs=1,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        learning_rate=2e-4,
        logging_steps=2,
        save_strategy="no",
        report_to="none",
        remove_unused_columns=False,
        seed=args.seed,
        use_cpu=True,
        dataloader_num_workers=0,
        optim="adamw_torch",
    )

    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=ds,
        data_collator=collator,
    )
    result = trainer.train()
    trainer.save_model(str(out))
    tokenizer.save_pretrained(str(out))

    manifest = {
        "schema": "u1/sentinel-smoke-model/v1",
        "base_model": args.base_model,
        "train_count": args.train_count,
        "seed": args.seed,
        "max_length": args.max_length,
        "security_invariant": "MODEL OUTPUT ∉ AUTHORITY",
        "purpose": "pipeline smoke fine-tune; not production security evidence",
        "train_metrics": result.metrics,
    }
    (out / "SMOKE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
