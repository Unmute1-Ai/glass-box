from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(*args: str) -> None:
    subprocess.check_call(list(args))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-model",
        default="Qwen/Qwen2.5-1.5B-Instruct",
        help="Use 1.5B for smoke training; move to 7B after pipeline validation.",
    )
    parser.add_argument("--count", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--output-dir", default="/tmp/u1-sentinel-evaluator-v0.1")
    parser.add_argument("--train-file", default="/tmp/u1-sentinel-train.jsonl")
    parser.add_argument("--load-in-4bit", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    train_file = Path(args.train_file)

    run(
        sys.executable,
        "-m",
        "u1_sentinel_model.dataset",
        "--output",
        str(train_file),
        "--count",
        str(args.count),
        "--seed",
        str(args.seed),
    )

    command = [
        sys.executable,
        "-m",
        "u1_sentinel_model.train",
        "--base-model",
        args.base_model,
        "--train-file",
        str(train_file),
        "--output-dir",
        args.output_dir,
    ]
    if args.load_in_4bit:
        command.append("--load-in-4bit")

    run(*command)
    print(f"trained adapter written to {args.output_dir}")


if __name__ == "__main__":
    main()
