from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def summarize(path: Path) -> dict:
    verdicts = Counter()
    risks = Counter()
    total = 0

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            total += 1
            record = json.loads(line)
            target = json.loads(record["messages"][-1]["content"])
            verdicts[target["verdict"]] += 1
            risks[target["risk"]] += 1

    return {
        "file": path.name,
        "sha256": file_sha256(path),
        "records": total,
        "verdicts": dict(sorted(verdicts.items())),
        "risks": dict(sorted(risks.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = {
        "schema": "u1/sentinel-model-corpus/v1",
        "security_invariant": "MODEL OUTPUT ∉ AUTHORITY",
        "corpora": [summarize(path) for path in args.files],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
