import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import gradio as gr

REPO_URL = "https://github.com/Unmute1-Ai/glass-box.git"
FROZEN_COMMIT = "6f69ff051cc6ef67363cfe4fbb944c93b4a7da22"
RELEASE_DIR = "v2.7-reproducible"


def checkout_release():
    work = Path(tempfile.mkdtemp(prefix="u1-glassbox-"))
    clone = subprocess.run(
        ["git", "clone", "--quiet", "--no-checkout", REPO_URL, str(work)],
        capture_output=True, text=True, timeout=90,
    )
    if clone.returncode:
        raise RuntimeError("Could not obtain public source revision: " + (clone.stderr or clone.stdout)[-2500:])
    checkout = subprocess.run(
        ["git", "-C", str(work), "checkout", "--quiet", "--detach", FROZEN_COMMIT],
        capture_output=True, text=True, timeout=45,
    )
    if checkout.returncode:
        raise RuntimeError("Could not check out pinned release commit: " + (checkout.stderr or checkout.stdout)[-2500:])
    release = work / RELEASE_DIR
    if not (release / "authoritybench.py").is_file() or not (release / "verify_release.py").is_file():
        raise RuntimeError("Pinned source lacks expected v2.7 release files.")
    return work, release


def run_check(mode):
    work = None
    try:
        work, release = checkout_release()
        command = ["python", "authoritybench.py", "--self-test"] if mode == "Self-test (4 unit tests)" else ["python", "verify_release.py"]
        result = subprocess.run(
            command, cwd=str(release), capture_output=True, text=True, timeout=90,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        output = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
        status = "PASS" if result.returncode == 0 else "FAIL"
        summary = f"**{status}** · exit code {result.returncode}\n\n**Source revision:** {FROZEN_COMMIT}\n\n**Command:** {' '.join(command)}"
        if mode == "Self-test (4 unit tests)":
            summary += "\n\nRuns the frozen unit tests only. No live model or production system is contacted."
        else:
            summary += "\n\nChecks package hashes, canonical manifest, detached signature, and unit tests. This is not a production security certification."
        return summary, output[-14000:]
    except Exception as exc:
        return "**ERROR** · execution could not be completed", str(exc)
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)


with gr.Blocks(title="U1 Glass Box Public Test Lab") as demo:
    gr.Markdown("""
# U1 Glass Box · Public Test Lab

Independently reproduce the frozen **U1 Control-Plane Evidence v2.7** package.

This Space checks the exact pinned source revision. It does not run a live model, touch production systems, or establish universal security.

**Read the claims boundary and methodology before interpreting any result.**

- [Claims boundary](https://github.com/Unmute1-Ai/glass-box/blob/6f69ff051cc6ef67363cfe4fbb944c93b4a7da22/v2.7-reproducible/CLAIMS.md)
- [Methodology](https://github.com/Unmute1-Ai/glass-box/blob/6f69ff051cc6ef67363cfe4fbb944c93b4a7da22/v2.7-reproducible/METHODOLOGY.md)
- [Reproduction instructions](https://github.com/Unmute1-Ai/glass-box/blob/6f69ff051cc6ef67363cfe4fbb944c93b4a7da22/v2.7-reproducible/REPRODUCE.md)
- [Submit a reproducible report](https://github.com/Unmute1-Ai/glass-box/issues/new)
""")
    mode = gr.Radio(
        ["Self-test (4 unit tests)", "Full release verification"],
        value="Full release verification",
        label="Choose a reproducible check",
    )
    run = gr.Button("Run verification", variant="primary")
    status = gr.Markdown()
    output = gr.Code(label="Raw execution output", language="shell")
    run.click(run_check, inputs=mode, outputs=[status, output])
    gr.Markdown("""
---
### Scope and safety

- Runs in a temporary checkout of the pinned public repository revision.
- No credentials, personal data, live models, or external targets are used by the benchmark.
- A passing result applies only to this synthetic benchmark and its documented policy.
- Proposed challenge cases are not counted as executed until implemented and independently reproduced.

**Unmute1AI · Accessibility first. Explicit authority. Reproducible evidence.**
""")

if __name__ == "__main__":
    demo.launch()
