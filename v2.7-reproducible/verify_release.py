#!/usr/bin/env python3
"""Verify the v2.7-reproducible evidence package.

Checks:
  1. SHA-256 of every file listed in MANIFEST.json / HASHES/SHA256SUMS
  2. Detached Ed25519 signature over MANIFEST.canonical.json
  3. Re-run of authoritybench.py --self-test (optional, default on)

Stdlib-only for hashes. Signature verification uses the `cryptography`
package if installed, otherwise OpenSSL 3.x (`openssl pkeyutl`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CANONICAL_NAME = "MANIFEST.canonical.json"
MANIFEST_NAME = "MANIFEST.json"
SUMS_NAME = Path("HASHES") / "SHA256SUMS"
PUB_NAME = Path("KEYS") / "release-ed25519.pub"
SIG_NAME = Path("SIGNATURES") / "manifest.ed25519.sig"

HASHED_FILES = [
    "CLAIMS.md",
    "METHODOLOGY.md",
    "README.md",
    "REPRODUCE.md",
    "authoritybench.py",
    "evidence/TEST-RESULTS.txt",
    "evidence/comparison.json",
    "evidence/receipts.jsonl",
    "requirements.txt",
    "verify_release.py",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_sums(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, rest = line.partition("  ")
        if not rest:
            digest, _, rest = line.partition(" ")
        out[rest.strip()] = digest.strip()
    return out


def parse_pub(path: Path) -> bytes:
    """Accept raw-32-byte-hex, optional `ed25519:hex:` prefix, or PEM."""
    text = path.read_text(encoding="utf-8").strip()
    if "BEGIN PUBLIC KEY" in text:
        return text.encode("ascii")
    hex_line = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("ed25519:hex:"):
            hex_line = line.split(":", 2)[2]
        else:
            hex_line = line
        break
    raw = bytes.fromhex(hex_line)
    if len(raw) != 32:
        raise ValueError(f"expected 32-byte Ed25519 public key, got {len(raw)}")
    return raw


def verify_ed25519(pub: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        raise ValueError(f"expected 64-byte Ed25519 signature, got {len(signature)}")
    if len(pub) == 32:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature

            key = Ed25519PublicKey.from_public_bytes(pub)
            try:
                key.verify(signature, message)
                return True
            except InvalidSignature:
                return False
        except ImportError:
            return verify_ed25519_openssl(pub, message, signature)
    raise ValueError("unsupported public key encoding")


def verify_ed25519_openssl(pub_raw: bytes, message: bytes, signature: bytes) -> bool:
    import tempfile

    # SPKI prefix for Ed25519 (RFC 8410) + 32-byte raw key, DER, then PEM.
    spki = bytes.fromhex("302a300506032b6570032100") + pub_raw
    import base64

    b64 = base64.encodebytes(spki).decode("ascii")
    pem = "-----BEGIN PUBLIC KEY-----\n" + b64 + "-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        (td_path / "pub.pem").write_text(pem, encoding="ascii")
        (td_path / "msg").write_bytes(message)
        (td_path / "sig").write_bytes(signature)
        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(td_path / "pub.pem"),
                "-rawin",
                "-in",
                str(td_path / "msg"),
                "-sigfile",
                str(td_path / "sig"),
            ],
            capture_output=True,
            text=True,
        )
        return proc.returncode == 0


def check_hashes(manifest: dict) -> list[str]:
    errors: list[str] = []
    listed = manifest.get("files", {})
    sums = parse_sums(HERE / SUMS_NAME)
    for rel in HASHED_FILES:
        path = HERE / rel
        if not path.is_file():
            errors.append(f"missing file: {rel}")
            continue
        digest = sha256_file(path)
        expected_m = listed.get(rel)
        expected_s = sums.get(rel)
        if expected_m and digest != expected_m:
            errors.append(f"MANIFEST mismatch: {rel}")
        if expected_s and digest != expected_s:
            errors.append(f"SHA256SUMS mismatch: {rel}")
        if expected_m is None:
            errors.append(f"not in MANIFEST.json files: {rel}")
        if expected_s is None:
            errors.append(f"not in SHA256SUMS: {rel}")
    return errors


def check_canonical(manifest: dict) -> list[str]:
    errors: list[str] = []
    path = HERE / CANONICAL_NAME
    if not path.is_file():
        return [f"missing {CANONICAL_NAME}"]
    canonical = json.loads(path.read_text(encoding="utf-8"))
    # Canonical object is the manifest minus the signature block, RFC-8785-ish.
    expected = {k: manifest[k] for k in ("release_id", "created_utc", "scope", "benchmark", "files")}
    got_bytes = path.read_bytes()
    want_bytes = json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    if got_bytes != want_bytes:
        errors.append("MANIFEST.canonical.json is not the canonical serialization of MANIFEST.json minus signature")
    if canonical != expected:
        errors.append("MANIFEST.canonical.json JSON value does not match MANIFEST.json body")
    return errors


def check_signature() -> list[str]:
    errors: list[str] = []
    pub_path = HERE / PUB_NAME
    sig_path = HERE / SIG_NAME
    msg_path = HERE / CANONICAL_NAME
    for p, label in ((pub_path, "public key"), (sig_path, "signature"), (msg_path, "canonical manifest")):
        if not p.is_file():
            errors.append(f"missing {label}: {p.relative_to(HERE)}")
    if errors:
        return errors
    try:
        pub = parse_pub(pub_path)
        sig = sig_path.read_bytes()
        msg = msg_path.read_bytes()
        if not verify_ed25519(pub, msg, sig):
            errors.append("Ed25519 signature INVALID")
    except Exception as exc:
        errors.append(f"signature verification error: {exc}")
    return errors


def rerun_tests() -> list[str]:
    proc = subprocess.run(
        [sys.executable, str(HERE / "authoritybench.py"), "--self-test"],
        capture_output=True,
        text=True,
        cwd=str(HERE),
    )
    if proc.returncode != 0:
        return ["authoritybench.py --self-test failed\n" + proc.stdout + proc.stderr]
    if "4/4 PASS" not in proc.stdout and "Self-test: 4/4 PASS" not in proc.stdout:
        return ["authoritybench.py did not report 4/4 PASS"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify v2.7-reproducible release")
    parser.add_argument("--skip-tests", action="store_true", help="do not re-run authoritybench")
    args = parser.parse_args(argv)

    manifest_path = HERE / MANIFEST_NAME
    if not manifest_path.is_file():
        print("FAIL  missing MANIFEST.json", file=sys.stderr)
        return 1
    manifest = load_json(manifest_path)

    errors: list[str] = []
    errors += check_hashes(manifest)
    errors += check_canonical(manifest)
    errors += check_signature()
    if not args.skip_tests:
        errors += rerun_tests()

    print(f"release_id: {manifest.get('release_id')}")
    print(f"created_utc: {manifest.get('created_utc')}")
    bench = manifest.get("benchmark", {})
    print(f"unit_tests: {bench.get('unit_tests')}")
    print(f"policy_authority_lift: {bench.get('policy_authority_lift')}")
    print(f"unauthorized_effects_observed: {bench.get('unauthorized_effects_observed')}")
    print(f"audit_integrity: {bench.get('audit_integrity')}")
    print()
    if errors:
        print("VERIFY  FAIL")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("Hashes                 = VALID")
    print("Canonical manifest     = VALID")
    print("Detached Ed25519 sig   = VALID")
    if not args.skip_tests:
        print("authoritybench tests   = 4/4 PASS")
    print()
    print("VERIFY  PASS")
    print()
    print("Boundary: these checks validate this package under its frozen")
    print("policy/scenario configuration. They are not a certification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
