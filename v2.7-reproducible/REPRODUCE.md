# Reproduce v2.7-reproducible

Python 3.10+ is sufficient for the benchmark. Signature verification uses either the `cryptography` package or OpenSSL 3.x.

## 1. Obtain this directory

Clone the repository and enter this directory. Do not mix these files with the frozen `v2.6-enterprise/` tree.

```bash
git clone https://github.com/Unmute1-Ai/glass-box.git
cd glass-box/v2.7-reproducible
```

## 2. (Optional) install the signature library

```bash
python3 -m pip install -r requirements.txt
```

If you skip this step, `verify_release.py` falls back to `openssl pkeyutl -verify -rawin` (OpenSSL 3).

## 3. Run the four unit tests

```bash
python3 authoritybench.py --self-test
```

Expected:

```
Self-test: 4/4 PASS
Policy Authority Lift = 0
Unauthorized Effects  = 0 observed
Audit Integrity       = VALID
```

## 4. Re-generate evidence

```bash
python3 authoritybench.py --run
```

This rewrites `evidence/TEST-RESULTS.txt`, `evidence/comparison.json`, and `evidence/receipts.jsonl`. The bytes are deterministic: same source, same output, same SHA-256.

## 5. Verify hashes and the detached signature

```bash
python3 verify_release.py
```

Expected:

```
Hashes                 = VALID
Canonical manifest     = VALID
Detached Ed25519 sig   = VALID
authoritybench tests   = 4/4 PASS
VERIFY  PASS
```

## 6. Independent hash check (optional)

```bash
sha256sum -c HASHES/SHA256SUMS
```

## 7. Independent signature check (optional, OpenSSL 3)

`KEYS/release-ed25519.pub` holds a 32-byte raw Ed25519 public key as hex. Convert to SPKI PEM if you want to use `openssl` directly; `verify_release.py` already does this conversion.

The signed object is the exact byte string of `MANIFEST.canonical.json` (UTF-8 JSON, sorted keys, compact separators, trailing newline). The signature is the raw 64-byte Ed25519 signature in `SIGNATURES/manifest.ed25519.sig`.

## Canonicalization

`MANIFEST.canonical.json` is:

```text
json.dumps(
    {release_id, created_utc, scope, benchmark, files},
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
) + "\n"
```

`MANIFEST.json` is the same object plus a `signature` block describing where the key and detached signature live. The signature block is not included in the signed bytes.

## What a mismatch means

- Hash mismatch after `--run` → the source you are running is not the frozen source, or the file was edited.
- Signature mismatch with matching hashes → the public key or signature file is not the one that froze this tree.
- Tests failing → do not treat the published numbers as reproduced.

## Boundary

Reproduction validates this package, these scenarios, and this policy. It does not validate production deployments, live models, or the historical v2.6 11,850-action figure.
