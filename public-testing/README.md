# U1 Public Testing Program

**Purpose:** Invite independent developers, security researchers, accessibility practitioners, and evaluators to reproduce and challenge the published U1 control-plane evidence.

This program starts with the frozen **v2.7-reproducible** Glass Box package. It is a synthetic, deterministic benchmark using mock adapters. It does not connect to live models, production systems, external services, or real user data.

## Start here

1. Read the [claims boundary](../v2.7-reproducible/CLAIMS.md).
2. Read the [methodology](../v2.7-reproducible/METHODOLOGY.md).
3. Follow the exact [reproduction procedure](../v2.7-reproducible/REPRODUCE.md).
4. Run the benchmark from a clean clone:

```bash
git clone https://github.com/Unmute1-Ai/glass-box.git
cd glass-box/v2.7-reproducible
python3 authoritybench.py --self-test
python3 authoritybench.py --run
python3 verify_release.py
```

Expected frozen-package checks are documented in that release. If your result differs, report the exact output; do not edit the frozen release to make it pass.

## What we want testers to do

- Reproduce the frozen package on a clean machine.
- Inspect the policy, adapter boundary, PhaseFlow transitions, second-principal gate, and receipt hash chain.
- Try to falsify the stated claims within the documented synthetic harness.
- Propose new negative tests and edge cases.
- Review whether the claims are appropriately limited by the evidence.

The existing S01–S18 cases and four unit tests are listed in [METHODOLOGY.md](../v2.7-reproducible/METHODOLOGY.md). Start by attempting to explain or reproduce each result, then propose cases the current suite does not cover.

## Safety and scope

- Test only the checked-in synthetic harness.
- Do not point tests at third-party services, production systems, real accounts, or systems you do not own or have explicit permission to test.
- Do not submit secrets, personal data, private keys, access tokens, or confidential customer information.
- Do not interpret a passing synthetic test as proof of production security.
- Do not describe this package as externally certified, universally secure, or validated against live frontier models.
- For a suspected vulnerability in a live U1 service, use the private reporting instructions in the repository's [SECURITY.md](../SECURITY.md), not a public issue.

## Submit a reproducible report

Open a GitHub issue in this repository using the [External reproduction report](../.github/ISSUE_TEMPLATE/external-reproduction-report.md) template. Include:
- Release ID and commit SHA.
- Operating system and Python version.
- Exact commands run.
- Complete relevant output.
- Whether the repository was modified.
- The smallest reproducible test case for any failure.
- Expected versus observed behavior.

For proposed tests, include the threat model, preconditions, expected authorization decision, expected effect (or explicit no-effect), and how another reviewer can reproduce it.

## Evidence labels

Every report will be classified as one of:
- **Reproduced:** another person reproduced the same result from the stated revision and commands.
- **Not reproduced:** the report could not be reproduced under the stated conditions.
- **New test proposed:** a test case has been submitted but not yet accepted or run.
- **Confirmed defect:** a defect has been reproduced and its scope documented.
- **Out of scope:** the report requires live systems, unauthorized access, or evidence not present in this package.

A report or issue is not an endorsement. External participation does not equal independent certification.

## Contributing

Read [CONTRIBUTING.md](../CONTRIBUTING.md). Preserve frozen evidence. New tests belong in a new versioned release or review branch; never silently rewrite historical results.

**Unmute1AI · Accessibility first. Explicit authority. Reproducible evidence.**
