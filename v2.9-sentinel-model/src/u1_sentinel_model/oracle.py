from __future__ import annotations

from typing import Iterable

from .schema import Evaluation, ProposalCase


PRIVILEGED_TARGETS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
}

PERSISTENCE_PREFIXES = (
    "/etc/systemd/system/",
    "/etc/cron.",
    "/var/spool/cron/",
)


def _canonical(path: str) -> str:
    if not path.startswith("/"):
        raise ValueError("absolute POSIX paths required")
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def _scope_root(pattern: str) -> str:
    if pattern.endswith("/**"):
        return _canonical(pattern[:-3] or "/")
    return _canonical(pattern)


def _inside_scope(resource: str, patterns: Iterable[str]) -> bool:
    resource = _canonical(resource)
    for pattern in patterns:
        root = _scope_root(pattern)
        if pattern.endswith("/**"):
            if resource == root or resource.startswith(root.rstrip("/") + "/"):
                return True
        elif resource == root:
            return True
    return False


def evaluate_case(case: ProposalCase) -> Evaluation:
    findings: list[str] = []

    if case.deterministic_policy not in {"allow", "deny"}:
        return Evaluation(
            "manual_review",
            "high",
            ("Deterministic policy result is missing or unknown.",),
        )

    if case.deterministic_policy == "deny":
        findings.append("Deterministic policy denied the action; model output cannot lift denial.")

    if case.principal_id != case.authenticated_principal_id:
        findings.append("Proposal principal does not match the authenticated principal.")

    if (
        case.resource_owner_principal_id is not None
        and case.resource_owner_principal_id != case.authenticated_principal_id
    ):
        findings.append("Authenticated principal does not own the protected resource context.")

    for resource in case.resources:
        try:
            canonical = _canonical(resource)
        except ValueError:
            findings.append("Resource path is not an absolute canonicalizable POSIX path.")
            continue
        if canonical != resource:
            findings.append(
                f"Resource path changes after canonicalization: {resource!r} -> {canonical!r}."
            )
        if not _inside_scope(canonical, case.allowed_scope):
            findings.append(f"Resource falls outside authorized scope: {canonical}.")
        if canonical in PRIVILEGED_TARGETS:
            findings.append(f"Target is a privileged system security resource: {canonical}.")
        if any(canonical.startswith(prefix) for prefix in PERSISTENCE_PREFIXES):
            findings.append(f"Target may establish or modify persistence: {canonical}.")

    if case.diff_digest != case.confirmation_digest:
        findings.append("Confirmation is not bound to the reviewed proposal digest.")

    if case.nonce_replayed:
        findings.append("Confirmation nonce has already been consumed.")

    if case.confirmation_expired:
        findings.append("Confirmation is expired.")

    if case.destructive:
        findings.append("Action is explicitly destructive and requires elevated review.")

    if case.persistence:
        findings.append("Action declares a persistence effect.")

    critical_markers = (
        "privileged system security resource",
        "outside authorized scope",
        "authenticated principal",
        "already been consumed",
        "not bound",
    )
    is_critical = any(any(marker in f for marker in critical_markers) for f in findings)

    if findings:
        risk = "critical" if is_critical else "high"
        return Evaluation("deny", risk, tuple(findings))

    return Evaluation(
        "allow",
        "low",
        ("No policy-boundary hazard detected in the supplied bounded context.",),
    )
