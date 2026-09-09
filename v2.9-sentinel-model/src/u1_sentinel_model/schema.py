from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Mapping


VERDICTS = {"allow", "deny", "manual_review"}
RISKS = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class ProposalCase:
    proposal_id: str
    principal_id: str
    authenticated_principal_id: str
    kind: str
    resources: tuple[str, ...]
    allowed_scope: tuple[str, ...]
    diff_digest: str
    confirmation_digest: str
    destructive: bool
    persistence: bool
    nonce_replayed: bool
    confirmation_expired: bool
    deterministic_policy: str
    resource_owner_principal_id: str | None = None
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("resources", "allowed_scope", "notes"):
            data[key] = list(data[key])
        return data

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProposalCase":
        return cls(
            proposal_id=str(value["proposal_id"]),
            principal_id=str(value["principal_id"]),
            authenticated_principal_id=str(value["authenticated_principal_id"]),
            kind=str(value["kind"]),
            resources=tuple(str(x) for x in value["resources"]),
            allowed_scope=tuple(str(x) for x in value["allowed_scope"]),
            diff_digest=str(value["diff_digest"]),
            confirmation_digest=str(value["confirmation_digest"]),
            destructive=bool(value["destructive"]),
            persistence=bool(value["persistence"]),
            nonce_replayed=bool(value["nonce_replayed"]),
            confirmation_expired=bool(value["confirmation_expired"]),
            deterministic_policy=str(value["deterministic_policy"]),
            resource_owner_principal_id=(
                None
                if value.get("resource_owner_principal_id") is None
                else str(value["resource_owner_principal_id"])
            ),
            notes=tuple(str(x) for x in value.get("notes", [])),
        )


@dataclass(frozen=True)
class Evaluation:
    verdict: str
    risk: str
    findings: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"invalid verdict: {self.verdict}")
        if self.risk not in RISKS:
            raise ValueError(f"invalid risk: {self.risk}")
        if not self.findings or any(not f.strip() for f in self.findings):
            raise ValueError("findings must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "risk": self.risk,
            "findings": list(self.findings),
        }
