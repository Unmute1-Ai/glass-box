"""AAT v11 completeness-claim verifier and bounded OAuth-agent grant checks.

This is a standard-library-only synthetic evaluator. It is NOT a production
AAT implementation, JCS implementation, signature provider, OAuth client, or
identity provider. The caller must supply a cryptographic signature verifier.
The canonical JSON helper intentionally accepts only the JSON subset used by
these fixtures; production interoperability requires full RFC 8785 JCS.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping


class VerificationError(ValueError):
    pass


def _canonical_fixture_json(value: Any) -> bytes:
    """Deterministic fixture encoding; not a general RFC 8785 implementation."""
    def validate(item: Any) -> None:
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            raise VerificationError("floating_point_not_supported_by_fixture_canonicalizer")
        if isinstance(item, list):
            for child in item:
                validate(child)
            return
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise VerificationError("object_keys_must_be_strings")
            for child in item.values():
                validate(child)
            return
        raise VerificationError("unsupported_json_value")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(records: Iterable[Mapping[str, Any]]) -> str:
    """RFC 6962 Merkle root: 0x00-prefixed leaves, 0x01-prefixed nodes.

    Records are supplied in their required ("timestamp", "prev_hash") order.
    AAT says an odd final node is promoted unchanged.
    """
    items = list(records)
    if not items:
        raise VerificationError("empty_record_set")
    leaves = []
    for record in items:
        body = dict(record)
        body.pop("batch", None)
        leaves.append(_sha256(b"\x00" + _canonical_fixture_json(body)))
    level = leaves
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            if index + 1 == len(level):
                next_level.append(level[index])
            else:
                next_level.append(_sha256(b"\x01" + level[index] + level[index + 1]))
        level = next_level
    return level[0].hex()


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise VerificationError("timestamp_must_be_rfc3339_string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError("invalid_timestamp") from exc
    if parsed.tzinfo is None:
        raise VerificationError("timestamp_must_include_timezone")
    return parsed.astimezone(timezone.utc)


def _in_scope(record: Mapping[str, Any], scope: Mapping[str, Any], as_of: datetime) -> bool:
    stamp = _parse_time(record.get("timestamp"))
    if stamp > as_of:
        return False
    agent_ids = scope.get("agent_ids")
    if agent_ids is not None and record.get("agent_id") not in agent_ids:
        return False
    session_ids = scope.get("session_ids")
    if session_ids is not None and record.get("session_id") not in session_ids:
        return False
    start = scope.get("from")
    end = scope.get("to")
    if start is not None and stamp < _parse_time(start):
        return False
    if end is not None and stamp > _parse_time(end):
        return False
    return True


def verify_completeness_statement(
    records: Iterable[Mapping[str, Any]],
    statement: Mapping[str, Any],
    *,
    verify_signature: Callable[[Mapping[str, Any]], bool],
) -> dict[str, Any]:
    """Verify signature via caller callback, scope, count, and Merkle set digest.

    The callback must verify the statement's actual signature and signer trust.
    A true callback in unit tests is only a fixture; it is not cryptographic
    validation. This function cannot prove that the custodian disclosed every
    record it produced; later discovery of an omitted in-scope record falsifies
    the claim, as described by AAT v11 Section 14.7.
    """
    if not verify_signature(statement):
        raise VerificationError("statement_signature_invalid")
    if statement.get("action_type") != "lifecycle":
        raise VerificationError("wrong_statement_action_type")
    detail = statement.get("action_detail")
    if not isinstance(detail, dict) or detail.get("event") != "completeness_statement":
        raise VerificationError("wrong_statement_event")
    scope = detail.get("scope")
    if not isinstance(scope, dict) or not scope:
        raise VerificationError("missing_scope")
    as_of = _parse_time(detail.get("as_of"))
    selected = [dict(r) for r in records if _in_scope(r, scope, as_of)]
    selected.sort(key=lambda r: (_parse_time(r.get("timestamp")), str(r.get("prev_hash", ""))))
    count = detail.get("record_count")
    if type(count) is not int or count < 0:
        raise VerificationError("invalid_record_count")
    if count != len(selected):
        raise VerificationError("record_count_mismatch")
    digest = detail.get("set_digest")
    if not isinstance(digest, str) or digest != merkle_root(selected):
        raise VerificationError("set_digest_mismatch")
    return {
        "signature_verified": True,
        "scope_count_verified": True,
        "record_count": len(selected),
        "set_digest": digest,
        "absence_reasoning_permitted_only_within_verified_scope": True,
    }


def validate_agent_oauth_grant(
    grant: Mapping[str, Any],
    *,
    expected_issuer: str,
    expected_client_id: str,
    principal_id: str,
    allowed_scopes: set[str],
    remote_session_approved: bool = False,
) -> None:
    """Synthetic policy check for agent OAuth grants; not an OAuth protocol stack."""
    if grant.get("issuer") != expected_issuer:
        raise VerificationError("oauth_issuer_mismatch")
    if grant.get("client_id") != expected_client_id:
        raise VerificationError("oauth_client_mismatch")
    if grant.get("principal_id") != principal_id:
        raise VerificationError("oauth_principal_mismatch")
    scopes = grant.get("scopes")
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        raise VerificationError("oauth_scopes_invalid")
    if len(scopes) != len(set(scopes)):
        raise VerificationError("oauth_duplicate_scope")
    if not set(scopes).issubset(allowed_scopes):
        raise VerificationError("oauth_scope_escalation")
    if grant.get("remote_session") is True and not remote_session_approved:
        raise VerificationError("remote_session_not_separately_approved")
    expiry = _parse_time(grant.get("expires_at"))
    if expiry <= datetime.now(timezone.utc):
        raise VerificationError("oauth_grant_expired")
