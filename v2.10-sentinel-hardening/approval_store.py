"""Single-host durable approval store; no public approval-issuance endpoint.

Only trusted approval-service code may call issue(). Protect the DB and its
directory with OS permissions. All worker processes must share the same DB.
SQLite WAL must be on a supported local filesystem, not a network share.
"""
from __future__ import annotations

import asyncio
import hashlib
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel_control import Confirmation


def utcnow():
    return datetime.now(timezone.utc)


class SQLiteApprovalStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path == ':memory:':
            raise ValueError('durable_database_required')
        with closing(self._connect()) as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('''CREATE TABLE IF NOT EXISTS approvals (
                token_hash TEXT PRIMARY KEY,
                principal TEXT NOT NULL,
                digest TEXT NOT NULL,
                expiry TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
            )''')
            conn.commit()

    def _connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def issue(self, *, principal_id: str, proposal_digest: str,
              ttl_seconds: int = 60) -> Confirmation:
        """Trusted approval path ONLY, after authenticating the approver.

        This adapter stores approval; it does not authenticate or authorize it.
        Never expose this method directly to an agent or request body.
        """
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
            raise ValueError('invalid_approval_ttl')
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise ValueError('invalid_principal')
        if (not isinstance(proposal_digest, str)
            or len(proposal_digest) != 71
            or not proposal_digest.startswith('sha256:')
            or any(c not in '0123456789abcdef' for c in proposal_digest[7:])):
            raise ValueError('invalid_proposal_digest')
        token = secrets.token_urlsafe(32)
        expiry = utcnow() + timedelta(seconds=ttl_seconds)
        with closing(self._connect()) as conn:
            conn.execute('INSERT INTO approvals(token_hash,principal,digest,expiry) VALUES(?,?,?,?)',
                         (self._hash(token), principal_id, proposal_digest, expiry.isoformat()))
            conn.commit()
        return Confirmation(principal_id, proposal_digest, token, expiry)

    @staticmethod
    def _hash(token):
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    async def consume_once(self, nonce, *, principal_id, proposal_digest, expires_at):
        return await asyncio.to_thread(self._consume, nonce, principal_id,
                                       proposal_digest, expires_at)

    def _consume(self, nonce, principal_id, proposal_digest, expires_at):
        if (not isinstance(nonce, str) or not 32 <= len(nonce) <= 128
            or not isinstance(expires_at, datetime)
            or expires_at.utcoffset() is None):
            return False
        try:
            with closing(self._connect()) as conn:
                # Acquire the write lock BEFORE reading time: a lock wait can
                # expire an otherwise valid token. Persist consumption atomically.
                conn.execute('BEGIN IMMEDIATE')
                if expires_at <= utcnow():
                    conn.rollback()
                    return False
                result = conn.execute('''UPDATE approvals SET consumed=1
                    WHERE token_hash=? AND principal=? AND digest=?
                    AND expiry=? AND consumed=0''',
                    (self._hash(nonce), principal_id, proposal_digest,
                     expires_at.astimezone(timezone.utc).isoformat()))
                conn.commit()
                return result.rowcount == 1
        except sqlite3.Error:
            # Missing schema, database outage, or lock timeout cannot grant access.
            return False
