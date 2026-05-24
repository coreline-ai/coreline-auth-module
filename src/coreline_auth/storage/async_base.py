"""Async storage protocol for pooled production adapters."""

from __future__ import annotations

from typing import Protocol

from .async_protocols import AsyncAuditEventStore, AsyncCredentialStore, AsyncHealthCheckStore, AsyncIdentityStore, AsyncLoginFlowStore, AsyncMfaFactorStore, AsyncRecoveryCodeStore, AsyncSessionStore, AsyncUserStore


class AsyncAuthStorage(
    AsyncUserStore,
    AsyncIdentityStore,
    AsyncCredentialStore,
    AsyncLoginFlowStore,
    AsyncSessionStore,
    AsyncAuditEventStore,
    AsyncMfaFactorStore,
    AsyncRecoveryCodeStore,
    AsyncHealthCheckStore,
    Protocol,
):
    """Async equivalent of `AuthStorage` for Postgres/pooled adapters.

    The sync `AuthStorage` protocol remains the stable v0.5 API. This contract
    is additive so production hosts can adopt async Postgres without breaking
    embedded SQLite users.
    """
