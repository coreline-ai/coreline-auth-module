"""Stable sync storage protocol."""

from __future__ import annotations

from typing import Protocol

from .protocols import AuditEventStore, CredentialStore, HealthCheckStore, IdentityStore, LoginFlowStore, MfaFactorStore, RecoveryCodeStore, SessionStore, UserStore


class AuthStorage(
    UserStore,
    IdentityStore,
    CredentialStore,
    LoginFlowStore,
    SessionStore,
    AuditEventStore,
    MfaFactorStore,
    RecoveryCodeStore,
    HealthCheckStore,
    Protocol,
):
    """All-in-one storage contract kept for v0.x API compatibility."""
