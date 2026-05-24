"""Coreline Auth exception hierarchy."""

from __future__ import annotations


class CorelineAuthError(Exception):
    """Base exception for Coreline Auth."""


class AuthConfigurationError(CorelineAuthError, ValueError):
    """Raised when configuration is unsafe or incomplete."""


class AuthValidationError(CorelineAuthError, ValueError):
    """Raised when caller-provided input is invalid."""


class AuthenticationFailed(CorelineAuthError):
    """Raised when credentials or sessions cannot be verified."""


class AuthorizationDenied(CorelineAuthError):
    """Raised when a principal lacks a required permission."""


class StorageError(CorelineAuthError, RuntimeError):
    """Raised by storage adapters."""
