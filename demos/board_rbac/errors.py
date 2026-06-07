"""Board demo exceptions."""

from __future__ import annotations


class BoardError(Exception):
    """Base exception for board demo failures."""


class BoardAuthenticationError(BoardError):
    """Raised when an actor/session cannot be authenticated."""


class BoardAuthorizationError(BoardError):
    """Raised when an actor lacks a required board permission."""


class BoardValidationError(BoardError):
    """Raised when board input/state is invalid."""


class BoardNotFoundError(BoardValidationError):
    """Raised when a board resource is missing."""
