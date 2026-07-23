"""Exception hierarchy for falcon-det1024.

All errors derive from `FalconError`. Verification failures raise
`InvalidSignature`. Invalid argument sizes raise the built-in `ValueError`, and
non bytes-like arguments raise `TypeError`.
"""

from __future__ import annotations


class FalconError(Exception):
    """Base class for all falcon-det1024 errors."""


class InvalidSignature(FalconError):
    """Raised when a signature fails verification."""


class KeygenError(FalconError):
    """Raised when key generation or private-key decoding fails."""


class SigningError(FalconError):
    """Raised when signing fails."""
