"""Exception hierarchy for falcon-det1024.

All errors derive from `FalconError`. Verification failures raise
`InvalidSignature`. Invalid argument sizes and types raise the built-in
`ValueError`.
"""

from __future__ import annotations


class FalconError(Exception):
    """Base class for all falcon-det1024 errors."""


class InvalidSignature(FalconError):
    """Raised when a signature fails verification."""


class KeygenError(FalconError):
    """Raised when key generation fails (e.g. the OS RNG is unavailable)."""


class SigningError(FalconError):
    """Raised when signing fails."""


class ConversionError(FalconError):
    """Raised when converting a signature between formats fails."""
