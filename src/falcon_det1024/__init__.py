"""falcon-det1024: Python bindings for the Algorand deterministic Falcon (det1024)
post-quantum signature scheme.

Example
-------
>>> from falcon_det1024 import FalconSigner
>>> signer = FalconSigner.generate(seed=bytes(32))
>>> sig = signer.sign(b"hello world")
>>> signer.verifying_key().verify(b"hello world", sig)  # no exception == valid
"""

from __future__ import annotations

from .api import (
    FalconSigner,
    FalconVerifier,
    compressed_to_ct,
    hash_to_point_coeffs,
    pubkey_coeffs,
    s1_coeffs,
    s2_coeffs,
    salt_version,
    verify_falcon1024,
)
from .constants import (
    COMPRESSED_SIG_MAX_SIZE,
    CT_SIGNATURE_SIZE,
    CURRENT_SALT_VERSION,
    LOGN,
    N,
    PRIVATE_KEY_SIZE,
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
)
from .exceptions import (
    ConversionError,
    FalconError,
    InvalidSignature,
    KeygenError,
    SigningError,
)

# Managed by python-semantic-release (version_variables in pyproject.toml).
__version__ = "0.0.0"

__all__ = [
    # version
    "__version__",
    # classes
    "FalconSigner",
    "FalconVerifier",
    # module-level functions
    "verify_falcon1024",
    "compressed_to_ct",
    "salt_version",
    # advanced coefficient helpers
    "pubkey_coeffs",
    "hash_to_point_coeffs",
    "s2_coeffs",
    "s1_coeffs",
    # constants
    "PUBLIC_KEY_SIZE",
    "PRIVATE_KEY_SIZE",
    "COMPRESSED_SIG_MAX_SIZE",
    "CT_SIGNATURE_SIZE",
    "CURRENT_SALT_VERSION",
    "SEED_SIZE",
    "LOGN",
    "N",
    # exceptions
    "FalconError",
    "InvalidSignature",
    "KeygenError",
    "SigningError",
    "ConversionError",
]
