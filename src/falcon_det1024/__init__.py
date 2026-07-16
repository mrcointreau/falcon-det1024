"""falcon-det1024: Python bindings for the Algorand deterministic Falcon (det1024)
post-quantum signature scheme.

The top level is the ergonomic API: `FalconSigner`, `FalconVerifier`, the size
constants, and the exception hierarchy. The C-mirroring low-level surface (raw
`*_compressed` / `*_ct` functions, CT conversion, salt-version and coefficient
helpers) lives under `falcon_det1024.bindings`, in the spirit of `nacl.bindings`.

Example
-------
>>> from falcon_det1024 import FalconSigner
>>> signer = FalconSigner.generate(seed=bytes(32))
>>> sig = signer.sign(b"hello world")
>>> signer.verifying_key().verify(b"hello world", sig)  # no exception == valid
"""

from __future__ import annotations

from . import bindings
from .api import FalconSigner, FalconVerifier
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
__version__ = "0.2.0"

__all__ = [
    # version
    "__version__",
    # low-level bindings
    "bindings",
    # classes
    "FalconSigner",
    "FalconVerifier",
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
