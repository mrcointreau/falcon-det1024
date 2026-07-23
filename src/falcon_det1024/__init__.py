"""falcon-det1024: Python bindings for the Algorand deterministic Falcon (det1024)
post-quantum signature scheme.

The surface is deliberately small: generate a keypair, sign, verify. The
C-mirroring layer stays private, so the only supported way to reach a det1024
primitive is through `FalconSigner` or `FalconVerifier`.

Example
-------
>>> from falcon_det1024 import FalconSigner
>>> signer = FalconSigner.generate()
>>> sig = signer.sign(b"hello world")
>>> signer.verifying_key().verify(b"hello world", sig)  # no exception == valid
"""

from __future__ import annotations

from .api import FalconSigner, FalconVerifier
from .constants import (
    COMPRESSED_SIG_MAX_SIZE,
    PRIVATE_KEY_SIZE,
    PUBLIC_KEY_SIZE,
)
from .exceptions import (
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
    # classes
    "FalconSigner",
    "FalconVerifier",
    # constants
    "PUBLIC_KEY_SIZE",
    "PRIVATE_KEY_SIZE",
    "COMPRESSED_SIG_MAX_SIZE",
    # exceptions
    "FalconError",
    "InvalidSignature",
    "KeygenError",
    "SigningError",
]
