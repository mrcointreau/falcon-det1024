"""Public det1024 constants, resolved from the compiled Falcon headers.

The size constants come straight from the C macros (via the compiler in API
mode), so they can never drift from the vendored library.
"""

from __future__ import annotations

from ._lib import lib

#: Public key length in bytes (FALCON_DET1024_PUBKEY_SIZE).
PUBLIC_KEY_SIZE: int = int(lib.FALCON_DET1024_PUBKEY_SIZE)
#: Private key length in bytes (FALCON_DET1024_PRIVKEY_SIZE).
PRIVATE_KEY_SIZE: int = int(lib.FALCON_DET1024_PRIVKEY_SIZE)
#: Maximum compressed signature length in bytes (actual length is variable).
COMPRESSED_SIG_MAX_SIZE: int = int(lib.FALCON_DET1024_SIG_COMPRESSED_MAXSIZE)
#: Fixed CT-format signature length in bytes.
CT_SIGNATURE_SIZE: int = int(lib.FALCON_DET1024_SIG_CT_SIZE)
#: Current salt version written by this library's signer.
CURRENT_SALT_VERSION: int = int(lib.FALCON_DET1024_CURRENT_SALT_VERSION)
#: log2 of the ring degree (10 for det1024).
LOGN: int = int(lib.FALCON_DET1024_LOGN)
#: Ring degree / number of polynomial coefficients (2**LOGN == 1024).
N: int = 1 << LOGN
#: Seed length in bytes accepted by `FalconSigner.generate`.
SEED_SIZE: int = 32
