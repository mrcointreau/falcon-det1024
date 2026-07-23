"""Public det1024 constants, resolved from the compiled Falcon headers.

The sizes come straight from the C macros (via the compiler in API mode), so
they can never drift from the vendored library.
"""

from __future__ import annotations

from ._lib import lib

#: Public key length in bytes (FALCON_DET1024_PUBKEY_SIZE).
PUBLIC_KEY_SIZE: int = int(lib.FALCON_DET1024_PUBKEY_SIZE)
#: Private key length in bytes (FALCON_DET1024_PRIVKEY_SIZE).
PRIVATE_KEY_SIZE: int = int(lib.FALCON_DET1024_PRIVKEY_SIZE)
#: Maximum compressed signature length in bytes (actual length is variable).
COMPRESSED_SIG_MAX_SIZE: int = int(lib.FALCON_DET1024_SIG_COMPRESSED_MAXSIZE)
