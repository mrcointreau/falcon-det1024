"""Known-answer tests (KATs) reproduced from the vendored Falcon test vectors.

These lock in the deterministic, emulated-FP build configuration: if the C were
built with native FP or SIMD, or the bindings marshalled anything incorrectly,
the byte-exact signatures would diverge.

The procedure follows `vendor/falcon/tests/test_deterministic.c`. For each index
`i` (which is also the message length):

  - the message is `i` bytes squeezed from a SHAKE256 PRNG seeded with the ASCII
    string `"msg-%04d" % i`;
  - the keypair is generated from a SHAKE256 PRNG seeded with `"key-%04d" % i`;
  - `sign_compressed` must reproduce `FALCON_DET1024_KAT[i]`;
  - `bindings.convert_compressed_to_ct` must reproduce `FALCON_DET1024_KAT_CT[i]`.

The KAT seeds are 8 bytes (not the public 32-byte seed), so keygen and message
generation use the low-level `_falcon` shake primitives directly.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import falcon_det1024 as fp
from falcon_det1024 import _falcon
from falcon_det1024 import constants as C


def find_kat_header() -> Path | None:
    """Locate the vendored KAT header by searching upward from this file.

    Return `None` when running against an installed wheel with no repo checkout
    (the vendored submodule is not present), so these tests skip.
    """
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / "vendor" / "falcon" / "tests" / "test_deterministic_kat.h"
        if candidate.is_file():
            return candidate
    return None


_KAT_HEADER = find_kat_header()
pytestmark = pytest.mark.skipif(
    _KAT_HEADER is None,
    reason="vendored KAT header not found (running without the falcon submodule)",
)

# Number of vectors, matching NUM_KATS / NUM_KATS_CT in test_deterministic.c.
NUM_KATS = 512
NUM_KATS_CT = 32

_lib = _falcon.lib
_ffi = _falcon.ffi


def _load_kats() -> tuple[list[str], list[str]]:
    assert _KAT_HEADER is not None
    text = _KAT_HEADER.read_text()

    def extract(name: str) -> list[str]:
        m = re.search(rf"{name}\[\]\s*=\s*\{{(.*?)\}};", text, re.DOTALL)
        assert m is not None, f"array {name} not found in KAT header"
        return re.findall(r'"([0-9a-fA-F]+)"', m.group(1))

    return extract("FALCON_DET1024_KAT"), extract("FALCON_DET1024_KAT_CT")


# Only parse the header when it exists; otherwise the module-level `skipif`
# above handles the skip. (Loading unconditionally would raise at import time
# and turn the intended skip into a collection ERROR.)
_KAT, _KAT_CT = _load_kats() if _KAT_HEADER is not None else ([], [])


def _prng(seed: bytes):  # type: ignore[no-untyped-def]
    rng = _ffi.new("shake256_context *")
    _lib.shake256_init_prng_from_seed(rng, seed, len(seed))
    return rng


def _message(i: int) -> bytes:
    if i == 0:
        return b""
    rng = _prng(f"msg-{i:04d}".encode("ascii"))
    buf = _ffi.new("uint8_t[]", i)
    _lib.shake256_extract(rng, buf, i)
    return bytes(_ffi.buffer(buf, i))


def _keypair(i: int) -> tuple[bytes, bytes]:
    rng = _prng(f"key-{i:04d}".encode("ascii"))
    priv = _ffi.new("uint8_t[]", C.PRIVATE_KEY_SIZE)
    pub = _ffi.new("uint8_t[]", C.PUBLIC_KEY_SIZE)
    rc = int(_lib.falcon_det1024_keygen(rng, priv, pub))
    assert rc == 0, f"keygen failed for KAT {i}: rc={rc}"
    return (
        bytes(_ffi.buffer(priv, C.PRIVATE_KEY_SIZE)),
        bytes(_ffi.buffer(pub, C.PUBLIC_KEY_SIZE)),
    )


def test_kat_counts() -> None:
    assert len(_KAT) == NUM_KATS
    assert len(_KAT_CT) == NUM_KATS_CT


def test_kat_compressed_signatures() -> None:
    """All 512 compressed KATs reproduce byte-exactly (and verify)."""
    for i in range(NUM_KATS):
        message = _message(i)
        priv, pub = _keypair(i)
        signer = fp.FalconSigner(priv, pub)
        sig = signer.sign(message)
        assert sig.hex() == _KAT[i], f"compressed KAT mismatch at index {i}"
        # sanity: the reproduced signature also verifies
        signer.verifying_key().verify(message, sig)


def test_kat_ct_signatures() -> None:
    """The first 32 CT KATs reproduce byte-exactly."""
    for i in range(NUM_KATS_CT):
        message = _message(i)
        priv, pub = _keypair(i)
        sig = fp.FalconSigner(priv, pub).sign(message)
        ct = fp.bindings.convert_compressed_to_ct(sig)
        assert ct.hex() == _KAT_CT[i], f"CT KAT mismatch at index {i}"
