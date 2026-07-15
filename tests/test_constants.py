"""The exact det1024 sizes, resolved from the C header macros in API mode."""

from __future__ import annotations

import falcon_det1024 as fp


def test_sizes_match_spec() -> None:
    assert fp.PUBLIC_KEY_SIZE == 1793
    assert fp.PRIVATE_KEY_SIZE == 2305
    assert fp.COMPRESSED_SIG_MAX_SIZE == 1423
    assert fp.CT_SIGNATURE_SIZE == 1538
    assert fp.SEED_SIZE == 32
    assert fp.CURRENT_SALT_VERSION == 0
    assert fp.LOGN == 10
    assert fp.N == 1024
    assert fp.N == 1 << fp.LOGN
