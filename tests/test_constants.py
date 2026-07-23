"""The exact det1024 sizes, resolved from the C header macros in API mode."""

from __future__ import annotations

import falcon_det1024 as fp


def test_sizes_match_spec() -> None:
    assert fp.PUBLIC_KEY_SIZE == 1793
    assert fp.PRIVATE_KEY_SIZE == 2305
    assert fp.COMPRESSED_SIG_MAX_SIZE == 1423
