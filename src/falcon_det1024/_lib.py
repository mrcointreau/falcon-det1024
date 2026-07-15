"""Internal access to the compiled cffi extension and error-code handling.

`falcon_det1024._falcon` is the compiled extension produced by `_build.py`. Its
`ffi` and `lib` objects are dynamic, so they are typed `Any`; the stub
`_falcon.pyi` declares them.
"""

from __future__ import annotations

from typing import Any

# Import the names directly from the compiled extension. The
# `from . import _falcon` form does not resolve under mypy for a stub-only
# C-extension submodule.
from falcon_det1024._falcon import ffi as _ffi
from falcon_det1024._falcon import lib as _lib

ffi: Any = _ffi
lib: Any = _lib

# Map each negative falcon error code (from falcon.h) to its name.
_ERR_NAMES: dict[int, str] = {
    int(lib.FALCON_ERR_RANDOM): "FALCON_ERR_RANDOM",
    int(lib.FALCON_ERR_SIZE): "FALCON_ERR_SIZE",
    int(lib.FALCON_ERR_FORMAT): "FALCON_ERR_FORMAT",
    int(lib.FALCON_ERR_BADSIG): "FALCON_ERR_BADSIG",
    int(lib.FALCON_ERR_BADARG): "FALCON_ERR_BADARG",
    int(lib.FALCON_ERR_INTERNAL): "FALCON_ERR_INTERNAL",
}


def err_name(code: int) -> str:
    """Return a human-readable name for a falcon error code."""
    return _ERR_NAMES.get(int(code), f"error {int(code)}")
