"""Minimal setup shim for the cffi C extension.

Almost all metadata lives in `pyproject.toml`. This file exists only to:

1. Register the cffi build (`cffi_modules`), which appends the compiled
   `falcon_det1024._falcon` extension to the distribution. cffi provides this
   `setup()` keyword via a setuptools entry point, so `cffi` must be in
   `[build-system].requires`.

2. Set the `bdist_wheel.py_limited_api` (abi3) wheel tag conditionally. It
   cannot be a static `[tool.distutils.bdist_wheel]` entry, because setuptools
   raises if `py_limited_api` is set while building on a free-threaded
   (`Py_GIL_DISABLED`) interpreter, which has no stable ABI. Those interpreters
   get a normal, version-specific (full-tagged) wheel; every other build gets a
   single `cp310-abi3` wheel per platform.
"""

import sysconfig

from setuptools import setup

options = {}
if not sysconfig.get_config_var("Py_GIL_DISABLED"):
    # Match the Py_LIMITED_API floor: build on cp310, tag as cp310-abi3.
    options["bdist_wheel"] = {"py_limited_api": "cp310"}

setup(
    cffi_modules=["src/falcon_det1024/_build.py:ffibuilder"],
    options=options,
)
