# 3. Defer free-threaded wheels

Date: 2026-07-14

## Status

Accepted

## Context

Free-threaded CPython (PEP 703, `Py_GIL_DISABLED`) has no stable ABI before PEP 803 and CPython 3.15, so abi3 cannot cover it today. cffi >= 2.0 handles a free-threaded build by producing a full-tagged, version-specific extension instead of abi3. cibuildwheel 4.x removed the `cpython-freethreading` enable flag and the experimental cp313t builds, and now builds free-threaded cp314t by default. We have no free-threaded interpreter to test against locally, and the det1024 functions are pure and stateless (so they are expected to be thread-safe, but that is unverified here).

## Decision

Do not ship free-threaded wheels in v1. The `build = "cp39-*"` cibuildwheel selector already excludes `cp314t-*`. Keep the conditional `setup.py` and cffi machinery in place, which already produces a correct full-tagged (non-abi3) wheel on a free-threaded build, so enabling the wheels later is a one-line change.

## Consequences

There are no `cp314t` wheels for now; free-threaded users install from the sdist and compile locally. To enable free-threaded wheels later, add `"cp314t-*"` to the cibuildwheel `build` selector, validate on a free-threaded runner, and supersede this ADR. Shipping an untested free-threaded artifact is worse than not shipping one, so this trades coverage for correctness in v1.
