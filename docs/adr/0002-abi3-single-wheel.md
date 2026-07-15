# 2. Ship a single abi3 wheel per platform

Date: 2026-07-14

## Status

Accepted

## Context

Without the CPython stable ABI (abi3), we would build one wheel per (Python minor version x platform), which multiplies the build matrix and the artifacts to test and publish. We want one wheel per platform that works on CPython 3.9 and later. abi3 has two independent layers that must agree: the compiled extension (the `.so` must be built against the limited API) and the wheel tag (`cpXY-abi3`).

## Decision

Ship abi3 wheels. Leave Layer 1 (the extension) to cffi >= 2.0, which sets `Py_LIMITED_API` automatically and emits `_falcon.abi3.so` on normal CPython, disables it on free-threaded builds below 3.15, and emits abi3t on 3.15 and later. Set Layer 2 (the wheel tag) in `setup.py` via `options={"bdist_wheel": {"py_limited_api": "cp39"}}`, guarded by `if not sysconfig.get_config_var("Py_GIL_DISABLED")` because setuptools raises if this is set on a free-threaded build. Build only `cp39-*` in cibuildwheel so the ABI floor, the wheel tag, and the build interpreter all agree. Pin `cffi >= 2.0.0` on both `build-system.requires` and the runtime dependencies.

## Consequences

One wheel per platform covers all supported CPythons. Because the `Py_LIMITED_API` define is unversioned, the ABI floor equals the interpreter we build on, so cibuildwheel must build on the lowest supported version; cibuildwheel runs `abi3audit` automatically after repair to catch a too-new build. Both layers key on the same `Py_GIL_DISABLED` signal, so the generated code, the extension flag, and the tag never disagree. `cffi` remains a runtime dependency, since the module imports `_cffi_backend`, and the shared build-and-runtime floor prevents a backend version mismatch.
