# 5. Set the minimum supported Python to 3.10

Date: 2026-07-16

## Status

Accepted

## Context

The project shipped `requires-python = ">=3.9"` and a `cp39-abi3` wheel. Python 3.9 reached end of life in October 2025 and receives no security fixes. The floor was also lower than the packages either side of it: cffi, the only runtime dependency, requires >= 3.10 from 2.1.0 onward, so a 3.9 install silently resolves to the older cffi 2.0.0; py-algorand-sdk, the primary consumer of these bindings, requires >= 3.10; and mypy cannot target 3.9, so the lowest supported version was never type-checked (`python_version = "3.10"` was already the mypy floor). Spanning the cffi 3.10 boundary additionally forks the uv resolution into `< '3.10'` and `>= '3.10'` branches, which churns the `uv.lock` markers on every re-lock. Because abi3 serves every version above the floor from a single build, a higher floor costs nothing above it. The alternatives were to keep 3.9, move to 3.10, or move to 3.11.

## Decision

Set `requires-python = ">=3.10"`, build `cp310-*` in cibuildwheel, and tag the wheel `cp310-abi3` (`py_limited_api = "cp310"` in `setup.py`). Match the consumer's floor rather than exceed it: 3.11 would drop 3.10 users that py-algorand-sdk still supports and would buy only newer syntax.

## Consequences

There are no 3.9 wheels; 3.9 users stay on an earlier release. The abi3 wheel still covers every CPython from 3.10 upward from one build per platform, so reach above the floor is unchanged. The uv resolution no longer forks, so `uv.lock` loses its per-branch markers. The mypy target now equals the floor, so the lowest supported version is the one that is type-checked. `from __future__ import annotations` is no longer needed for 3.9 compatibility and is kept for lazy annotation evaluation. The floor, the cibuildwheel selector, the `setup.py` tag, and the CI test matrix must move together whenever the floor is raised again; `uv sync` fails outright if the matrix pins an interpreter below the floor. [ADR 0002](0002-abi3-single-wheel.md) and [ADR 0003](0003-defer-free-threaded-wheels.md) record the earlier `cp39` tag and selector; they stand as written, and this record supersedes those details.
