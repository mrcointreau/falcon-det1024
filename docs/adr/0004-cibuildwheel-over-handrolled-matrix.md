# 4. Use cibuildwheel instead of a hand-rolled matrix

Date: 2026-07-14

## Status

Accepted

## Context

Building the wheel matrix (manylinux and musllinux on x86_64 and aarch64, macOS on both architectures, Windows) involves per-platform toolchains, wheel repair, and getting the vendored git submodule into each build. This can be hand-rolled (docker containers plus native runners, driving the build and wheel repair by hand) or delegated to cibuildwheel.

## Decision

Use cibuildwheel end-to-end. Wheel repair (auditwheel on Linux, delocate on macOS, delvewheel on Windows) and abi3audit run automatically with no extra configuration. Provide the vendored submodule with `actions/checkout` `submodules: recursive` rather than a `before-all` git command, which fails inside the Linux build container with "dubious ownership". Keep cibuildwheel and python-semantic-release out of the `[dependency-groups] dev` group, because cibuildwheel requires Python >= 3.11 and would otherwise constrain our `requires-python = ">=3.9"`; both run via their official GitHub Actions, or via `uvx` locally.

## Consequences

We get standard, maintained tooling and far less CI code than a hand-rolled matrix, at the cost of less bespoke control over each build step. The dev dependency group stays minimal (cffi, pytest, mypy), so `uv sync` resolves cleanly on every supported Python.
