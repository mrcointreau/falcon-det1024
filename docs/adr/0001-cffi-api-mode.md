# 1. Use cffi API mode

Date: 2026-07-14

## Status

Accepted

## Context

We wrap the vendored Falcon C library. cffi offers two ways to do this. ABI mode loads a prebuilt shared library and requires us to hand-transcribe sizes, struct layouts, and signatures. API mode compiles the C sources and lets the C compiler resolve everything from the headers.

Three properties of the det1024 C surface make hand-transcription dangerous. Buffer-size constants come from nested function-like macro arithmetic (for example `FALCON_DET1024_SIG_COMPRESSED_MAXSIZE = FALCON_SIG_COMPRESSED_MAXSIZE(10)-40+1`, where the inner macro is itself bit-shift arithmetic). `shake256_context` must be allocated by the caller (208 bytes). And the det1024 output functions take no length argument and do no bounds check: `falcon_det1024_keygen` writes 2305/1793 bytes unconditionally, and `falcon_det1024_verify_ct` / `falcon_det1024_s2_coeffs` read a fixed 1538 bytes. An undersized transcribed literal is a silent out-of-bounds access, not a caught error.

## Decision

Use cffi API mode. Compile the vendored source set (`codec, common, deterministic, falcon, fft, fpr, keygen, rng, shake, sign, vrfy`) via `ffi.set_source(sources=[...])` with the submodule on `include_dirs`. In the `cdef`, declare size constants as bare `#define NAME ...` (no trailing semicolon) and the context as the partial struct `typedef struct { ...; } shake256_context;`, so the compiler supplies every value. Pass no FP or SIMD `-D` flags, because the fork's `config.h` already hard-defines the emulated-FP build.

## Consequences

Sizes and struct layout can never drift from the vendored headers, which removes a real heap-overflow risk rather than a theoretical one. A C compiler is required at build time, which is fine because we ship wheels for every platform. The build backend is setuptools plus cffi. The same no-extra-flags configuration yields the bit-exact, emulated-FP build that Algorand consensus determinism requires, and `tests/test_kat.py` locks that in by reproducing the upstream known-answer vectors byte-for-byte.
