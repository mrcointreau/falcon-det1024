"""CFFI build script for falcon-det1024, using out-of-line API mode.

Compiles the vendored Falcon C sources (see `SOURCES`) and exposes the
deterministic det1024 API declared in `deterministic.h`.

API mode (not ABI mode) is required for three reasons:

- Every buffer-size constant is function-like macro arithmetic (for example
  `FALCON_DET1024_SIG_COMPRESSED_MAXSIZE = FALCON_SIG_COMPRESSED_MAXSIZE(10)-40+1`,
  where `FALCON_SIG_COMPRESSED_MAXSIZE(logn)` is bit-shift arithmetic). The C
  compiler resolves these from the headers, so no size is transcribed by hand.
- `shake256_context` must be allocated by the caller (208 bytes). It is declared
  as a partial struct so the compiler computes its size.
- The det1024 output functions take no length argument and do no bounds check
  (for example `falcon_det1024_keygen` writes 2305 and 1793 bytes
  unconditionally), so an undersized buffer is a silent out-of-bounds write. The
  compiler supplies the sizes from the header.

No FP or SIMD `-D` flags are passed. The fork's `config.h` hard-defines
`FALCON_FPEMU=1`, `FALCON_FPNATIVE=0`, `FALCON_AVX2=0`, `FALCON_FMA=0`, and
`FALCON_ASM_CORTEXM4=0`, so compiling the source set with no extra defines yields
the emulated-FP, no-SIMD, bit-exact build that Algorand consensus determinism
requires. No `-mavx2` and no `-lm`.
"""

from __future__ import annotations

import os

from cffi import FFI

_HERE = os.path.dirname(os.path.abspath(__file__))
# _build.py lives at <repo>/src/falcon_det1024/, so the repo root is two levels up.
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir))
_FALCON_DIR = os.path.join(_REPO_ROOT, "vendor", "falcon")

# The vendored .c set compiled together. The deterministic layer is
# `deterministic.c` at the repo root. The det1024 functions allocate their own
# scratch on the stack, so no tmp buffer or `FALCON_TMPSIZE_*` is involved.
SOURCES = [
    "codec.c",
    "common.c",
    "deterministic.c",
    "falcon.c",
    "fft.c",
    "fpr.c",
    "keygen.c",
    "rng.c",
    "shake.c",
    "sign.c",
    "vrfy.c",
]

ffibuilder = FFI()

# ---------------------------------------------------------------------------
# The cdef holds declarations only. Size constants use a bare `...` (a macro
# name, a space, three dots, and no trailing semicolon) so the C compiler
# supplies the value. `shake256_context` uses the partial-struct `...;` form,
# where the inner `;` is the last-field marker and `opaque_contents` is left
# for the compiler.
# ---------------------------------------------------------------------------
ffibuilder.cdef(
    r"""
    /* --- SHAKE256 context and PRNG seeding (falcon.h) ---------------- */
    typedef struct { ...; } shake256_context;

    void shake256_init(shake256_context *sc);
    void shake256_inject(shake256_context *sc, const void *data, size_t len);
    void shake256_flip(shake256_context *sc);
    void shake256_extract(shake256_context *sc, void *out, size_t len);
    void shake256_init_prng_from_seed(shake256_context *sc,
        const void *seed, size_t seed_len);
    int shake256_init_prng_from_system(shake256_context *sc);

    /* --- Error codes (falcon.h) ------------------------------------- */
    #define FALCON_ERR_RANDOM ...
    #define FALCON_ERR_SIZE ...
    #define FALCON_ERR_FORMAT ...
    #define FALCON_ERR_BADSIG ...
    #define FALCON_ERR_BADARG ...
    #define FALCON_ERR_INTERNAL ...

    /* --- det1024 sizes / constants (deterministic.h) ---------------- */
    #define FALCON_DET1024_LOGN ...
    #define FALCON_DET1024_PUBKEY_SIZE ...
    #define FALCON_DET1024_PRIVKEY_SIZE ...
    #define FALCON_DET1024_SIG_COMPRESSED_MAXSIZE ...
    #define FALCON_DET1024_SIG_CT_SIZE ...
    #define FALCON_DET1024_CURRENT_SALT_VERSION ...

    /* --- det1024 API (deterministic.h) ------------------------------ */
    int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey);
    int falcon_det1024_sign_compressed(void *sig, size_t *sig_len,
        const void *privkey, const void *data, size_t data_len);
    int falcon_det1024_verify_compressed(const void *sig, size_t sig_len,
        const void *pubkey, const void *data, size_t data_len);
    int falcon_det1024_verify_ct(const void *sig,
        const void *pubkey, const void *data, size_t data_len);
    int falcon_det1024_convert_compressed_to_ct(void *sig_ct,
        const void *sig_compressed, size_t sig_compressed_len);
    int falcon_det1024_get_salt_version(const void *sig);
    int falcon_det1024_pubkey_coeffs(uint16_t *h, const void *pubkey);
    void falcon_det1024_hash_to_point_coeffs(uint16_t *c, const void *data,
        size_t data_len, uint8_t salt_version);
    int falcon_det1024_s2_coeffs(int16_t *s2, const void *sig);
    int falcon_det1024_s1_coeffs(int16_t *s1, const uint16_t *h,
        const uint16_t *c, const int16_t *s2);
    """
)

# setuptools requires Extension source and include paths to be relative to the
# setup.py directory. The build runs with cwd at the project root, so the paths
# are expressed relative to cwd.
_sources = [os.path.relpath(os.path.join(_FALCON_DIR, name)) for name in SOURCES]
_include_dirs = [os.path.relpath(_FALCON_DIR)]

ffibuilder.set_source(
    "falcon_det1024._falcon",
    r"""
    #include "falcon.h"
    #include "deterministic.h"
    """,
    sources=_sources,
    include_dirs=_include_dirs,
    # py_limited_api is not passed here. cffi (>=2.0) manages the extension
    # (Layer 1) on its own: it emits the unversioned `#define Py_LIMITED_API` and
    # sets py_limited_api to true on normal CPython (including Windows 3.5 and
    # later), producing `_falcon.abi3.so`; on free-threaded builds
    # (`Py_GIL_DISABLED`) below 3.15 it disables the limited API for a
    # full-tagged extension, and on 3.15 and later it emits abi3t. The wheel tag
    # (Layer 2) is set conditionally in setup.py. Both layers key on
    # `Py_GIL_DISABLED`, so they agree.
    #
    # No FP or SIMD -D flags and no -lm: `config.h` hard-defines the emulated-FP,
    # no-SIMD build required for bit-exact cross-platform determinism.
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
