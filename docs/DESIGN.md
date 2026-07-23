# Design & binding reference

How-it-works and reference notes for falcon-det1024. The significant, alternative-bearing decisions live as decision records under [adr/](adr/), which indexes them.

## The cdef forms

In API mode the `cdef` declares values that the C compiler fills in. Size constants are declared as a macro name, a space, three dots, and no trailing semicolon: `#define FALCON_DET1024_PRIVKEY_SIZE ...`. A trailing `;` makes `ffi.cdef()` raise `CDefError`. The SHAKE context is declared as the partial struct `typedef struct { ...; } shake256_context;`, where the inner `...;` is the required "last field" marker; we do not redeclare `opaque_contents`, so the compiler computes `sizeof` (208 bytes). Both forms only work in API mode, since there is no compiler in ABI mode to resolve them.

## Public surface

The package exposes `FalconSigner`, `FalconVerifier`, three size constants, and four exceptions. The cffi marshalling lives in the private `_bindings.py`, so a caller cannot reach a det1024 primitive except through the two classes. CT format, coefficient inspection, and salt-version reads stay unexposed; [ADR 0006](adr/0006-minimal-public-surface.md) records why.

`FalconSigner` takes only a private key and recomputes the public key via `falcon_make_public`, so a mismatched keypair cannot be constructed. That matters because an Algorand address derives from the public key: a signer holding an unrelated private key would produce signatures that can never authorize its own address, with no error until consensus rejects them.

## Memory safety: exact-length guards

The det1024 functions take no length argument for their fixed-size buffers and do no bounds check, so `_bindings.py` enforces exact input lengths before every call as defence in depth. The lengths mirror what `deterministic.c` reads or writes. `falcon_det1024_keygen` writes 2305/1793 bytes unconditionally. `sign_compressed` reads the 2305-byte private key. `verify_compressed` reads the 1793-byte public key. Variable-length inputs (the message, the compressed signature, the seed) are passed with their length and validated by C. Every buffer argument is also normalized to `bytes` at the boundary (accepting `bytearray` and `memoryview`, rejecting `int` so `bytes(2305)` cannot forge a valid-length zero key).

## Deterministic build

The bit-exact, emulated-FP build is what makes signatures identical across compilers and architectures, which consensus determinism requires. It falls out of compiling the vendored source set with no extra `-D` flags: the fork's `config.h` hard-defines `FALCON_FPEMU=1`, `FALCON_FPNATIVE=0`, `FALCON_AVX2=0`, `FALCON_FMA=0`, `FALCON_ASM_CORTEXM4=0`. `tests/test_kat.py` reproduces the upstream 512 compressed and 32 CT known-answer vectors byte-for-byte, so any regression in this configuration fails the suite immediately. The CT vectors are reached through the private `_falcon` extension rather than the public API: CT is not part of the surface, but it is the strongest available check that the build is bit-exact. See [ADR 0001](adr/0001-cffi-api-mode.md).

## sdist

setuptools auto-includes the 11 `.c` Extension sources but not the vendored headers, so `MANIFEST.in` explicitly ships `vendor/falcon/*.h` (`falcon.h`, `deterministic.h`, `config.h`, `inner.h`, `fpr.h`). Without them a build from the sdist fails at `'falcon.h' file not found`. Extension source and include paths in `_build.py` are made relative with `os.path.relpath`, because setuptools rejects absolute paths.

## Conventions

The project uses uv with a committed `uv.lock`, the Falcon C sources vendored as a git submodule pinned to a commit, python-semantic-release for versioning, PyPI OIDC trusted publishing, and pytest plus mypy. Two choices are worth calling out:

- **CI tooling is not in the dev group.** cibuildwheel and python-semantic-release run via their official GitHub Actions (or `uvx` locally). Keeping them out of `[dependency-groups] dev` avoids constraining `requires-python`, since cibuildwheel needs Python >= 3.11. See [ADR 0004](adr/0004-cibuildwheel-over-handrolled-matrix.md).
- **Release identity.** The release job pushes the version-bump commit with `GITHUB_TOKEN`. If `main` is protected, swap in a GitHub App token or admin PAT.
