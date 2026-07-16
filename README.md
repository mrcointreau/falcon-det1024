# falcon-det1024

Python bindings for the Algorand deterministic **Falcon** (`det1024`) post-quantum signature scheme, built directly over the [`algorand/falcon`](https://github.com/algorand/falcon) C implementation with [cffi](https://cffi.readthedocs.io/) in **API mode**.

- **Deterministic**: the same `(private key, message)` always produces a byte-identical signature (no nonce). This is what Algorand consensus requires.
- **Bit-exact**: compiled with the emulated floating-point, no-SIMD configuration, so signatures are identical across compilers and CPU architectures. This is locked in by the upstream known-answer tests (KATs).
- **Typed**: ships `py.typed`, and the public surface is fully annotated.
- **abi3 wheels**: one wheel per platform works on CPython 3.10+.

## Installation

```console
pip install falcon-det1024
```

Prebuilt `cp310-abi3` wheels are published for Linux (x86_64/aarch64, manylinux and musllinux), macOS (x86_64/arm64), and Windows (amd64). The only runtime dependency is `cffi`.

## Quickstart

```python
from falcon_det1024 import FalconSigner, InvalidSignature

# Generate a keypair (OS RNG); pass seed=<32 bytes> for deterministic keygen.
signer = FalconSigner.generate()

signature = signer.sign(b"hello world")   # deterministic, compressed format

verifier = signer.verifying_key()
verifier.verify(b"hello world", signature)      # returns None; raises on failure
assert verifier.is_valid(b"hello world", signature)

# Low-level, C-mirroring API (raw bytes, no domain separation) lives in `bindings`:
from falcon_det1024 import bindings
bindings.verify_compressed(signer.public_key, b"hello world", signature)

try:
    verifier.verify(b"tampered", signature)
except InvalidSignature:
    print("rejected")
```

## API

### `FalconSigner`

- `FalconSigner.generate(seed: bytes | None = None) -> FalconSigner`: create a new keypair. `seed=None` uses the OS RNG. Otherwise `seed` must be exactly `SEED_SIZE` (32) bytes and deterministically derives the keypair.
- `FalconSigner(private_key: bytes, public_key: bytes)`: reconstruct from stored key bytes.
- `.sign(message: bytes) -> bytes`: deterministic compressed signature.
- `.verifying_key() -> FalconVerifier`
- `.private_key`, `.public_key`: raw `bytes`.

### `FalconVerifier`

- `FalconVerifier(public_key: bytes)`
- `.verify(message, signature) -> None`: raises `InvalidSignature` on failure.
- `.is_valid(message, signature) -> bool`
- `.public_key`

### `bindings`

`falcon_det1024.bindings` is the low-level wrapper layer (in the spirit of `nacl.bindings`): each function maps 1:1 to a `falcon_det1024_*` C function with the prefix dropped, and operates on raw bytes with no domain separation.

- `sign_compressed(private_key, data) -> bytes`, `verify_compressed(public_key, data, signature) -> None`
- `verify_ct(public_key, data, ct_signature) -> None`: verify a fixed-length (1538 byte) CT-format signature.
- `convert_compressed_to_ct(signature) -> bytes`: convert a compressed signature to the fixed-length (1538 byte) CT serialization used for hashing and Merkle trees.
- `get_salt_version(signature) -> int`: read the salt-version byte, which works on either format.
- `keygen_from_seed(seed) -> (private_key, public_key)`, `keygen_from_system() -> (private_key, public_key)`.
- Coefficient helpers: `pubkey_coeffs`, `hash_to_point_coeffs`, `s2_coeffs`, `s1_coeffs`. Each works over `N = 1024` coefficients.

All buffer arguments (top-level and `bindings`) accept any bytes-like object (`bytes`, `bytearray`, `memoryview`).

### Constants

`PUBLIC_KEY_SIZE=1793`, `PRIVATE_KEY_SIZE=2305`, `COMPRESSED_SIG_MAX_SIZE=1423`, `CT_SIGNATURE_SIZE=1538`, `SEED_SIZE=32`, `CURRENT_SALT_VERSION=0`, `LOGN=10`, `N=1024`. The size constants are resolved from the C header macros at build time, so they can never drift from the vendored library.

### Exceptions

`FalconError` is the base class. `InvalidSignature`, `KeygenError`, `SigningError`, and `ConversionError` derive from it. Wrong argument *sizes* raise the built-in `ValueError`, and non bytes-like arguments raise `TypeError`.

## Development

Requires [uv](https://docs.astral.sh/uv/). The Falcon C sources are vendored as a git submodule.

```console
git clone --recurse-submodules https://github.com/mrcointreau/falcon-det1024
cd falcon-det1024
uv sync                 # builds the cffi extension + installs dev deps
uv run pytest           # roundtrip, determinism, tamper, CT, and 512+32 KATs
uv run mypy             # strict
```

Wheels are built with [cibuildwheel](https://cibuildwheel.pypa.io/) (`uvx cibuildwheel` locally). Releases are cut by [python-semantic-release](https://python-semantic-release.readthedocs.io/) from [conventional commits](https://www.conventionalcommits.org/).

See [docs/adr/](docs/adr/) for the key decisions and [docs/DESIGN.md](docs/DESIGN.md) for the binding and packaging reference.

## License

MIT. See [LICENSE](LICENSE). Bundles the Falcon C implementation (Copyright (c) 2017-2020 Falcon Project, MIT).
