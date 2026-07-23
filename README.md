# falcon-det1024

Python bindings for the Algorand deterministic **Falcon** (`det1024`) post-quantum signature scheme, built directly over the [`algorand/falcon`](https://github.com/algorand/falcon) C implementation with [cffi](https://cffi.readthedocs.io/) in **API mode**.

- **Deterministic**: the same `(private key, message)` always produces a byte-identical signature (no nonce). This is what Algorand consensus requires.
- **Bit-exact**: compiled with the emulated floating-point, no-SIMD configuration, so signatures are identical across compilers and CPU architectures. This is locked in by the upstream known-answer tests (KATs).
- **Small surface**: generate, sign, verify. The C-mirroring layer is private, so there is no low-level API to misuse. See [ADR 0006](docs/adr/0006-minimal-public-surface.md).
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

signer = FalconSigner.generate()          # or generate(seed) for deterministic keygen

signature = signer.sign(b"hello world")   # deterministic, compressed format

verifier = signer.verifying_key()
verifier.verify(b"hello world", signature)      # returns None; raises on failure
assert verifier.is_valid(b"hello world", signature)

try:
    verifier.verify(b"tampered", signature)
except InvalidSignature:
    print("rejected")
```

## Using with py-algorand-sdk

`py-algorand-sdk` has no Falcon dependency: its post-quantum signer takes a public key plus a callback that signs exact preimage bytes. `FalconSigner.sign` is that callback.

```python
from algosdk import mnemonic, constants
from algosdk.signer import Falcon1024TransactionSigner
from falcon_det1024 import FalconSigner

seed = mnemonic.to_pq_seed(my_mnemonic, constants.falcon_1024_scheme)  # 32 bytes
signer = FalconSigner.generate(seed)

txn_signer = Falcon1024TransactionSigner(signer.public_key, signer.sign)
```

The same signer serves both preimage families the SDK produces: transactions (`"TX"` + msgpack) and delegated logic signatures (`"PQProgram"` + address + program).

## API

### `FalconSigner`

- `FalconSigner.generate(seed: bytes | None = None) -> FalconSigner`: create a new keypair. `seed=None` derives from a fresh 48-byte OS CSPRNG seed. Otherwise `seed` deterministically derives the keypair and may be any non-empty length. For Algorand accounts it is the 32 bytes `algosdk.mnemonic.to_pq_seed()` returns.
- `FalconSigner(private_key: bytes)`: load from stored private key bytes. The public key is recomputed from the private key, so the two can never disagree.
- `.sign(message: bytes) -> bytes`: deterministic compressed signature.
- `.verifying_key() -> FalconVerifier`
- `.private_key`, `.public_key`: raw `bytes`.

### `FalconVerifier`

- `FalconVerifier(public_key: bytes)`
- `.verify(message, signature) -> None`: raises `InvalidSignature` on failure.
- `.is_valid(message, signature) -> bool`
- `.public_key`

### Key hygiene

`sign` and `verify` operate on raw bytes with **no domain separation**: the message is signed verbatim. A key that signs arbitrary caller-supplied bytes can be made to sign a valid transaction preimage, so use one key for one protocol. To reproduce a signature an application made over a structured object, sign the digest that application hashes to, not the object itself.

### Constants

`PUBLIC_KEY_SIZE=1793`, `PRIVATE_KEY_SIZE=2305`, `COMPRESSED_SIG_MAX_SIZE=1423`. Resolved from the C header macros at build time, so they can never drift from the vendored library.

### Exceptions

`FalconError` is the base class. `InvalidSignature`, `KeygenError`, and `SigningError` derive from it. Wrong argument *sizes* raise the built-in `ValueError`, and arguments of the wrong type raise `TypeError`.

## Development

Requires [uv](https://docs.astral.sh/uv/). The Falcon C sources are vendored as a git submodule.

```console
git clone --recurse-submodules https://github.com/mrcointreau/falcon-det1024
cd falcon-det1024
uv sync                 # builds the cffi extension + installs dev deps
uv run pytest           # roundtrip, determinism, tamper, surface, and 512+32 KATs
uv run mypy             # strict
```

Wheels are built with [cibuildwheel](https://cibuildwheel.pypa.io/) (`uvx cibuildwheel` locally). Releases are cut by [python-semantic-release](https://python-semantic-release.readthedocs.io/) from [conventional commits](https://www.conventionalcommits.org/).

See [docs/adr/](docs/adr/) for the key decisions and [docs/DESIGN.md](docs/DESIGN.md) for the binding and packaging reference.

## License

MIT. See [LICENSE](LICENSE). Bundles the Falcon C implementation (Copyright (c) 2017-2020 Falcon Project, MIT).
