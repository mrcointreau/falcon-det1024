"""Idiomatic Falcon deterministic (det1024) signing API.

The primary path is compressed-format sign/verify, which is deterministic:
the same `(private key, message)` always yields a byte-identical signature.

Both `sign` and `verify` operate on the raw `message` bytes with no domain
separation. To reproduce a signature that an application (e.g. go-algorand)
produced over a structured object, sign the digest that application hashes to,
not the object itself.

The C-mirroring low-level surface (CT conversion, coefficient helpers, the raw
`*_compressed` / `*_ct` functions) lives in `falcon_det1024.bindings`.
"""

from __future__ import annotations

from . import bindings
from .constants import PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE
from .exceptions import InvalidSignature


class FalconVerifier:
    """Verifies det1024 compressed signatures against a public key."""

    __slots__ = ("_public_key",)

    def __init__(self, public_key: bytes) -> None:
        public_key = bindings._as_bytes("public_key", public_key)
        if len(public_key) != PUBLIC_KEY_SIZE:
            raise ValueError(
                f"public_key must be exactly {PUBLIC_KEY_SIZE} bytes, "
                f"got {len(public_key)}"
            )
        self._public_key = public_key

    @property
    def public_key(self) -> bytes:
        """The raw public key bytes."""
        return self._public_key

    def verify(self, message: bytes, signature: bytes) -> None:
        """Verify `signature` over the raw `message` bytes.

        Return `None` on success and raise `InvalidSignature` on failure. No
        domain separation is applied; `message` is verified verbatim.
        """
        bindings.verify_compressed(self._public_key, message, signature)

    def is_valid(self, message: bytes, signature: bytes) -> bool:
        """Return `True` if `signature` is valid for `message`."""
        try:
            self.verify(message, signature)
        except InvalidSignature:
            return False
        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FalconVerifier):
            return NotImplemented
        return self._public_key == other._public_key

    def __hash__(self) -> int:
        return hash(self._public_key)

    def __repr__(self) -> str:
        return f"FalconVerifier(public_key=<{PUBLIC_KEY_SIZE} bytes>)"


class FalconSigner:
    """Holds a det1024 keypair and produces deterministic compressed signatures."""

    __slots__ = ("_private_key", "_public_key")

    def __init__(self, private_key: bytes, public_key: bytes) -> None:
        private_key = bindings._as_bytes("private_key", private_key)
        public_key = bindings._as_bytes("public_key", public_key)
        if len(private_key) != PRIVATE_KEY_SIZE:
            raise ValueError(
                f"private_key must be exactly {PRIVATE_KEY_SIZE} bytes, "
                f"got {len(private_key)}"
            )
        if len(public_key) != PUBLIC_KEY_SIZE:
            raise ValueError(
                f"public_key must be exactly {PUBLIC_KEY_SIZE} bytes, "
                f"got {len(public_key)}"
            )
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls, seed: bytes | None = None) -> FalconSigner:
        """Create a new signer.

        With `seed=None` the keypair is seeded from the operating system RNG.
        Otherwise `seed` must be exactly `SEED_SIZE` (32) bytes and
        deterministically derives the keypair.
        """
        if seed is None:
            private_key, public_key = bindings.keygen_from_system()
        else:
            # keygen_from_seed normalizes bytes-like input and enforces the
            # exact SEED_SIZE, raising ValueError on a wrong length.
            private_key, public_key = bindings.keygen_from_seed(seed)
        return cls(private_key, public_key)

    @property
    def private_key(self) -> bytes:
        """The raw private key bytes."""
        return self._private_key

    @property
    def public_key(self) -> bytes:
        """The raw public key bytes."""
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        """Deterministically sign raw `message` bytes into a compressed signature.

        No domain separation is applied; `message` is signed verbatim. To match a
        signature an application made over a structured object, sign the digest
        that application hashes to, not the object itself.
        """
        return bindings.sign_compressed(self._private_key, message)

    def verifying_key(self) -> FalconVerifier:
        """Return a `FalconVerifier` for this signer's public key."""
        return FalconVerifier(self._public_key)

    def __repr__(self) -> str:
        return f"FalconSigner(public_key=<{PUBLIC_KEY_SIZE} bytes>)"
