"""Idiomatic Falcon deterministic (det1024) signing API.

The primary path is compressed-format sign/verify, which is deterministic:
the same `(private key, message)` always yields a byte-identical signature.
CT format is a fixed-length serialization used for hashing and Merkle trees.
"""

from __future__ import annotations

from collections.abc import Sequence

from . import _core
from .constants import CURRENT_SALT_VERSION, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE
from .exceptions import InvalidSignature


class FalconVerifier:
    """Verifies det1024 compressed signatures against a public key."""

    __slots__ = ("_public_key",)

    def __init__(self, public_key: bytes) -> None:
        public_key = _core._as_bytes("public_key", public_key)
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
        """Verify `signature` over `message`.

        Return `None` on success and raise `InvalidSignature` on failure.
        """
        _core.verify_compressed(self._public_key, message, signature)

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
        private_key = _core._as_bytes("private_key", private_key)
        public_key = _core._as_bytes("public_key", public_key)
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
            private_key, public_key = _core.keygen_from_system()
        else:
            # keygen_from_seed normalizes bytes-like input and enforces the
            # exact SEED_SIZE, raising ValueError on a wrong length.
            private_key, public_key = _core.keygen_from_seed(seed)
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
        """Deterministically sign `message` and return a compressed signature."""
        return _core.sign_compressed(self._private_key, message)

    def verifying_key(self) -> FalconVerifier:
        """Return a `FalconVerifier` for this signer's public key."""
        return FalconVerifier(self._public_key)

    def __repr__(self) -> str:
        return f"FalconSigner(public_key=<{PUBLIC_KEY_SIZE} bytes>)"


# --------------------------------------------------------------------------- #
# Module-level helpers
# --------------------------------------------------------------------------- #
def verify_falcon1024(message: bytes, public_key: bytes, signature: bytes) -> None:
    """Verify a compressed det1024 signature and raise `InvalidSignature` on failure."""
    _core.verify_compressed(public_key, message, signature)


def compressed_to_ct(signature: bytes) -> bytes:
    """Convert a compressed signature to fixed-length CT format (1538 bytes)."""
    return _core.convert_compressed_to_ct(signature)


def salt_version(signature: bytes) -> int:
    """Return the salt-version byte of a signature (compressed or CT)."""
    return _core.get_salt_version(signature)


# --------------------------------------------------------------------------- #
# Advanced coefficient helpers
# --------------------------------------------------------------------------- #
def pubkey_coeffs(public_key: bytes) -> list[int]:
    """Unpack a public key into its 1024 ring-element coefficients (h)."""
    return _core.pubkey_coeffs(public_key)


def hash_to_point_coeffs(
    data: bytes, salt_version: int = CURRENT_SALT_VERSION
) -> list[int]:
    """Hash `data` (with the fixed versioned salt) to 1024 coefficients (c)."""
    return _core.hash_to_point_coeffs(data, salt_version)


def s2_coeffs(ct_signature: bytes) -> list[int]:
    """Unpack the 1024 s2 coefficients from a CT-format signature."""
    return _core.s2_coeffs(ct_signature)


def s1_coeffs(
    h: Sequence[int], c: Sequence[int], s2: Sequence[int]
) -> list[int]:
    """Compute the 1024 coefficients of s1 = c - s2*h, validating shortness."""
    return _core.s1_coeffs(h, c, s2)
