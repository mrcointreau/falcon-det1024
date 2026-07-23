"""Deterministic Falcon (det1024) signing API.

Signatures are compressed-format and deterministic: the same
`(private key, message)` always yields byte-identical output.

Both `sign` and `verify` operate on the raw `message` bytes with no domain
separation. To reproduce a signature that an application (e.g. go-algorand)
produced over a structured object, sign the digest that application hashes to,
not the object itself. A key used to sign arbitrary caller-supplied bytes can be
made to sign a valid transaction preimage, so use one key for one protocol.
"""

from __future__ import annotations

from . import _bindings
from .constants import PUBLIC_KEY_SIZE
from .exceptions import InvalidSignature


class FalconVerifier:
    """Verifies det1024 compressed signatures against a public key."""

    __slots__ = ("_public_key",)

    def __init__(self, public_key: bytes) -> None:
        public_key = _bindings._as_bytes("public_key", public_key)
        _bindings._check_len("public_key", public_key, PUBLIC_KEY_SIZE)
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
        _bindings.verify_compressed(self._public_key, message, signature)

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
    """Holds a det1024 keypair and produces deterministic compressed signatures.

    The public key is always recomputed from the private key, so the two can
    never disagree.
    """

    __slots__ = ("_private_key", "_public_key")

    def __init__(self, private_key: bytes) -> None:
        """Load a signer from stored private key bytes."""
        # Normalize first, then derive from the stored copy: a caller-supplied
        # bytearray could otherwise be mutated between the two reads, pairing a
        # public key with a private key it was not derived from.
        self._private_key = _bindings._as_bytes("private_key", private_key)
        # `falcon_make_public` decodes the f and g halves, so the public key
        # it returns always matches them. It does not read the trailing F data;
        # a key malformed only there is rejected by `sign`.
        self._public_key = _bindings.public_key_from_private(self._private_key)

    @classmethod
    def generate(cls, seed: bytes | None = None) -> FalconSigner:
        """Create a new signer.

        With `seed=None` the keypair is derived from a fresh 48-byte seed taken
        from the OS CSPRNG. Otherwise `seed` deterministically derives the
        keypair and may be any non-empty length. For Algorand accounts it is the
        32 bytes that `algosdk.mnemonic.to_pq_seed()` returns.
        """
        return cls(_bindings.keygen(seed))

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
        return _bindings.sign_compressed(self._private_key, message)

    def verifying_key(self) -> FalconVerifier:
        """Return a `FalconVerifier` for this signer's public key."""
        return FalconVerifier(self._public_key)

    def __repr__(self) -> str:
        return f"FalconSigner(public_key=<{PUBLIC_KEY_SIZE} bytes>)"
