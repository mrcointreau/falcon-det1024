# 6. Minimal public surface: generate, sign, verify

Date: 2026-07-22

## Status

Accepted. Supersedes the surface decision in [ADR 0005](0005-minimum-python-3-10.md)'s companion change (`0d2aa2e`, "expose public bindings module").

## Context

Version 0.2.0 shipped a public `falcon_det1024.bindings` module in the spirit of `nacl.bindings`: eleven functions mirroring the C API 1:1, including CT-format conversion and verification, salt-version reads, and the four coefficient helpers (`pubkey_coeffs`, `hash_to_point_coeffs`, `s2_coeffs`, `s1_coeffs`). Eight constants and five exceptions were exported alongside two classes.

Three findings drove a reassessment.

**The consumers need two operations.** `py-algorand-sdk` has no Falcon dependency at all; its `Falcon1024TransactionSigner(public_key, signer)` takes a callback, `Callable[[bytes], bytes]`. The complete journey is: `mnemonic.to_pq_seed()` → keypair → sign the preimage. Nothing verifies client-side; consensus does that.

**A public low-level layer has to earn its place.** Seven of the eleven `bindings` functions had no caller anywhere outside this repository's own tests. Exposing them is not free: it commits the project to their stability, and it invites callers to assemble primitives by hand instead of using the operation they actually want. Every name that is published is a name that has to keep working.

**The extra surface carried a real defect.** `hash_to_point_coeffs` defaulted `salt_version` to `CURRENT_SALT_VERSION`, a parameter C requires. The obvious hand-rolled verification chain (`pubkey_coeffs` → `hash_to_point_coeffs` → `s2_coeffs` → `s1_coeffs`) therefore ignored the signature's own salt-version byte and accepted a tampered CT signature that `verify_ct` correctly rejects. The helpers invited a verifier that does not verify.

Separately, `FalconSigner(private_key, public_key)` accepted a mismatched pair on length checks alone. Since an Algorand address derives from the *public* key, that silently produces an account whose signatures can never authorize it.

## Decision

Expose `FalconSigner`, `FalconVerifier`, three size constants, and four exceptions. Ten names.

- Delete the `bindings` module. The three operations behind the classes move to a private `_bindings.py`.
- Drop `CT_SIGNATURE_SIZE`, `CURRENT_SALT_VERSION`, `LOGN`, `N`, `SEED_SIZE`, and `ConversionError`.
- Trim the cdef to what is reachable. `shake256_init_prng_from_seed` stays because `generate` seeds keygen's PRNG through it; `falcon_det1024_convert_compressed_to_ct` and `shake256_extract` stay so `tests/test_kat.py` can still derive the KAT messages and reproduce the 32 CT known-answer vectors. CT is test-only, not API.
- Bind `falcon_make_public` and take **only the private key** in `FalconSigner.__init__`, recomputing the public key. A mismatched keypair becomes unrepresentable rather than merely detected. `falcon_make_public` decodes f and g, so a private key corrupt there fails at construction; corruption in F is invisible until signing decodes it and raises `SigningError`.
- Accept any non-empty seed length in `generate`, matching C, where `shake256_init_prng_from_seed` takes the length explicitly. The 32-byte rule was this library's invention and would reject a seed a caller legitimately holds. An empty seed raises rather than silently falling back to randomness, so a caller who meant to supply a seed never gets a random key by accident.

Minimal does not mean unstructured. Classes are kept rather than reduced to module-level functions over raw bytes, because class-based keypairs are the Python convention (`nacl.signing.SigningKey`, `cryptography`'s `Ed25519PrivateKey`), and because binding a key to an object is what lets the public key be derived once at construction. Likewise `InvalidSignature` keeps its name, matching `cryptography.exceptions.InvalidSignature`.

## Consequences

The public API can no longer express CT format, coefficient inspection, or salt-version reads. Anyone needing those should use the C library directly; the vendored source is in the sdist. If a second consumer appears (state proofs, an AVM opcode, ZK circuits), reintroducing them as a `hazmat`-style subpackage is the expected path, and reintroduction is additive.

This is a breaking change one release after `0d2aa2e` made `bindings` public. The cost is bounded: the package is `Development Status :: 3 - Alpha`, and no released consumer imports it.

Determinism coverage is unchanged: all 512 compressed and 32 CT known-answer vectors still run. `test_kat.py` additionally asserts that `falcon_make_public` agrees with `falcon_det1024_keygen` across all 512 keypairs.
