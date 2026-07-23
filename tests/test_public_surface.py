"""Pins the public surface to generate / sign / verify.

Adding a name here should be a deliberate act, so the expected set is spelled
out in full, the C-mirroring layer is asserted to stay private, and the compiled
extension is held to the declarations the package actually reaches. See
docs/adr/0006-minimal-public-surface.md.
"""

from __future__ import annotations

import importlib
import pkgutil
from importlib.metadata import version

import falcon_det1024 as fp
from falcon_det1024 import _falcon

PUBLIC_NAMES = {
    "__version__",
    "FalconSigner",
    "FalconVerifier",
    "PUBLIC_KEY_SIZE",
    "PRIVATE_KEY_SIZE",
    "COMPRESSED_SIG_MAX_SIZE",
    "FalconError",
    "InvalidSignature",
    "KeygenError",
    "SigningError",
}

# CT format, coefficient inspection, and salt-version reads are C capabilities
# the package deliberately does not surface.
PRIVATE_NAMES = {
    "bindings",
    "CT_SIGNATURE_SIZE",
    "CURRENT_SALT_VERSION",
    "LOGN",
    "N",
    "SEED_SIZE",
    "ConversionError",
}

# `constants` and `exceptions` carry no underscore, so unlike `_bindings` they
# stay importable in their own right. A name defined there is public even though
# `__init__.py` never mentions it.
NON_PUBLIC_SUBMODULE_NAMES = {
    "falcon_det1024.constants": {
        "CT_SIGNATURE_SIZE",
        "CURRENT_SALT_VERSION",
        "LOGN",
        "N",
        "SEED_SIZE",
    },
    "falcon_det1024.exceptions": {"ConversionError"},
}

# The only modules that may ship without a leading underscore. Any other public
# module, such as a hazmat-style layer, has to be declared here first.
PUBLIC_SUBMODULES = {"api", "constants", "exceptions"}

# Every declaration in the cdef, which covers exactly what the package and its
# tests reach.
CDEF_NAMES = {
    "FALCON_ERR_RANDOM",
    "FALCON_ERR_SIZE",
    "FALCON_ERR_FORMAT",
    "FALCON_ERR_BADSIG",
    "FALCON_ERR_BADARG",
    "FALCON_ERR_INTERNAL",
    "FALCON_DET1024_TMPSIZE_MAKEPUB",
    "FALCON_DET1024_PUBKEY_SIZE",
    "FALCON_DET1024_PRIVKEY_SIZE",
    "FALCON_DET1024_SIG_COMPRESSED_MAXSIZE",
    "FALCON_DET1024_SIG_CT_SIZE",
    "shake256_extract",
    "shake256_init_prng_from_seed",
    "falcon_make_public",
    "falcon_det1024_keygen",
    "falcon_det1024_sign_compressed",
    "falcon_det1024_verify_compressed",
    "falcon_det1024_convert_compressed_to_ct",
}


def test_all_is_exactly_the_supported_surface() -> None:
    assert set(fp.__all__) == PUBLIC_NAMES


def test_every_exported_name_is_importable() -> None:
    for name in PUBLIC_NAMES:
        assert hasattr(fp, name), f"{name} is in __all__ but not importable"


def test_internals_are_not_reachable_from_the_package() -> None:
    for name in PRIVATE_NAMES:
        assert not hasattr(fp, name), f"{name} must not be public"


def test_internals_are_not_reachable_from_the_public_submodules() -> None:
    for module_name, names in NON_PUBLIC_SUBMODULE_NAMES.items():
        module = importlib.import_module(module_name)
        for name in sorted(names):
            assert not hasattr(module, name), f"{module_name}.{name} is public"


def test_no_undeclared_submodule_ships_importable() -> None:
    # `hasattr` only sees names bound on the package, so a module file that
    # nothing imports slips past that check while `import falcon_det1024.x`
    # still works.
    shipped = {
        m.name for m in pkgutil.iter_modules(fp.__path__) if not m.name.startswith("_")
    }
    assert shipped == PUBLIC_SUBMODULES, "a module outside the API layer is public"


def test_cdef_declares_exactly_what_the_package_reaches() -> None:
    # Set equality, not a denylist: a denylist only catches the names someone
    # thought to list, so any other Falcon entry point would appear silently.
    assert set(dir(_falcon.lib)) == CDEF_NAMES


def test_version_matches_the_distribution_metadata() -> None:
    # Two independent semantic-release writers update `__version__` and the
    # pyproject version, so they can drift apart.
    assert fp.__version__ == version("falcon-det1024")
