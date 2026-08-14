"""Verification mode enum shared by ``config_model`` and ``lxd_api``.

Kept in its own tiny module so ``config_model`` can remain free of ``ssl`` and
``http.client`` imports while both modules use the same type.
"""

from __future__ import annotations

from enum import Enum


class VerificationMode(Enum):
    """How the LXD server's TLS identity is pinned."""

    CERTIFICATE = "certificate"
    FINGERPRINT = "fingerprint"
