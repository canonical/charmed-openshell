#!/usr/bin/env python3

"""LXD Integrator K8s charm."""

from __future__ import annotations

import logging

import ops

from config_model import IntegratorConfig, load_config

logger = logging.getLogger(__name__)


class LxdIntegratorCharm(ops.CharmBase):
    """Workload-less integrator charm for unmanaged LXD servers.

    This scaffold owns config loading and secret resolution only; relation
    handling, reconcile, and LXD trust calls are deferred to the follow-on
    feature.
    """

    def __init__(self, framework: ops.Framework) -> None:
        super().__init__(framework)

        self._model: IntegratorConfig | None = None
        self._config_error: str | None = None

        credentials = self._resolve_credentials()
        raw_config = dict(self.config)
        raw_config.pop("lxd-credentials", None)
        raw_config.update(credentials)
        self._model, self._config_error = load_config(raw_config)

    def _resolve_credentials(self) -> dict[str, str]:
        """Resolve the ``lxd-credentials`` secret into a key/value mapping.

        Returns a dictionary with the secret content keys
        (``client-cert``, ``client-key``, ``server-cert``, ``trust-token``), or
        an empty dictionary when the option is unset or the secret has not yet
        been granted.
        """
        secret_uri = self.config.get("lxd-credentials")
        if not secret_uri:
            return {}

        try:
            secret = self.model.get_secret(id=str(secret_uri))
            content = secret.get_content(refresh=True)
        except (ops.SecretNotFoundError, ops.ModelError):
            logger.warning("Failed to resolve lxd-credentials secret %s", secret_uri)
            return {}

        return {key: value for key, value in content.items() if value}


if __name__ == "__main__":
    ops.main(LxdIntegratorCharm)
