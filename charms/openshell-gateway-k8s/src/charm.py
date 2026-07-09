"""OpenShell Gateway K8s charm."""

from __future__ import annotations

import ops
from ops import ActiveStatus, BlockedStatus, CharmBase

from config_model import GatewayConfig, load_config


class OpenshellGatewayK8sCharm(CharmBase):
    """Sidecar ops charm for the OpenShell gateway on Kubernetes."""

    def __init__(self, framework: ops.Framework) -> None:
        super().__init__(framework)

        # Initialise sentinels before parsing so collect_unit_status never
        # AttributeErrors even on a fresh deploy before config_changed fires.
        self._model: GatewayConfig | None = None
        self._config_error: str | None = None

        # Parse config once per dispatch — available to every hook on this instance.
        self._model, self._config_error = load_config(dict(self.config))

        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)

    def _on_config_changed(self, _event: ops.ConfigChangedEvent) -> None:
        """Handle config-changed.

        Config is parsed in __init__ (once per dispatch); this handler exists
        for any config-change side effects FD-002 needs to perform.  Status is
        set centrally in _on_collect_unit_status (B1 pattern) — do not set it
        here.

        # FD-003: push rendered env into Pebble layer here once the workload
        # container lifecycle is wired.
        """

    def _on_collect_unit_status(self, event: ops.CollectStatusEvent) -> None:
        """Central status decision site (B1 — collect-unit-status pattern).

        Derives unit status from the config parse outcome computed in __init__.
        FD-003 will add relation-missing blockers here alongside the roles
        blocker without fragmenting logic.
        """
        if self._config_error:
            event.add_status(BlockedStatus(self._config_error))
        else:
            event.add_status(ActiveStatus())


if __name__ == "__main__":
    ops.main(OpenshellGatewayK8sCharm)
