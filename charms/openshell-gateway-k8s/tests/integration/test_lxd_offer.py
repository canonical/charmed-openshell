"""Integration tests for the gateway's LXD provider via a cross-model offer.

Approach B: the test creates a machine model on the lxd cloud, deploys the
``lxd`` charm, and offers its ``https`` endpoint. The Kubernetes model consumes
the offer and relates it to the gateway. It asserts the trust lifecycle on the
managed LXD via ``juju exec`` on the ``lxd`` unit.

Sandbox end-to-end assertions are gated by ``requires_sandbox_e2e`` and skip
until the upstream ``--gateway-endpoint`` driver flag lands.
"""

from __future__ import annotations

import logging
import shutil
import time
import uuid

import jubilant
import pytest

from .conftest import (
    APP_NAME,
    LXD_CONTROLLER,
    _run_gated_sandbox_e2e,
    _wait_for_gateway_blocked,
    assert_trust_registered,
    assert_trust_withdrawn,
    managed_lxd_trust_fingerprints,
    prepare_openshell_client,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.offer]

MACHINE_MODEL_PREFIX = "openshell-lxd-offer"
LXD_APP = "lxd"
OFFER_ALIAS = "lxd-offer"


def _prime_lxd_certificate_store(machine_juju: jubilant.Juju) -> None:
    """Ensure the managed LXD certificate store is initialised.

    On freshly initialised LXD daemons the ``/1.0/certificates`` API may return
    ``metadata: null`` until at least one certificate is present. The canonical
    ``lxd`` charm iterates over ``pylxd.Client().certificates.all()`` without
    handling null metadata, so its ``https-relation-changed`` hook fails before
    it can add the gateway's client certificate. A dummy certificate is added
    to keep the store non-null; it is left in place because removing the only
    certificate reverts the API response to ``metadata: null``.
    """
    machine_juju.exec(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        "/tmp/openshell-dummy.key",
        "-out",
        "/tmp/openshell-dummy.crt",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=openshell-dummy",
        unit=f"{LXD_APP}/0",
    )
    machine_juju.exec(
        "lxc",
        "config",
        "trust",
        "add",
        "/tmp/openshell-dummy.crt",
        unit=f"{LXD_APP}/0",
    )
    machine_juju.exec(
        "rm", "-f", "/tmp/openshell-dummy.key", "/tmp/openshell-dummy.crt", unit=f"{LXD_APP}/0"
    )


def _prime_lxd_image_store(machine_juju: jubilant.Juju) -> None:
    """Ensure the managed LXD has the default sandbox image alias."""
    script = (
        "import json, subprocess, tempfile, tarfile, io, os, sys\n"
        "res = subprocess.run(['lxc', 'image', 'alias', 'list', '--format=json'], "
        "capture_output=True, text=True)\n"
        "aliases = json.loads(res.stdout) if res.returncode == 0 and res.stdout else []\n"
        "if any(a.get('name') == 'openshell-sandbox' for a in aliases):\n"
        "    sys.exit(0)\n"
        "img_res = subprocess.run(['lxc', 'image', 'list', '--format=json'], "
        "capture_output=True, text=True)\n"
        "imgs = json.loads(img_res.stdout) if img_res.returncode == 0 and img_res.stdout else []\n"
        "if imgs:\n"
        "    subprocess.run(['lxc', 'image', 'alias', 'create', 'openshell-sandbox', "
        "imgs[0]['fingerprint']], check=True)\n"
        "    sys.exit(0)\n"
        "meta = b'architecture: x86_64\\ncreation_date: 1600000000\\nproperties:\\n"
        "  description: openshell sandbox\\n  os: ubuntu\\n  release: noble\\n'\n"
        "with tempfile.TemporaryDirectory() as td:\n"
        "    m = os.path.join(td, 'm.tar.gz')\n"
        "    r = os.path.join(td, 'r.tar.gz')\n"
        "    with tarfile.open(m, 'w:gz') as t:\n"
        "        ti = tarfile.TarInfo('metadata.yaml')\n"
        "        ti.size = len(meta)\n"
        "        t.addfile(ti, io.BytesIO(meta))\n"
        "    with tarfile.open(r, 'w:gz') as t:\n"
        "        pass\n"
        "    subprocess.run(['lxc', 'image', 'import', m, r, '--alias', 'openshell-sandbox'], "
        "check=True)\n"
    )
    machine_juju.exec("python3", "-c", script, unit=f"{LXD_APP}/0")


def _wait_for_managed_lxd_ready(machine_juju: jubilant.Juju, timeout: int = 300) -> None:
    """Poll the managed LXD until the charm's pylxd client can list certificates."""
    deadline = time.monotonic() + timeout
    probe = (
        "import sys; "
        "sys.path.insert(0, '/var/lib/juju/agents/unit-lxd-0/charm/venv'); "
        "import pylxd; "
        "list(pylxd.Client().certificates.all())"
    )
    while True:
        try:
            machine_juju.exec("python3", "-c", probe, unit=f"{LXD_APP}/0")
            return
        except (jubilant.CLIError, jubilant.TaskError):
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


@pytest.fixture(scope="module")
def machine_lxd_offer() -> tuple[str, jubilant.Juju]:
    """Create a machine model, deploy the lxd charm, and offer its https endpoint."""
    if shutil.which("juju") is None:  # noqa: F821
        pytest.skip("juju binary not found; skipping offer provider tests")

    machine_model = f"{MACHINE_MODEL_PREFIX}-{uuid.uuid4().hex[:8]}"
    machine_juju = jubilant.Juju()
    machine_juju.add_model(machine_model, cloud="localhost", controller=LXD_CONTROLLER)

    try:
        machine_juju.deploy(
            LXD_APP,
            app=LXD_APP,
            channel="latest/stable",
            trust=True,
            config={"lxd-listen-https": "true"},
        )
        machine_juju.wait(lambda s: jubilant.all_active(s, LXD_APP), timeout=1800)
        # The charm can report active before the LXD API is ready to answer
        # certificate queries; prime the trust store and wait for the pylxd
        # client the charm uses to be able to iterate over certificates.
        _prime_lxd_certificate_store(machine_juju)
        _prime_lxd_image_store(machine_juju)
        _wait_for_managed_lxd_ready(machine_juju)
        machine_juju.offer(LXD_APP, endpoint="https")
        # Give the offer a moment to publish.
        time.sleep(5)
        yield machine_model, machine_juju
    finally:
        # Capture debug logs from the machine model before tearing it down so
        # hook failures in the lxd charm can be diagnosed.
        try:
            status = machine_juju.status()
            lxd_app = status.apps.get(LXD_APP)
            if lxd_app is not None and lxd_app.app_status.current == "error":
                logger.error("lxd charm is in error state; capturing debug logs")
                log_output = machine_juju.cli("debug-log", "--replay", "--no-tail")
                logger.error("lxd debug-log:\n%s", log_output)
        except (jubilant.CLIError, jubilant.TaskError):
            logger.exception("failed to capture lxd debug logs")

        # ``add_model`` sets ``self.model`` to ``<controller>:<model>``; use the
        # fully-qualified form so teardown targets the LXD controller even if the
        # CLI's current controller is different.
        model_to_destroy = machine_juju.model or f"{LXD_CONTROLLER}:{machine_model}"
        machine_juju.destroy_model(
            model_to_destroy,
            destroy_storage=True,
            force=True,
            no_wait=True,
        )


class TestLxdOfferProvider:
    """Trust lifecycle and sandbox e2e for the cross-model offer provider path."""

    def test_offer_relation_registers_trust(
        self,
        juju: jubilant.Juju,
        machine_lxd_offer: tuple[str, jubilant.Juju],
    ) -> None:
        """Consuming the lxd offer registers the gateway's client cert on the managed LXD."""
        machine_model, machine_juju = machine_lxd_offer
        juju.consume(f"{machine_model}.{LXD_APP}", OFFER_ALIAS, controller=LXD_CONTROLLER)
        juju.integrate(f"{APP_NAME}:lxd", f"{OFFER_ALIAS}:https")

        def _no_offer_error(status: jubilant.Status) -> bool:
            offer = status.app_endpoints.get(OFFER_ALIAS)
            if offer is not None and offer.app_status.current == "error":
                try:
                    log_output = machine_juju.debug_log(limit=500)
                    logger.error("lxd debug-log on offer error:\n%s", log_output)
                except Exception:
                    logger.exception("failed to capture lxd debug logs")
                pytest.fail(f"{OFFER_ALIAS} is in error state: {offer.app_status.message}")
            return False

        juju.wait(
            lambda s: jubilant.all_active(s, APP_NAME),
            error=_no_offer_error,
            timeout=900,
        )

        assert_trust_registered(
            juju,
            lambda: managed_lxd_trust_fingerprints(machine_juju),
        )

    def test_offer_unrelate_withdraws_trust(
        self,
        juju: jubilant.Juju,
        machine_lxd_offer: tuple[str, jubilant.Juju],
    ) -> None:
        """Removing the cross-model relation withdraws the gateway's client cert."""
        _, machine_juju = machine_lxd_offer
        juju.cli("remove-relation", f"{APP_NAME}:lxd", f"{OFFER_ALIAS}:https")
        juju.cli("remove-saas", OFFER_ALIAS)
        _wait_for_gateway_blocked(juju)

        assert_trust_withdrawn(
            juju,
            lambda: managed_lxd_trust_fingerprints(machine_juju),
        )

    def test_sandbox_ops_via_offer(
        self,
        juju: jubilant.Juju,
        gateway_url: str,
        machine_lxd_offer: tuple[str, jubilant.Juju],
        requires_sandbox_e2e: None,
        openshell_available: None,
    ) -> None:
        """Gated: the openshell CLI connects to the gateway over the offer path."""
        machine_model, machine_juju = machine_lxd_offer

        # Re-establish the offer relation if a previous test removed it.
        status = juju.status()
        if OFFER_ALIAS not in status.apps:
            juju.consume(f"{machine_model}.{LXD_APP}", OFFER_ALIAS, controller=LXD_CONTROLLER)
        juju.integrate(f"{APP_NAME}:lxd", f"{OFFER_ALIAS}:https")
        juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=900)

        creds = prepare_openshell_client(juju, gateway_url)
        _run_gated_sandbox_e2e(
            gateway_url=creds["gateway_url"],
            issuer_url=creds["issuer_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            audience=creds["audience"],
            gateway_name="integration-test-gateway-offer",
            sandbox_name="integration-test-sandbox-offer",
        )
