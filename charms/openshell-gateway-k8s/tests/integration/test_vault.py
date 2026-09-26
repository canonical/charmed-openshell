"""Integration tests for the optional Vault-backed JWT signing-key store.

Vault has to be initialised, unsealed and authorised before it serves
anything, which is slow and is the usual reason vault tests are flaky. The
setup here does each step explicitly and waits on the observable result of it
rather than on a fixed sleep.

The assertions are about the two things that matter: the gateway keeps working
when Vault takes over, and the key it was already signing with survives the
move, so tokens held by live sandboxes stay valid.
"""

from __future__ import annotations

import json
import logging
import time
from typing import NoReturn

import jubilant
import pytest

from .helpers import (
    APP_NAME,
    gateway_status,
    kubectl,
    kubectl_try,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.vault, pytest.mark.integrator]

VAULT_APP = "vault-k8s"
VAULT_RELATION = "vault-kv"

# A pod the kube-scheduler cannot place never recovers by waiting, so the
# API wait stops early once the pod has gone without a node this long.
_SCHEDULING_GRACE_SECONDS = 180


def _vault_address_or_none(juju: jubilant.Juju) -> str | None:
    """Return the address Vault's certificate is valid for, if assigned yet.

    The default ``VAULT_ADDR`` of ``https://127.0.0.1:8200`` does not work:
    vault-k8s issues its certificate for the application address, so a
    loopback call fails verification before it reaches the API.
    """
    app = juju.status().apps.get(VAULT_APP)
    if app is None or not app.address:
        return None
    return f"https://{app.address}:8200"


def _vault_address(juju: jubilant.Juju) -> str:
    """Return the Vault address, failing the test when there is none."""
    address = _vault_address_or_none(juju)
    if address is None:
        pytest.fail(f"{VAULT_APP} has no application address yet")
    return address


def _vault_run(
    juju: jubilant.Juju,
    subcommand: list[str],
    *positional: str,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> str:
    """Run a ``vault`` CLI command inside the vault-k8s workload container.

    The image is distroless and has no shell, so the connection cannot be
    configured through the environment and has to go on the command line.
    Vault's flag parser stops at the first non-flag argument, so the global
    flags are placed after the subcommand and before any positional — which
    is why *subcommand* and *positional* are separate arguments here rather
    than one list.

    Skipping verification is test setup, not something the charm relies on:
    vault-k8s signs its certificate with its own CA, which is not in the
    workload image's trust store, and the address is pinned separately.
    """
    model = juju.model.split(":")[-1]
    flags = [f"-address={_vault_address(juju)}", "-tls-skip-verify"]
    return kubectl(
        "-n",
        model,
        "exec",
        f"{VAULT_APP}-0",
        "-c",
        "vault",
        "--",
        "vault",
        *subcommand,
        *flags,
        *positional,
        allowed_returncodes=allowed_returncodes,
    )


def _vault_status(juju: jubilant.Juju) -> str:
    """Return ``vault status -format=json``.

    Exit code 2 means "sealed", which is exactly the state this is asked
    about, so it is not treated as a failure.
    """
    return _vault_run(juju, ["status", "-format=json"], allowed_returncodes=(0, 1, 2))


def _vault_pod_unscheduled_reason(juju: jubilant.Juju) -> str | None:
    """Return why the vault pod has no node assigned, or None when scheduled.

    A pod that does not exist yet — the StatefulSet has not created it — also
    counts as scheduled: that is a normal early state the probe tolerates.
    """
    model = juju.model.split(":")[-1]
    pod = f"{VAULT_APP}-0"
    result = kubectl_try("-n", model, "get", "pod", pod, "-o", "jsonpath={.spec.nodeName}")
    if result.returncode != 0 or result.stdout.strip():
        return None
    condition = kubectl_try(
        "-n",
        model,
        "get",
        "pod",
        pod,
        "-o",
        "jsonpath={.status.conditions[?(@.type=='PodScheduled')].reason}",
    )
    return condition.stdout.strip() or "no node assigned"


def _fail_unscheduled(juju: jubilant.Juju, reason: str) -> NoReturn:
    """Capture scheduler diagnostics for the vault pod and fail the wait."""
    model = juju.model.split(":")[-1]
    pod = f"{VAULT_APP}-0"
    describe = kubectl_try("-n", model, "describe", "pod", pod)
    events = kubectl_try(
        "-n",
        model,
        "get",
        "events",
        "--field-selector",
        f"involvedObject.name={pod}",
        "--sort-by",
        ".lastTimestamp",
    )
    logger.error(
        "kubectl describe pod %s:\n%s\nkubectl get events for %s:\n%s",
        pod,
        describe.stdout,
        pod,
        events.stdout,
    )
    pytest.fail(
        f"{pod} stayed unscheduled for {_SCHEDULING_GRACE_SECONDS}s ({reason}); the "
        "vault API cannot answer on a pod with no node, and waiting the full "
        "timeout would not change that"
    )


def _wait_for_vault_api(juju: jubilant.Juju, timeout: int = 900) -> None:
    """Wait until ``vault status`` answers inside the workload container.

    The unit can be up well before the application has an address and the
    workload is accepting API calls, so this polls with a tolerant probe: a
    command that has not succeeded yet must not end the test.

    An unscheduled pod is different: no amount of waiting puts a node
    assignment on a pod the scheduler has declined. The poll therefore also
    watches ``spec.nodeName``; once the pod has gone without a node longer
    than the scheduling grace, it captures ``kubectl describe pod`` and the
    pod's events and fails immediately with the scheduler's reason, rather
    than looping blind until the timeout.
    """
    deadline = time.monotonic() + timeout
    unscheduled_since: float | None = None
    last = ""
    while True:
        reason = _vault_pod_unscheduled_reason(juju)
        if reason is None:
            unscheduled_since = None
        else:
            now = time.monotonic()
            if unscheduled_since is None:
                unscheduled_since = now
                logger.warning(
                    "%s pod is unscheduled (%s); allowing %ss for the scheduler",
                    VAULT_APP,
                    reason,
                    _SCHEDULING_GRACE_SECONDS,
                )
            elif now - unscheduled_since >= _SCHEDULING_GRACE_SECONDS:
                _fail_unscheduled(juju, reason)

        address = _vault_address_or_none(juju)
        if address is not None:
            result = kubectl_try(
                "-n",
                juju.model.split(":")[-1],
                "exec",
                f"{VAULT_APP}-0",
                "-c",
                "vault",
                "--",
                "vault",
                "status",
                "-format=json",
                f"-address={address}",
                "-tls-skip-verify",
            )
            # Exit 2 means sealed, which is the expected state before init.
            if result.returncode in (0, 1, 2) and result.stdout.strip().startswith("{"):
                return
            last = f"{result.returncode}: {result.stdout}\n{result.stderr}"
        else:
            last = f"{VAULT_APP} has no application address yet"
        if time.monotonic() > deadline:
            pytest.fail(f"vault API did not answer within {timeout}s; last: {last}")
        time.sleep(10)


def _initialise_and_unseal(juju: jubilant.Juju) -> str:
    """Initialise and unseal Vault, returning the root token.

    Returns the existing root token when Vault is already initialised, so the
    fixture is safe to re-enter against a model left in place by JUJU_MODEL.
    """
    status = json.loads(_vault_status(juju))
    if status.get("initialized"):
        pytest.fail(
            "vault-k8s is already initialised; this test needs to hold the root "
            "token, so run it against a fresh model"
        )

    result = json.loads(
        _vault_run(
            juju,
            ["operator", "init", "-key-shares=1", "-key-threshold=1", "-format=json"],
        )
    )
    unseal_key = result["unseal_keys_b64"][0]
    root_token = result["root_token"]

    _vault_run(juju, ["operator", "unseal", "-format=json"], unseal_key)

    deadline = time.monotonic() + 300
    while True:
        status = json.loads(_vault_status(juju))
        if not status.get("sealed", True):
            break
        if time.monotonic() > deadline:
            pytest.fail(f"vault stayed sealed: {status}")
        time.sleep(5)

    return root_token


def _authorize_charm(juju: jubilant.Juju, root_token: str) -> None:
    """Hand the charm a token so it can manage Vault's own configuration."""
    secret_uri = juju.cli("add-secret", "vault-approle", f"token={root_token}").strip()
    juju.cli("grant-secret", "vault-approle", VAULT_APP)
    result = juju.run(f"{VAULT_APP}/0", "authorize-charm", {"secret-id": secret_uri})
    if result.status != "completed":
        pytest.fail(f"authorize-charm did not complete: {result.status} {result.results}")


@pytest.fixture(scope="module", autouse=True)
def _vault_backed_gateway(
    juju: jubilant.Juju,
    integrator_provider: None,
) -> None:
    """Bring the gateway up on Juju secrets, then stand Vault up beside it."""
    juju.deploy(VAULT_APP, channel="1.16/stable", trust=True)
    # Vault reports blocked until it is initialised; waiting for "active" here
    # would time out before the test ever got to initialise it.
    juju.wait(
        lambda s: VAULT_APP in s.apps and bool(s.apps[VAULT_APP].units),
        timeout=900,
    )

    _wait_for_vault_api(juju)

    root_token = _initialise_and_unseal(juju)
    _authorize_charm(juju, root_token)
    juju.wait(lambda s: jubilant.all_active(s, VAULT_APP), timeout=900)


def _wait_for_jwt_store(juju: jubilant.Juju, expected: str, timeout: int = 900) -> dict[str, str]:
    """Wait until the gateway reports *expected* as its JWT store."""
    deadline = time.monotonic() + timeout
    while True:
        status = gateway_status(juju)
        if status.get("jwt-store") == expected and status.get("jwt-kid"):
            return status
        if time.monotonic() > deadline:
            pytest.fail(
                f"gateway still reports {status.get('jwt-store')!r}, expected {expected!r}"
            )
        time.sleep(10)


class TestVaultStore:
    def test_relating_vault_migrates_the_existing_key(self, juju: jubilant.Juju) -> None:
        """The key in use survives the move, so live sandbox tokens stay valid."""
        before = _wait_for_jwt_store(juju, "juju-secret")
        assert before["workload-running"] == "True", before

        juju.integrate(f"{APP_NAME}:{VAULT_RELATION}", f"{VAULT_APP}:{VAULT_RELATION}")
        juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=1800)

        after = _wait_for_jwt_store(juju, "vault")
        assert after["jwt-kid"] == before["jwt-kid"], (
            "the signing key changed when Vault took over; every token already "
            "issued to a running sandbox would stop verifying"
        )
        assert after["workload-running"] == "True", after
        assert after["readiness-gaps"] == "none", after

    def test_rotation_goes_through_vault(self, juju: jubilant.Juju) -> None:
        """Rotation targets the active store and reports which one that was."""
        before = _wait_for_jwt_store(juju, "vault")

        result = juju.run(f"{APP_NAME}/0", "rotate-jwt-signing-key")
        assert result.status == "completed", result.status
        assert result.results["store"] == "vault", result.results
        assert result.results["kid"] != before["jwt-kid"], result.results

        juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=900)
        after = _wait_for_jwt_store(juju, "vault")
        assert after["jwt-kid"] == result.results["kid"], after
        assert after["workload-running"] == "True", after
        juju.wait(
            lambda s: jubilant.all_active(s, APP_NAME) and jubilant.all_agents_idle(s, APP_NAME),
            timeout=900,
        )

    def test_removing_vault_falls_back_to_juju_secret(self, juju: jubilant.Juju) -> None:
        """Removing the vault-kv relation reverts the gateway to juju-secret store."""
        _wait_for_jwt_store(juju, "vault")

        juju.cli(
            "remove-relation", f"{APP_NAME}:{VAULT_RELATION}", f"{VAULT_APP}:{VAULT_RELATION}"
        )
        juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=1800)

        after = _wait_for_jwt_store(juju, "juju-secret")
        assert after["workload-running"] == "True", after
        assert after["readiness-gaps"] == "none", after
        assert after.get("jwt-kid"), (
            "gateway has no signing key after reverting to juju-secret store"
        )
