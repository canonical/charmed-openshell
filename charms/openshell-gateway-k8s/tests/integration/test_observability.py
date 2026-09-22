"""Integration tests for the gateway's Prometheus metrics endpoint.

``opentelemetry-collector-k8s`` scrapes the gateway over the
``metrics-endpoint`` relation. The collector refuses to scrape anything until
it has somewhere to forward to, so the stack includes ``prometheus-k8s`` as
that downstream — which also gives the test somewhere to read the result back
from. The assertion is on the ``up`` series Prometheus stores for the gateway
target: a scrape job naming an unreachable target joins exactly as happily as
one that works, so "the relation is there" proves nothing.
"""

from __future__ import annotations

import json
import logging
import time

import jubilant
import pytest

from .conftest import (
    APP_NAME,
    CONTAINER_NAME,
    INTEGRATOR_APP,
    _wait_for_gateway_stack,
    deploy_integrator,
    gateway_status,
    kubectl,
)
from .lxd_host import HostLxdEndpoint

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.observability]

COLLECTOR_APP = "opentelemetry-collector-k8s"
PROMETHEUS_APP = "prometheus-k8s"
METRICS_PORT = 9090


@pytest.fixture(scope="module", autouse=True)
def _observability_stack(
    juju: jubilant.Juju,
    host_lxd_endpoint: HostLxdEndpoint,
    integrator_charm_file: str,
    _cleanup_host_lxd_gateway_trust: None,
) -> None:
    """Bring the gateway to active, then deploy the collector and its backend."""
    deploy_integrator(juju, host_lxd_endpoint, charm_file=integrator_charm_file)
    juju.wait(lambda s: jubilant.all_active(s, INTEGRATOR_APP), timeout=900)
    juju.integrate(f"{APP_NAME}:lxd", f"{INTEGRATOR_APP}:https")
    _wait_for_gateway_stack(juju)

    juju.deploy(COLLECTOR_APP, channel="2/stable", trust=True)
    juju.deploy(PROMETHEUS_APP, channel="1/stable", trust=True)
    # The collector blocks until it has a downstream; relating Prometheus is
    # what makes it start scraping at all.
    juju.integrate(f"{COLLECTOR_APP}:send-remote-write", f"{PROMETHEUS_APP}:receive-remote-write")
    juju.integrate(f"{APP_NAME}:metrics-endpoint", f"{COLLECTOR_APP}:metrics-endpoint")
    juju.wait(
        lambda s: (
            jubilant.all_active(s, APP_NAME, COLLECTOR_APP, PROMETHEUS_APP)
            and jubilant.all_agents_idle(s, APP_NAME, COLLECTOR_APP, PROMETHEUS_APP)
        ),
        timeout=1800,
    )


def _prometheus_query(juju: jubilant.Juju, query: str) -> list[dict]:
    """Run an instant query against Prometheus and return the result vector.

    The query goes through the unit's charm container, which has ``curl`` and
    shares the pod network with Prometheus. The test host reaches neither the
    pod IP nor the service IP, so this is the route that works from anywhere
    the suite runs.
    """
    model = juju.model.split(":")[-1]
    raw = kubectl(
        "-n",
        model,
        "exec",
        f"{PROMETHEUS_APP}-0",
        "-c",
        "charm",
        "--",
        "curl",
        "-sS",
        "--max-time",
        "10",
        "--get",
        "--data-urlencode",
        f"query={query}",
        "http://localhost:9090/api/v1/query",
    )
    payload = json.loads(raw)
    if payload.get("status") != "success":
        pytest.fail(f"prometheus query {query!r} failed: {raw}")
    return payload["data"]["result"]


class TestMetricsEndpoint:
    def test_gateway_serves_the_metrics_endpoint(self, juju: jubilant.Juju) -> None:
        """The workload listens on the configured port and answers /metrics.

        Asserted on the fetch succeeding rather than on any particular series:
        OpenShell v0.0.116 registers its collectors lazily, so an idle gateway
        legitimately returns an empty body. A listener that answers on the
        configured port is the part the charm is responsible for.

        ``busybox wget -q`` exits non-zero on a connection failure or a non-2xx
        response, and jubilant raises on a non-zero exit, so the call either
        returns or fails the test. The rock ships busybox rather than curl, and
        the probe deliberately avoids a shell: ``wget -S`` would write its
        status line to stderr, which ``juju ssh`` does not return, and quoting
        a ``bash -c`` string through ``juju ssh`` does not survive.
        """
        url = f"http://127.0.0.1:{METRICS_PORT}/metrics"
        try:
            juju.ssh(
                f"{APP_NAME}/0",
                "busybox",
                "wget",
                "-q",
                "-O",
                "/dev/null",
                "-T",
                "10",
                url,
                container=CONTAINER_NAME,
            )
        except jubilant.CLIError as exc:
            pytest.fail(f"the gateway did not serve {url}: {exc.stdout}\n{exc.stderr}")

    def test_collector_has_the_gateway_target_up(self, juju: jubilant.Juju) -> None:
        """The gateway is scraped, not merely configured as a target.

        ``up`` is the synthetic series every Prometheus-compatible scraper
        writes per target: 1 when the last scrape succeeded. A wired but broken
        target yields 0, and a target that was never scraped yields no series
        at all, so this distinguishes all three.
        """
        deadline = time.monotonic() + 600
        while True:
            results = _prometheus_query(juju, f'up{{juju_application="{APP_NAME}"}}')
            if results and all(sample["value"][1] == "1" for sample in results):
                assert len(results) == 1, results
                return
            if time.monotonic() > deadline:
                pytest.fail(
                    f"prometheus has no healthy up series for {APP_NAME} after 600s: {results}"
                )
            time.sleep(15)

    def test_scrape_job_names_the_configured_port(self, juju: jubilant.Juju) -> None:
        """The published scrape job targets the port the charm opened.

        Read from the collector's side of the relation: in ``juju show-unit``,
        ``application-data`` is the *remote* application's databag, so the
        gateway's own published jobs are only visible from the consumer.
        """
        data = juju.cli("show-unit", f"{COLLECTOR_APP}/0", "--format", "json")
        unit = json.loads(data)[f"{COLLECTOR_APP}/0"]
        scrape = next(
            rel
            for rel in unit.get("relation-info", [])
            if rel.get("endpoint") == "metrics-endpoint"
        )
        jobs = json.loads(scrape["application-data"]["scrape_jobs"])
        targets = [
            target
            for job in jobs
            for static in job.get("static_configs", [])
            for target in static.get("targets", [])
        ]
        assert targets == [f"*:{METRICS_PORT}"], targets

    def test_disabling_metrics_is_reported_not_silent(self, juju: jubilant.Juju) -> None:
        """Turning the listener off with a collector related is observable.

        Asserted through ``get-gateway-status`` rather than the unit status
        message: ops surfaces only one ActiveStatus, so the ingress
        component's own note masks this one whenever it has something to say.
        The action always answers.
        """
        juju.config(APP_NAME, {"metrics-port": 0})
        try:
            deadline = time.monotonic() + 600
            while True:
                status = gateway_status(juju)
                if (
                    status.get("metrics-port") == "0"
                    and status.get("metrics-endpoint-related") == "True"
                ):
                    break
                if time.monotonic() > deadline:
                    pytest.fail(f"gateway did not report metrics as disabled: {status}")
                time.sleep(10)
        finally:
            juju.config(APP_NAME, {"metrics-port": METRICS_PORT})
            juju.wait(lambda s: jubilant.all_active(s, APP_NAME), timeout=900)

        restored = gateway_status(juju)
        assert restored["metrics-port"] == str(METRICS_PORT), restored
