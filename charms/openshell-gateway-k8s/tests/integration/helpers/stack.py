"""Deployment and wiring of gateway and supporting charms."""

from __future__ import annotations

import logging

import jubilant

from .constants import (
    APP_NAME,
    DB_GATEWAY_APP,
    DB_HYDRA_APP,
    HYDRA_APP,
    INFRA_APPS,
    LOGIN_UI_APP,
    OIDC_ADMIN_ROLE,
    OIDC_AUDIENCE,
    OIDC_ROLES_CLAIM,
    OIDC_USER_ROLE,
    TLS_APP,
    TRAEFIK_APP,
)
from .juju_wait import fail_on_app_error
from .kube import get_traefik_lb_address

logger = logging.getLogger(__name__)


def deploy_infrastructure(juju: jubilant.Juju) -> None:
    """Deploy and relate the supporting charms for the gateway."""
    logger.info("Deploying supporting infrastructure")

    juju.deploy("postgresql-k8s", app=DB_GATEWAY_APP, channel="14/stable", trust=True)
    juju.deploy("postgresql-k8s", app=DB_HYDRA_APP, channel="14/stable", trust=True)
    juju.deploy("self-signed-certificates", app=TLS_APP, channel="1/stable")
    juju.deploy("traefik-k8s", app=TRAEFIK_APP, channel="latest/stable", trust=True)
    juju.deploy("hydra", app=HYDRA_APP, channel="latest/stable", trust=True)
    juju.deploy(
        "identity-platform-login-ui-operator",
        app=LOGIN_UI_APP,
        channel="latest/stable",
        trust=True,
    )
    # Hydra needs cluster-scoped trust to manage its Kubernetes resources.
    juju.cli("trust", HYDRA_APP, "--scope=cluster")

    logger.info("Relating infrastructure charms")
    juju.integrate(f"{HYDRA_APP}:pg-database", f"{DB_HYDRA_APP}:database")
    juju.integrate(f"{HYDRA_APP}:ui-endpoint-info", f"{LOGIN_UI_APP}:ui-endpoint-info")
    juju.integrate(f"{HYDRA_APP}:public-route", f"{TRAEFIK_APP}:traefik-route")
    juju.integrate(f"{HYDRA_APP}:internal-route", f"{TRAEFIK_APP}:traefik-route")
    juju.integrate(f"{LOGIN_UI_APP}:public-route", f"{TRAEFIK_APP}:traefik-route")
    juju.integrate(f"{TRAEFIK_APP}:certificates", f"{TLS_APP}:certificates")

    logger.info("Waiting for infrastructure relations to converge")
    juju.wait(
        lambda s: jubilant.all_active(s, *INFRA_APPS) and jubilant.all_agents_idle(s, *INFRA_APPS),
        error=fail_on_app_error(juju, *INFRA_APPS, hook_retry_limit=1),
        timeout=1800,
    )


def deploy_gateway(juju: jubilant.Juju, charm_file: str, gateway_image: str) -> str:
    """Deploy the gateway charm, wire it up, and return the public gateway URL."""
    logger.info("Deploying OpenShell Gateway charm")
    juju.deploy(
        charm_file,
        app=APP_NAME,
        resources={"gateway-image": gateway_image},
        config={
            "oidc-admin-role": OIDC_ADMIN_ROLE,
            "oidc-user-role": OIDC_USER_ROLE,
            "oidc-audience": OIDC_AUDIENCE,
            "oidc-roles-claim": OIDC_ROLES_CLAIM,
        },
    )

    logger.info("Relating gateway to infrastructure")
    juju.integrate(f"{APP_NAME}:database", f"{DB_GATEWAY_APP}:database")
    juju.integrate(f"{APP_NAME}:certificates", f"{TLS_APP}:certificates")
    juju.integrate(f"{APP_NAME}:oauth", f"{HYDRA_APP}:oauth")
    juju.integrate(f"{APP_NAME}:ingress", f"{TRAEFIK_APP}:traefik-route")

    logger.info("Discovering Traefik LoadBalancer address for external hostname")
    lb_address = get_traefik_lb_address(juju)
    external_hostname = lb_address
    logger.info("Using external hostname %s", external_hostname)

    juju.config(TRAEFIK_APP, {"external_hostname": external_hostname})
    juju.config(APP_NAME, {"external-hostname": external_hostname})

    return f"https://{external_hostname}:8443"
