"""Constants and shared configuration for OpenShell Gateway integration tests."""

from __future__ import annotations

import os
from pathlib import Path

CHARM_DIR = Path(__file__).resolve().parent.parent.parent.parent
REPO_ROOT = CHARM_DIR.parent.parent

APP_NAME = "openshell-gateway-k8s"
CONTAINER_NAME = "gateway"
DB_GATEWAY_APP = "postgresql-gateway"
DB_HYDRA_APP = "postgresql-hydra"
HYDRA_APP = "hydra"
LOGIN_UI_APP = "login-ui"
TRAEFIK_APP = "traefik-k8s"
TLS_APP = "self-signed-certificates"
INTEGRATOR_APP = "lxd-integrator-k8s"

INFRA_APPS = [
    DB_GATEWAY_APP,
    DB_HYDRA_APP,
    HYDRA_APP,
    LOGIN_UI_APP,
    TRAEFIK_APP,
    TLS_APP,
]

OIDC_ADMIN_ROLE = "gw-admin"
OIDC_USER_ROLE = "gw-user"
OIDC_AUDIENCE = "openshell-cli"
OIDC_ROLES_CLAIM = "scp"

IT_PROJECT = os.environ.get("OPENSHELL_TEST_LXD_PROJECT", "openshell-it")

K8S_CONTROLLER = os.environ.get("JUJU_CONTROLLER", "concierge-k8s")
LXD_CONTROLLER = os.environ.get("JUJU_LXD_CONTROLLER", "concierge-lxd")
