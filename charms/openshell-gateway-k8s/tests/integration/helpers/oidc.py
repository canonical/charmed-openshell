"""OIDC and CA trust preparation helpers for client authentication."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from .command import run_cmd
from .constants import APP_NAME, HYDRA_APP, OIDC_ADMIN_ROLE, OIDC_AUDIENCE, TLS_APP

if TYPE_CHECKING:
    import jubilant

logger = logging.getLogger(__name__)


def trust_self_signed_ca(juju: jubilant.Juju) -> str:
    """Install the self-signed CA into the host trust store."""
    result = juju.run(f"{TLS_APP}/0", "get-ca-certificate")
    assert result.status == "completed", result
    ca_pem = result.results.get("ca-certificate")
    assert ca_pem, "get-ca-certificate did not return a certificate"

    cert_dir = Path.home() / ".local" / "share" / "openshell-gateway-integration"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_file = cert_dir / "ca.crt"
    cert_file.write_text(ca_pem)

    system_file = Path("/usr/local/share/ca-certificates") / "openshell-gateway-ca.crt"
    if os.geteuid() == 0:
        shutil.copy2(cert_file, system_file)
        run_cmd("update-ca-certificates")
    else:
        install = run_cmd("sudo", "cp", str(cert_file), str(system_file))
        if install.returncode == 0:
            run_cmd("sudo", "update-ca-certificates")
        else:
            logger.warning(
                "Could not install CA system-wide (sudo failed); relying on SSL_CERT_FILE"
            )

    return ca_pem


def get_oidc_client_config(juju: jubilant.Juju) -> dict[str, str]:
    """Return OIDC client configuration advertised by the gateway charm."""
    result = juju.run(f"{APP_NAME}/0", "get-oidc-client-config")
    assert result.status == "completed", result
    return dict(result.results)


def create_hydra_m2m_client(juju: jubilant.Juju, *, audience: str) -> tuple[str, str]:
    """Create a Hydra OAuth2 client for the openshell snap M2M flow."""
    result = juju.run(
        f"{HYDRA_APP}/0",
        "create-oauth-client",
        params={
            "name": "openshell-cli-m2m",
            "grant-types": ["client_credentials"],
            "scope": [OIDC_ADMIN_ROLE],
            "audience": [audience],
            "token-endpoint-auth-method": "client_secret_post",
        },
    )
    assert result.status == "completed", result
    client_id = result.results.get("client-id")
    client_secret = result.results.get("client-secret") or result.results.get("secret")
    assert client_id and client_secret, f"missing client credentials: {result.results}"
    return client_id, client_secret


def prepare_openshell_client(juju: jubilant.Juju, gateway_url: str) -> dict[str, str]:
    """Prepare host CA trust and Hydra M2M credentials for the openshell snap."""
    trust_self_signed_ca(juju)
    oidc = get_oidc_client_config(juju)
    audience = oidc.get("audience") or OIDC_AUDIENCE
    issuer_url = oidc["issuer"]
    client_id, client_secret = create_hydra_m2m_client(juju, audience=audience)
    return {
        "gateway_url": gateway_url,
        "issuer_url": issuer_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
    }
