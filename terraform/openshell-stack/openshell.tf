# -------------- # OpenShell -------------- #

# The existing in-repo product module, composed unchanged. Everything is
# forwarded from `var.openshell`, and the model is `models.openshell`. Only
# the identity platform's oauth offer is passed through: the product module
# owns that one integration - its `identity.oauth_offer_url` is required and
# unconditional - while every other cross-pillar integration is declared
# below.

module "openshell" {
  source = "../openshell"

  model = var.models.openshell
  risk  = var.openshell.risk
  ha    = var.openshell.ha

  external_hostname = var.openshell.external_hostname
  oidc              = var.openshell.oidc

  gateway                  = var.openshell.gateway
  integrator               = var.openshell.integrator
  postgresql               = var.openshell.postgresql
  traefik                  = var.openshell.traefik
  self_signed_certificates = var.openshell.self_signed_certificates
  vault                    = var.openshell.vault
  opentelemetry_collector  = local.openshell_opentelemetry_collector

  # The identity platform's oauth offer. `send_ca_cert_offer_url` stays
  # unset: the product module creates that integration only when the URL is
  # set, and it decides with `count` - which Terraform has to know at plan,
  # while this stack's offer only exists at apply. The gateway's CA trust is
  # wired below.
  identity = {
    oauth_offer_url = module.identity_platform.oauth_offer_url
  }
}

# -------------- # Gateway cross-pillar integrations -------------- #

# The gateway's remaining integrations with the other pillars: the issuer CA
# it has to trust for OIDC discovery, the collector's remote-write
# downstream, and the dashboard offer. The product module owns these same
# integrations, driven by its `identity` and `cos` variables, for operators
# who bring their own pillars - but its conditional resources count on
# `var.x != null`, and a composed offer URL is unknown until the apply has
# created the offer. Terraform cannot plan such a count, so in this
# composition the integrations are declared here instead, unconditionally,
# and the product module's variables stay unset.

# The endpoint names are the charms' own - `receive-ca-cert` and
# `grafana-dashboard` on the gateway, `send-remote-write` on the collector -
# wired the way the product module wires them.

resource "juju_integration" "gateway_identity_ca" {
  model_uuid = module.openshell.model_uuid

  application {
    name     = module.openshell.app_names.gateway
    endpoint = "receive-ca-cert"
  }

  application {
    offer_url = juju_offer.core_send_ca_cert.url
  }
}

resource "juju_integration" "collector_remote_write" {
  count = local.openshell_collector_enabled ? 1 : 0

  model_uuid = module.openshell.model_uuid

  application {
    name     = module.openshell.app_names.opentelemetry_collector
    endpoint = "send-remote-write"
  }

  application {
    offer_url = module.cos_lite.offers.prometheus_receive_remote_write.url
  }
}

resource "juju_integration" "gateway_dashboards" {
  model_uuid = module.openshell.model_uuid

  application {
    name     = module.openshell.app_names.gateway
    endpoint = "grafana-dashboard"
  }

  application {
    offer_url = module.cos_lite.offers.grafana_dashboards.url
  }
}
