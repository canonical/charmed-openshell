# -------------- # Identity platform -------------- #

# The Canonical Identity Platform, composed as published: Hydra, Kratos and
# the login UI in the iam model, consuming the core model's offers.
# https://canonical-identity.readthedocs-hosted.com/

module "identity_platform" {
  source = "git::https://github.com/canonical/iam-bundle-integration?ref=${var.identity_platform.ref}"

  model = local.models.iam.model_uuid

  hydra                                 = var.identity_platform.hydra
  kratos                                = var.identity_platform.kratos
  login_ui                              = var.identity_platform.login_ui
  enable_kratos_external_idp_integrator = var.identity_platform.enable_kratos_external_idp_integrator
  kratos_external_idp_integrator        = var.identity_platform.kratos_external_idp_integrator

  # The core model's offers. Terraform orders the iam module after these
  # resources because their URLs are its inputs; no explicit depends_on.
  postgresql_offer_url    = juju_offer.core_postgresql.url
  traefik_route_offer_url = juju_offer.core_traefik_route.url

  # Its COS inputs stay unset. The module treats a null offer URL as "no
  # integration", and it decides with `count` - which Terraform has to know
  # at plan, while an offer this stack creates only exists at apply. The
  # platform's telemetry is wired below instead, where nothing is
  # conditional.
}

# -------------- # Identity platform telemetry -------------- #

# The platform's own "integrate with COS" pattern, as direct offers from
# cos-lite, mirrored onto every application the iam module fronts: Hydra,
# Kratos and the login UI each scrape into Prometheus, push logs to Loki and
# publish a dashboard to Grafana. Tracing stays unwired: nothing in this
# stack serves traces.

# This glue cannot be driven through the iam module's COS variables either:
# its own integrations are `count`-guarded on the offer URLs, and the same
# plan-time rule applies. The endpoint names are the charms' own, wired the
# way the iam module wires them.

resource "juju_integration" "iam_metrics" {
  for_each   = local.iam_app_names
  model_uuid = local.models.iam.model_uuid

  # The applications are referenced by name - the iam module exposes no
  # app-name output - so the integrations have to wait for the module to
  # have deployed them.
  depends_on = [module.identity_platform]

  application {
    name     = each.value
    endpoint = "metrics-endpoint"
  }

  application {
    offer_url = module.cos_lite.offers.prometheus_metrics_endpoint.url
  }
}

resource "juju_integration" "iam_logging" {
  for_each   = local.iam_app_names
  model_uuid = local.models.iam.model_uuid
  depends_on = [module.identity_platform]

  application {
    name     = each.value
    endpoint = "logging"
  }

  application {
    offer_url = module.cos_lite.offers.loki_logging.url
  }
}

resource "juju_integration" "iam_dashboards" {
  for_each   = local.iam_app_names
  model_uuid = local.models.iam.model_uuid
  depends_on = [module.identity_platform]

  application {
    name     = each.value
    endpoint = "grafana-dashboard"
  }

  application {
    offer_url = module.cos_lite.offers.grafana_dashboards.url
  }
}
