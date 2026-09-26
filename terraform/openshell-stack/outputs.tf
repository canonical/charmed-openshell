output "models" {
  description = "Name and UUID of each pillar model."
  value = {
    openshell = {
      name = module.openshell.model_name
      uuid = module.openshell.model_uuid
    }
    iam = {
      name = local.models.iam.model_name
      uuid = local.models.iam.model_uuid
    }
    core = {
      name = local.models.core.model_name
      uuid = local.models.core.model_uuid
    }
    cos_lite = {
      name = var.models.cos_lite.name
      uuid = module.cos_lite.model_uuid
    }
  }
}

output "offers" {
  description = "Juju offer URLs of the composed stack, for integrating further applications."
  value = {
    oauth                           = module.identity_platform.oauth_offer_url
    send_ca_cert                    = juju_offer.core_send_ca_cert.url
    postgresql                      = juju_offer.core_postgresql.url
    traefik_route                   = juju_offer.core_traefik_route.url
    prometheus_receive_remote_write = module.cos_lite.offers.prometheus_receive_remote_write.url
    prometheus_metrics_endpoint     = module.cos_lite.offers.prometheus_metrics_endpoint.url
    grafana_dashboards              = module.cos_lite.offers.grafana_dashboards.url
    loki_logging                    = module.cos_lite.offers.loki_logging.url
  }
}

output "app_names" {
  description = "Names of the applications in each pillar. The cos-lite pillars' own names come from its components output."
  value = {
    openshell = module.openshell.app_names

    # The iam module has no app-name output, so the names come from the
    # forwarded blocks and the module's own defaults. The optional
    # external-IdP integrator, when enabled, is named in its own block.
    iam = local.iam_app_names

    core = {
      postgresql               = juju_application.postgresql.name
      traefik                  = juju_application.traefik.name
      self_signed_certificates = juju_application.self_signed_certificates.name
    }

    cos_lite = {
      prometheus   = module.cos_lite.components.prometheus.app_name
      grafana      = module.cos_lite.components.grafana.app_name
      loki         = module.cos_lite.components.loki.app_name
      alertmanager = module.cos_lite.components.alertmanager.app_name
      catalogue    = module.cos_lite.components.catalogue.app_name
      traefik      = try(module.cos_lite.components.traefik.app_name, null)
      ssc          = try(module.cos_lite.components.ssc.app_name, null)
    }
  }
}
