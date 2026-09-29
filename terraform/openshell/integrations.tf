# -------------- # Persistence -------------- #

resource "juju_integration" "gateway_database" {
  model_uuid = local.model_uuid

  application {
    name     = module.gateway.app_name
    endpoint = module.gateway.requires.database
  }

  application {
    name     = juju_application.postgresql_gateway.name
    endpoint = "database"
  }
}

# -------------- # Identity -------------- #

# The gateway consumes the Canonical Identity Platform's `oauth` offer rather
# than this stack deploying Hydra. The platform is its own deployment, with its
# own models, database and login UI:
# https://canonical-identity.readthedocs-hosted.com/identity-platform/

resource "juju_integration" "gateway_oauth" {
  model_uuid = local.model_uuid

  application {
    name     = module.gateway.app_name
    endpoint = module.gateway.requires.oauth
  }

  application {
    offer_url = var.identity.oauth_offer_url
  }
}

# The gateway verifies the issuer's TLS certificate during OIDC discovery. The
# identity platform signs it with its own CA, which is not in the gateway
# image's trust store, so that CA has to be transferred in or discovery fails.

resource "juju_integration" "gateway_identity_ca" {
  count = var.identity.send_ca_cert_offer_url != null ? 1 : 0

  model_uuid = local.model_uuid

  application {
    name     = module.gateway.app_name
    endpoint = module.gateway.requires.receive_ca_cert
  }

  application {
    offer_url = var.identity.send_ca_cert_offer_url
  }
}

# -------------- # Ingress -------------- #

# Hydra publishes its issuer URL from its public route, and the gateway's OIDC
# discovery has to reach that same URL, so both sides go through one Traefik.

# Only the gateway's own gRPC route. The identity platform's applications are
# behind its own Traefik; this one exists to give the gateway a TLS-passthrough
# entry point on 8443, which is not something to mix into a shared ingress.

resource "juju_integration" "gateway_ingress" {
  model_uuid = local.model_uuid

  application {
    name     = module.gateway.app_name
    endpoint = module.gateway.requires.ingress
  }

  application {
    name     = juju_application.traefik.name
    endpoint = "traefik-route"
  }
}

# -------------- # TLS -------------- #

resource "juju_integration" "certificates" {
  for_each = {
    gateway = {
      app_name = module.gateway.app_name
      endpoint = module.gateway.requires.certificates
    }
    traefik = {
      app_name = juju_application.traefik.name
      endpoint = "certificates"
    }
  }
  model_uuid = local.model_uuid

  application {
    name     = each.value.app_name
    endpoint = each.value.endpoint
  }

  application {
    name     = juju_application.self_signed_certificates.name
    endpoint = "certificates"
  }
}

# -------------- # Optional: credentials store -------------- #

resource "juju_integration" "gateway_vault" {
  count = local.vault_enabled ? 1 : 0

  model_uuid = local.model_uuid

  application {
    name     = module.gateway.app_name
    endpoint = module.gateway.requires.vault_kv
  }

  application {
    name     = juju_application.vault[0].name
    endpoint = "vault-kv"
  }
}

# -------------- # Optional: metrics -------------- #

resource "juju_integration" "gateway_metrics" {
  count = local.collector_enabled ? 1 : 0

  model_uuid = local.model_uuid

  application {
    name     = module.gateway.app_name
    endpoint = module.gateway.provides.metrics_endpoint
  }

  application {
    name     = juju_application.opentelemetry_collector[0].name
    endpoint = "metrics-endpoint"
  }
}

# -------------- # Optional: cross-model COS -------------- #

# The collector refuses to scrape until it has somewhere to forward to, so a
# collector without this integration (or another downstream) sits blocked.

resource "juju_integration" "collector_remote_write" {
  count = local.collector_enabled && local.cos_metrics_enabled ? 1 : 0

  model_uuid = local.model_uuid

  application {
    name     = juju_application.opentelemetry_collector[0].name
    endpoint = "send-remote-write"
  }

  application {
    offer_url = var.cos.remote_write_offer_url
  }
}

resource "juju_integration" "gateway_dashboards" {
  count = local.cos_dashboards_enabled ? 1 : 0

  model_uuid = local.model_uuid

  application {
    name     = module.gateway.app_name
    endpoint = module.gateway.provides.grafana_dashboard
  }

  application {
    offer_url = var.cos.grafana_dashboards_offer_url
  }
}
