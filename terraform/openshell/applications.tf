# -------------- # OpenShell -------------- #

module "gateway" {
  source = "../../charms/openshell-gateway-k8s/terraform"

  model_uuid  = local.model_uuid
  app_name    = var.gateway.app_name
  base        = var.gateway.base
  channel     = local.channels.gateway
  revision    = var.gateway.revision
  units       = local.units.gateway
  constraints = var.gateway.constraints
  config      = local.gateway_config
  resources   = var.gateway.resources
}

# Declared directly rather than through the integrator repository's own
# Terraform module: a module `source` must be a literal, so pointing it at a
# local checkout or an unreleased ref would mean editing this file rather than
# passing a variable. The charm's interface is one relation, so there is little
# the module would add here.

resource "juju_application" "integrator" {
  model_uuid = local.model_uuid
  name       = var.integrator.app_name
  units      = local.units.integrator

  charm {
    name     = "lxd-integrator-k8s"
    channel  = local.channels.integrator
    revision = var.integrator.revision
    base     = var.integrator.base
  }

  constraints = var.integrator.constraints
  config      = var.integrator.config
}

# -------------- # Persistence -------------- #

# Only the gateway's own database. Identity lives in the Canonical Identity
# Platform, which brings its own PostgreSQL.

resource "juju_application" "postgresql_gateway" {
  model_uuid = local.model_uuid
  name       = var.postgresql.gateway_app_name
  units      = local.units.postgresql
  trust      = true

  charm {
    name     = "postgresql-k8s"
    channel  = local.channels.postgresql
    revision = var.postgresql.revision
    base     = var.postgresql.base
  }

  constraints = var.postgresql.constraints
  config      = var.postgresql.config
}

# -------------- # Ingress and TLS -------------- #

resource "juju_application" "traefik" {
  model_uuid = local.model_uuid
  name       = var.traefik.app_name
  units      = local.units.traefik
  trust      = true

  charm {
    name     = "traefik-k8s"
    channel  = local.channels.traefik
    revision = var.traefik.revision
    base     = var.traefik.base
  }

  constraints = var.traefik.constraints
  config = merge(
    var.external_hostname != null ? { "external_hostname" = var.external_hostname } : {},
    var.traefik.config,
  )
}

resource "juju_application" "self_signed_certificates" {
  model_uuid = local.model_uuid
  name       = var.self_signed_certificates.app_name
  units      = local.units.ssc

  charm {
    name     = "self-signed-certificates"
    channel  = local.channels.ssc
    revision = var.self_signed_certificates.revision
    base     = var.self_signed_certificates.base
  }

  constraints = var.self_signed_certificates.constraints
  config      = var.self_signed_certificates.config
}

# -------------- # Optional: credentials store -------------- #

resource "juju_application" "vault" {
  count = local.vault_enabled ? 1 : 0

  model_uuid = local.model_uuid
  name       = var.vault.app_name
  units      = local.units.vault
  trust      = true

  charm {
    name     = "vault-k8s"
    channel  = local.channels.vault
    revision = var.vault.revision
    base     = var.vault.base
  }

  constraints = var.vault.constraints
  config      = var.vault.config
}

# -------------- # Optional: metrics collection -------------- #

resource "juju_application" "opentelemetry_collector" {
  count = local.collector_enabled ? 1 : 0

  model_uuid = local.model_uuid
  name       = var.opentelemetry_collector.app_name
  units      = local.units.otelcol
  trust      = true

  charm {
    name     = "opentelemetry-collector-k8s"
    channel  = local.channels.otelcol
    revision = var.opentelemetry_collector.revision
    base     = var.opentelemetry_collector.base
  }

  constraints = var.opentelemetry_collector.constraints
  config      = var.opentelemetry_collector.config
}
