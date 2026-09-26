# -------------- # Core model -------------- #

# The dependencies the identity platform consumes offers from: PostgreSQL for
# its databases, Traefik for the issuer's public routes, and a certificate
# authority for the issuer's TLS. This is dependency infrastructure rather
# than a product topology, so it is declared here directly, in the shape the
# upstream iam-bundle-integration examples prescribe for a core model.

# Declared directly rather than through the charms' own Terraform modules: a
# module `source` must be a literal, so pointing it at a pinned ref per charm
# would add three more sources that cannot follow the pillar refs, and the
# charm interfaces here are the plain ones the offers expose.

resource "juju_application" "postgresql" {
  model_uuid = local.models.core.model_uuid
  name       = var.core.postgresql.app_name
  units      = var.core.postgresql.units
  trust      = true

  charm {
    name     = "postgresql-k8s"
    channel  = local.core_channels.postgresql
    revision = var.core.postgresql.revision
    base     = var.core.postgresql.base
  }

  constraints = var.core.postgresql.constraints
  config      = var.core.postgresql.config

  storage_directives = {
    pgdata = "10G"
  }
}

resource "juju_application" "traefik" {
  model_uuid = local.models.core.model_uuid
  name       = var.core.traefik.app_name
  units      = var.core.traefik.units
  trust      = true

  charm {
    name     = "traefik-k8s"
    channel  = local.core_channels.traefik
    revision = var.core.traefik.revision
    base     = var.core.traefik.base
  }

  constraints = var.core.traefik.constraints
  config = merge(
    { "external_hostname" = var.identity_hostname },
    var.core.traefik.config,
  )
}

resource "juju_application" "self_signed_certificates" {
  model_uuid = local.models.core.model_uuid
  name       = var.core.self_signed_certificates.app_name
  units      = var.core.self_signed_certificates.units

  charm {
    name     = "self-signed-certificates"
    channel  = local.core_channels.ssc
    revision = var.core.self_signed_certificates.revision
    base     = var.core.self_signed_certificates.base
  }

  constraints = var.core.self_signed_certificates.constraints
  config      = var.core.self_signed_certificates.config
}

# Traefik gets its issuer certificate from the core CA, so what it serves on
# identity_hostname is signed by the same CA the gateway is handed below.

resource "juju_integration" "traefik_certificates" {
  model_uuid = local.models.core.model_uuid

  application {
    name     = juju_application.traefik.name
    endpoint = "certificates"
  }

  application {
    name     = juju_application.self_signed_certificates.name
    endpoint = "certificates"
  }
}

# -------------- # Core offers -------------- #

# The three offers the identity platform and the gateway consume. Their names
# match the iam module's defaults (`admin/core.postgresql`,
# `admin/core.traefik-route`), so the composed URLs need no override there.

resource "juju_offer" "core_postgresql" {
  name             = "postgresql"
  application_name = juju_application.postgresql.name
  endpoints        = ["database"]
  model_uuid       = local.models.core.model_uuid
}

resource "juju_offer" "core_traefik_route" {
  name             = "traefik-route"
  application_name = juju_application.traefik.name
  endpoints        = ["traefik-route"]
  model_uuid       = local.models.core.model_uuid
}

resource "juju_offer" "core_send_ca_cert" {
  name             = "send-ca-cert"
  application_name = juju_application.self_signed_certificates.name
  endpoints        = ["send-ca-cert"]
  model_uuid       = local.models.core.model_uuid
}
