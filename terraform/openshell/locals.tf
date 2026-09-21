locals {
  create_model = var.model.uuid == null
  model_uuid   = local.create_model ? juju_model.openshell[0].uuid : data.juju_model.openshell[0].uuid

  # Optional components. Each is off unless asked for, so the default stack is
  # the smallest thing that actually serves sandboxes.
  vault_enabled     = var.vault.enabled
  collector_enabled = var.opentelemetry_collector.enabled

  # Cross-model integration with COS. Set the offer URLs to wire the stack into
  # an existing COS deployment; leave them null and the stack stands alone.
  cos_metrics_enabled    = var.cos.remote_write_offer_url != null
  cos_dashboards_enabled = var.cos.grafana_dashboards_offer_url != null

  tracks = {
    gateway    = "latest"
    integrator = "latest"
    postgresql = "14"
    traefik    = "latest"
    ssc        = "1"
    vault      = "1.16"
    otelcol    = "2"
  }

  channels = {
    gateway    = var.gateway.channel != null ? var.gateway.channel : "${local.tracks.gateway}/${var.risk}"
    integrator = var.integrator.channel != null ? var.integrator.channel : "${local.tracks.integrator}/${var.risk}"
    postgresql = var.postgresql.channel != null ? var.postgresql.channel : "${local.tracks.postgresql}/${var.risk}"
    traefik    = var.traefik.channel != null ? var.traefik.channel : "${local.tracks.traefik}/${var.risk}"
    ssc        = var.self_signed_certificates.channel != null ? var.self_signed_certificates.channel : "${local.tracks.ssc}/${var.risk}"
    vault      = var.vault.channel != null ? var.vault.channel : "${local.tracks.vault}/${var.risk}"
    otelcol    = var.opentelemetry_collector.channel != null ? var.opentelemetry_collector.channel : "${local.tracks.otelcol}/${var.risk}"
  }

  # Unit counts. `ha` raises the floor for every component that can genuinely
  # run more than one unit; a per-component `units` still wins over it, so the
  # switch is a default rather than a constraint.
  ha_units = {
    gateway    = 3
    integrator = 2
    postgresql = 3
    traefik    = 2
    ssc        = 1
    vault      = 3
    otelcol    = 2
  }

  units = {
    gateway    = coalesce(var.gateway.units, var.ha ? local.ha_units.gateway : 1)
    integrator = coalesce(var.integrator.units, var.ha ? local.ha_units.integrator : 1)
    postgresql = coalesce(var.postgresql.units, var.ha ? local.ha_units.postgresql : 1)
    traefik    = coalesce(var.traefik.units, var.ha ? local.ha_units.traefik : 1)
    ssc        = coalesce(var.self_signed_certificates.units, var.ha ? local.ha_units.ssc : 1)
    vault      = coalesce(var.vault.units, var.ha ? local.ha_units.vault : 1)
    otelcol    = coalesce(var.opentelemetry_collector.units, var.ha ? local.ha_units.otelcol : 1)
  }

  # RBAC is required by default in the gateway charm: it stays blocked until
  # both role options are set, so they are merged in rather than left to the
  # caller's config map to remember.
  gateway_config = merge(
    {
      "oidc-admin-role"  = var.oidc.admin_role
      "oidc-user-role"   = var.oidc.user_role
      "oidc-audience"    = var.oidc.audience
      "oidc-roles-claim" = var.oidc.roles_claim
    },
    var.external_hostname != null ? { "external-hostname" = var.external_hostname } : {},
    var.gateway.config,
  )
}
