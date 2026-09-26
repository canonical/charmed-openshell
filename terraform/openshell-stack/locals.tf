locals {
  # The iam and core models are the two this module creates or looks up; the
  # openshell and cos-lite models are managed by their own modules.
  models = {
    iam = {
      create_model = var.models.iam.uuid == null
      model_uuid   = var.models.iam.uuid == null ? juju_model.iam[0].uuid : data.juju_model.iam[0].uuid
      model_name   = var.models.iam.uuid == null ? juju_model.iam[0].name : data.juju_model.iam[0].name
    }
    core = {
      create_model = var.models.core.uuid == null
      model_uuid   = var.models.core.uuid == null ? juju_model.core[0].uuid : data.juju_model.core[0].uuid
      model_name   = var.models.core.uuid == null ? juju_model.core[0].name : data.juju_model.core[0].name
    }
  }

  # The core model's applications, mirroring the existing module's track and
  # channel tables. A component's own `channel` wins over `core.risk`.
  core_tracks = {
    postgresql = "14"
    traefik    = "latest"
    ssc        = "1"
  }

  core_channels = {
    postgresql = var.core.postgresql.channel != null ? var.core.postgresql.channel : "${local.core_tracks.postgresql}/${var.core.risk}"
    traefik    = var.core.traefik.channel != null ? var.core.traefik.channel : "${local.core_tracks.traefik}/${var.core.risk}"
    ssc        = var.core.self_signed_certificates.channel != null ? var.core.self_signed_certificates.channel : "${local.core_tracks.ssc}/${var.core.risk}"
  }

  # The stack always deploys cos-lite, so the collector has the downstream it
  # refuses to scrape without. It stays opt-out for operators who bring their
  # own telemetry path: an unset `enabled` means on here, where the existing
  # module treats it as off.
  openshell_opentelemetry_collector = merge(
    var.openshell.opentelemetry_collector,
    { enabled = coalesce(var.openshell.opentelemetry_collector.enabled, true) },
  )

  # The glue's remote-write integration only exists when the collector the
  # product module deploys does.
  openshell_collector_enabled = local.openshell_opentelemetry_collector.enabled

  # The iam module has no app-name output, so the names its applications get
  # come from the forwarded blocks and the module's own defaults. The
  # telemetry integrations and the app_names output share them.
  iam_app_names = {
    hydra    = coalesce(var.identity_platform.hydra.name, "hydra")
    kratos   = coalesce(var.identity_platform.kratos.name, "kratos")
    login_ui = coalesce(var.identity_platform.login_ui.name, "login-ui")
  }
}
