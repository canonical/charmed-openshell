# Model management: create internally, or look up an existing model by UUID.
# Mirrors the COS product module so the two can be driven the same way.

resource "juju_model" "openshell" {
  count = local.create_model ? 1 : 0

  name = var.model.name

  dynamic "cloud" {
    for_each = var.model.cloud != null ? [var.model.cloud] : []
    content {
      name   = cloud.value.name
      region = cloud.value.region
    }
  }

  annotations       = var.model.annotations
  config            = var.model.config
  constraints       = var.model.constraints
  credential        = var.model.credential
  target_controller = var.model.target_controller
}

data "juju_model" "openshell" {
  count = local.create_model ? 0 : 1

  uuid = var.model.uuid
}
