# Model management for the two models this module owns. Mirrors the existing
# module's model.tf: create internally, or look up an existing model by UUID.
# The openshell and cos-lite models are created or looked up by their own
# modules and are passed through as configured.

resource "juju_model" "iam" {
  count = var.models.iam.uuid == null ? 1 : 0

  name = var.models.iam.name

  dynamic "cloud" {
    for_each = var.models.iam.cloud != null ? [var.models.iam.cloud] : []
    content {
      name   = cloud.value.name
      region = cloud.value.region
    }
  }

  annotations       = var.models.iam.annotations
  config            = var.models.iam.config
  constraints       = var.models.iam.constraints
  credential        = var.models.iam.credential
  target_controller = var.models.iam.target_controller
}

data "juju_model" "iam" {
  count = var.models.iam.uuid == null ? 0 : 1

  uuid = var.models.iam.uuid
}

resource "juju_model" "core" {
  count = var.models.core.uuid == null ? 1 : 0

  name = var.models.core.name

  dynamic "cloud" {
    for_each = var.models.core.cloud != null ? [var.models.core.cloud] : []
    content {
      name   = cloud.value.name
      region = cloud.value.region
    }
  }

  annotations       = var.models.core.annotations
  config            = var.models.core.config
  constraints       = var.models.core.constraints
  credential        = var.models.core.credential
  target_controller = var.models.core.target_controller
}

data "juju_model" "core" {
  count = var.models.core.uuid == null ? 0 : 1

  uuid = var.models.core.uuid
}
