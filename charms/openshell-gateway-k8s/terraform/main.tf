resource "juju_application" "openshell_gateway_k8s" {
  model_uuid = var.model_uuid
  name       = var.app_name
  units      = var.units

  charm {
    name     = "openshell-gateway-k8s"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  constraints = var.constraints
  config      = var.config
  resources   = var.resources
}
