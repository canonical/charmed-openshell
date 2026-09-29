output "model_uuid" {
  description = "UUID of the model the stack is deployed into."
  value       = local.model_uuid
}

output "model_name" {
  description = "Name of the model the stack is deployed into."
  value       = local.create_model ? juju_model.openshell[0].name : data.juju_model.openshell[0].name
}

output "app_names" {
  description = "Names of every application deployed by this stack. Optional components are null when disabled."
  value = {
    gateway                  = module.gateway.app_name
    postgresql_gateway       = juju_application.postgresql_gateway.name
    traefik                  = juju_application.traefik.name
    self_signed_certificates = juju_application.self_signed_certificates.name
    vault                    = local.vault_enabled ? juju_application.vault[0].name : null
    opentelemetry_collector  = local.collector_enabled ? juju_application.opentelemetry_collector[0].name : null
  }
}

output "provides" {
  description = "Relation endpoints this stack exposes for further integration."
  value = {
    metrics_endpoint  = module.gateway.provides.metrics_endpoint
    grafana_dashboard = module.gateway.provides.grafana_dashboard
    send_ca_cert      = module.gateway.provides.send_ca_cert
  }
}
