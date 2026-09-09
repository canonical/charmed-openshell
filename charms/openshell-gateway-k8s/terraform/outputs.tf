output "app_name" {
  description = "Name of the deployed gateway Juju application."
  value       = juju_application.openshell_gateway_k8s.name
}

output "provides" {
  description = "Map of relation names provided by the gateway."
  value = {
    send_ca_cert = "send-ca-cert"
  }
}

output "requires" {
  description = "Map of relation names required by the gateway."
  value = {
    database     = "database"
    certificates = "certificates"
    oauth        = "oauth"
    ingress      = "ingress"
    lxd          = "lxd"
  }
}
