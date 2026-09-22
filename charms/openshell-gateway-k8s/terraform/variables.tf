variable "model_uuid" {
  description = "UUID of the Juju model in which to deploy the gateway."
  type        = string
}

variable "app_name" {
  description = "Name of the Juju application for the gateway."
  type        = string
  default     = "openshell-gateway-k8s"
}

variable "channel" {
  description = "Charm channel from which to deploy the gateway."
  type        = string
  default     = "latest/edge"
}

variable "revision" {
  description = "Charm revision to deploy. If unset, the latest revision from the channel is used."
  type        = number
  default     = null
}

variable "base" {
  description = "Base (OS series) on which to deploy the gateway."
  type        = string
  default     = "ubuntu@24.04"
}

variable "units" {
  description = <<-EOT
    Number of gateway units to deploy. The charm coordinates restarts across
    units and shares its JWT signing key through a peer secret, so units beyond
    the first are genuine replicas rather than independent gateways.
  EOT
  type        = number
  default     = 1
}

variable "constraints" {
  description = "Juju constraints to apply to each gateway unit."
  type        = string
  # Not null: the Juju Terraform provider currently fails on an empty
  # constraints value (juju/terraform-provider-juju#344).
  default = "arch=amd64"
}

variable "config" {
  description = "Charm configuration options for the gateway."
  type        = map(string)
  default     = {}
}

variable "resources" {
  description = "Charm resources for the gateway, keyed by resource name."
  type        = map(string)
  default     = {}
}
