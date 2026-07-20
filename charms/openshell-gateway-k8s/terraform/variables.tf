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
  description = "Number of gateway units to deploy."
  type        = number
  default     = 1
}

variable "constraints" {
  description = "Juju constraints to apply to each gateway unit."
  type        = string
  default     = null
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
