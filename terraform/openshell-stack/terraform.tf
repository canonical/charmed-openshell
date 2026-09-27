terraform {
  # The pinned refs of the composed modules are const variables, which have
  # to be resolvable while modules are downloaded. Support for that landed in
  # Terraform 1.15:
  # https://developer.hashicorp.com/terraform/language/modules/sources#variables-in-module-source-and-versions
  required_version = ">= 1.15"

  required_providers {
    juju = {
      source  = "juju/juju"
      version = ">= 1.0"
    }
  }
}
