# The Juju Terraform provider currently fails on an empty constraints value
# (juju/terraform-provider-juju#344), so every component defaults to
# "arch=amd64" rather than to null.

variable "model" {
  description = "Model configuration. When `uuid` is set an existing model is looked up; otherwise a new model is created with the given fields."
  type = object({
    uuid = optional(string)
    name = optional(string, "openshell")
    cloud = optional(object({
      name   = string
      region = optional(string)
    }))
    annotations       = optional(map(string))
    config            = optional(map(string))
    constraints       = optional(string)
    credential        = optional(string)
    target_controller = optional(string)
  })
  default = {}

  validation {
    condition = var.model.uuid == null || (
      var.model.annotations == null &&
      var.model.cloud == null &&
      var.model.config == null &&
      var.model.constraints == null &&
      var.model.credential == null &&
      var.model.target_controller == null
    )
    error_message = "When `model.uuid` is set the model already exists; do not also set `annotations`, `cloud`, `config`, `constraints`, `credential` or `target_controller`."
  }

  validation {
    condition     = var.model.uuid != null || (var.model.name != null && length(var.model.name) > 0)
    error_message = "`model.name` must be non-empty when creating a model (that is, when `model.uuid` is null)."
  }
}

variable "risk" {
  description = "Risk level the applications are deployed from, unless a component sets its own channel."
  type        = string
  default     = "stable"

  validation {
    condition     = contains(["stable", "candidate", "beta", "edge"], var.risk)
    error_message = "Allowed values are: stable, candidate, beta, edge."
  }
}

variable "ha" {
  description = <<-EOT
    Raise the default unit count for every component that can genuinely run
    more than one unit: the gateway, the integrator, PostgreSQL, Traefik, the
    certificate provider, Vault and the collector. Identity is not deployed by
    this stack and has its own. A component's own `units` still wins, so this
    is a floor rather than a constraint.

    It does not make a single-node Kubernetes highly available. On one node the
    extra units land on the same machine and buy process-level redundancy only.
  EOT
  type        = bool
  default     = false
}

variable "external_hostname" {
  description = <<-EOT
    Hostname or address clients and sandboxes reach the deployment on. Applied
    to both Traefik and the gateway, because the gateway's TLS SAN, its OIDC
    redirect and the dial-back address it hands to sandboxes all have to agree
    with what Traefik serves.

    It has to be routable from the sandbox network, which is not the same
    network as the Kubernetes cluster: an in-cluster address will not do.
  EOT
  type        = string
  default     = null
}

variable "oidc" {
  description = <<-EOT
    OIDC roles and audience for the gateway. Both roles are required: the charm
    stays blocked until each is set, which is deliberate — RBAC is not optional.
  EOT
  type = object({
    admin_role  = optional(string, "openshell-admin")
    user_role   = optional(string, "openshell-user")
    audience    = optional(string, "openshell-cli")
    roles_claim = optional(string, "groups")
  })
  default = {}
}

variable "identity" {
  description = <<-EOT
    Offer URLs of a Canonical Identity Platform deployment, in the form
    `<controller>:<user>/<model>.<offer>`. This stack does not deploy Hydra: the
    identity platform is its own product, with its own models, database and
    login UI.

    See https://canonical-identity.readthedocs-hosted.com/identity-platform/

    `oauth_offer_url` is required — the gateway stays blocked without an OIDC
    provider. `send_ca_cert_offer_url` lets the gateway trust the CA the
    platform signs its issuer certificate with, which OIDC discovery needs when
    that CA is not a public one.
  EOT
  type = object({
    oauth_offer_url        = string
    send_ca_cert_offer_url = optional(string)
  })
}

variable "cos" {
  description = <<-EOT
    Offer URLs of an existing COS deployment to integrate with, in the form
    `<controller>:<user>/<model>.<offer>`. Leave them null and the stack stands
    alone.

    `remote_write_offer_url` gives the collector somewhere to forward to;
    without it, or another downstream, the collector stays blocked and never
    scrapes. It is the metrics backend's remote-write offer, whichever backend
    the COS deployment uses — `prometheus-receive-remote-write` on COS Lite,
    `mimir-receive-remote-write` on COS 3.0.

    `grafana_dashboards_offer_url` sends the gateway's dashboard to Grafana.
  EOT
  type = object({
    remote_write_offer_url       = optional(string)
    grafana_dashboards_offer_url = optional(string)
  })
  default = {}
}

variable "gateway" {
  description = "OpenShell gateway application configuration."
  type = object({
    app_name    = optional(string, "openshell-gateway-k8s")
    base        = optional(string, "ubuntu@24.04")
    channel     = optional(string)
    revision    = optional(number)
    units       = optional(number)
    constraints = optional(string, "arch=amd64")
    config      = optional(map(string), {})
    resources   = optional(map(string), {})
  })
  default = {}
}

variable "integrator" {
  description = <<-EOT
    LXD integrator application configuration. `config.lxd-credentials` must name
    a Juju secret granted to the application; Terraform does not create it,
    because the secret carries an administrative LXD client key that should not
    pass through Terraform state.

    `config.project` names the LXD project the gateway's sandboxes are created
    in, and restricts the gateway's LXD trust entry to it. It belongs here
    rather than on the gateway: which project a requirer may use is the LXD
    administrator's decision.
  EOT
  type = object({
    app_name    = optional(string, "lxd-integrator-k8s")
    base        = optional(string, "ubuntu@24.04")
    channel     = optional(string)
    revision    = optional(number)
    units       = optional(number)
    constraints = optional(string, "arch=amd64")
    config      = optional(map(string), {})
  })
  default = {}
}

variable "postgresql" {
  description = "PostgreSQL configuration for the gateway's own database. Identity brings its own."
  type = object({
    gateway_app_name = optional(string, "postgresql-gateway")
    base             = optional(string, "ubuntu@22.04")
    channel          = optional(string)
    revision         = optional(number)
    units            = optional(number)
    constraints      = optional(string, "arch=amd64")
    config           = optional(map(string), {})
  })
  default = {}
}

variable "traefik" {
  description = "Traefik ingress application configuration."
  type = object({
    app_name    = optional(string, "traefik-k8s")
    base        = optional(string, "ubuntu@20.04")
    channel     = optional(string)
    revision    = optional(number)
    units       = optional(number)
    constraints = optional(string, "arch=amd64")
    config      = optional(map(string), {})
  })
  default = {}
}

variable "self_signed_certificates" {
  description = <<-EOT
    Self-signed certificate authority application configuration. Suitable for a
    test drive; swap it for a real CA before anyone depends on the deployment.
  EOT
  type = object({
    app_name    = optional(string, "self-signed-certificates")
    base        = optional(string, "ubuntu@24.04")
    channel     = optional(string)
    revision    = optional(number)
    units       = optional(number)
    constraints = optional(string, "arch=amd64")
    config      = optional(map(string), {})
  })
  default = {}
}

variable "vault" {
  description = <<-EOT
    Vault application configuration. When enabled the gateway keeps its JWT
    signing key in Vault instead of a Juju secret, migrating the existing key
    on the first ready event so live sandbox tokens keep verifying.

    Vault needs initialising, unsealing and authorising before it serves
    anything; Terraform deploys it but does not do that for you.
  EOT
  type = object({
    enabled     = optional(bool, false)
    app_name    = optional(string, "vault-k8s")
    base        = optional(string, "ubuntu@22.04")
    channel     = optional(string)
    revision    = optional(number)
    units       = optional(number)
    constraints = optional(string, "arch=amd64")
    config      = optional(map(string), {})
  })
  default = {}
}

variable "opentelemetry_collector" {
  description = <<-EOT
    OpenTelemetry collector configuration. When enabled it scrapes the
    gateway's metrics endpoint. It needs a downstream to forward to — see
    `cos.remote_write_offer_url` — or it stays blocked.
  EOT
  type = object({
    enabled     = optional(bool, false)
    app_name    = optional(string, "opentelemetry-collector-k8s")
    base        = optional(string, "ubuntu@24.04")
    channel     = optional(string)
    revision    = optional(number)
    units       = optional(number)
    constraints = optional(string, "arch=amd64")
    config      = optional(map(string), {})
  })
  default = {}
}
