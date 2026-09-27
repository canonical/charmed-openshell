# The Juju Terraform provider currently fails on an empty constraints value
# (juju/terraform-provider-juju#344), so every component defaults to
# "arch=amd64" rather than to null.

# Forwarded component blocks keep this module's own defaults empty: an
# attribute left unset converts to null, and the composed module's own
# optional-attribute default applies. The pillars keep their published
# defaults; only a value set here overrides them.

variable "models" {
  description = <<-EOT
    One model per pillar: the OpenShell gateway stack, the identity platform,
    the core dependencies the identity platform consumes offers from, and the
    observability stack. Each entry follows the existing module's lookup
    convention: set `uuid` to use an existing model, or leave it to have the
    model created with the given fields.

    The `openshell` and `cos_lite` models are created or looked up by their
    own modules; the `iam` and `core` models are created or looked up by this
    module.
  EOT
  type = object({
    openshell = optional(object({
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
    }), { name = "openshell" })
    iam = optional(object({
      uuid = optional(string)
      name = optional(string, "iam")
      cloud = optional(object({
        name   = string
        region = optional(string)
      }))
      annotations       = optional(map(string))
      config            = optional(map(string))
      constraints       = optional(string)
      credential        = optional(string)
      target_controller = optional(string)
    }), { name = "iam" })
    core = optional(object({
      uuid = optional(string)
      name = optional(string, "core")
      cloud = optional(object({
        name   = string
        region = optional(string)
      }))
      annotations       = optional(map(string))
      config            = optional(map(string))
      constraints       = optional(string)
      credential        = optional(string)
      target_controller = optional(string)
    }), { name = "core" })
    cos_lite = optional(object({
      uuid = optional(string)
      name = optional(string, "cos-lite")
      cloud = optional(object({
        name   = string
        region = optional(string)
      }))
      annotations       = optional(map(string))
      config            = optional(map(string))
      constraints       = optional(string)
      credential        = optional(string)
      target_controller = optional(string)
    }), { name = "cos-lite" })
  })
  default = {}

  validation {
    condition = var.models.openshell.uuid == null || (
      var.models.openshell.annotations == null &&
      var.models.openshell.cloud == null &&
      var.models.openshell.config == null &&
      var.models.openshell.constraints == null &&
      var.models.openshell.credential == null &&
      var.models.openshell.target_controller == null
    )
    error_message = "When `models.openshell.uuid` is set the model already exists; do not also set `annotations`, `cloud`, `config`, `constraints`, `credential` or `target_controller`."
  }

  validation {
    condition     = var.models.openshell.uuid != null || (var.models.openshell.name != null && length(var.models.openshell.name) > 0)
    error_message = "`models.openshell.name` must be non-empty when creating a model (that is, when `models.openshell.uuid` is null)."
  }

  validation {
    condition = var.models.iam.uuid == null || (
      var.models.iam.annotations == null &&
      var.models.iam.cloud == null &&
      var.models.iam.config == null &&
      var.models.iam.constraints == null &&
      var.models.iam.credential == null &&
      var.models.iam.target_controller == null
    )
    error_message = "When `models.iam.uuid` is set the model already exists; do not also set `annotations`, `cloud`, `config`, `constraints`, `credential` or `target_controller`."
  }

  validation {
    condition     = var.models.iam.uuid != null || (var.models.iam.name != null && length(var.models.iam.name) > 0)
    error_message = "`models.iam.name` must be non-empty when creating a model (that is, when `models.iam.uuid` is null)."
  }

  validation {
    condition = var.models.core.uuid == null || (
      var.models.core.annotations == null &&
      var.models.core.cloud == null &&
      var.models.core.config == null &&
      var.models.core.constraints == null &&
      var.models.core.credential == null &&
      var.models.core.target_controller == null
    )
    error_message = "When `models.core.uuid` is set the model already exists; do not also set `annotations`, `cloud`, `config`, `constraints`, `credential` or `target_controller`."
  }

  validation {
    condition     = var.models.core.uuid != null || (var.models.core.name != null && length(var.models.core.name) > 0)
    error_message = "`models.core.name` must be non-empty when creating a model (that is, when `models.core.uuid` is null)."
  }

  validation {
    condition = var.models.cos_lite.uuid == null || (
      var.models.cos_lite.annotations == null &&
      var.models.cos_lite.cloud == null &&
      var.models.cos_lite.config == null &&
      var.models.cos_lite.constraints == null &&
      var.models.cos_lite.credential == null &&
      var.models.cos_lite.target_controller == null
    )
    error_message = "When `models.cos_lite.uuid` is set the model already exists; do not also set `annotations`, `cloud`, `config`, `constraints`, `credential` or `target_controller`."
  }

  validation {
    condition     = var.models.cos_lite.uuid != null || (var.models.cos_lite.name != null && length(var.models.cos_lite.name) > 0)
    error_message = "`models.cos_lite.name` must be non-empty when creating a model (that is, when `models.cos_lite.uuid` is null)."
  }
}

variable "identity_platform" {
  description = <<-EOT
    Composition of the Canonical Identity Platform, deployed by the published
    iam-bundle-integration module into the `iam` model: Hydra, Kratos and the
    login UI, consuming the `core` model's offers.

    `ref` pins the module to a revision. It names a module source, so
    Terraform has to resolve it at init time: the whole variable is const and
    must be set from static values (a variables file or a literal), and
    changing it needs a fresh `terraform init`.

    The application blocks are forwarded to the module as they are; unset
    fields keep the module's own defaults. See
    https://github.com/canonical/iam-bundle-integration
  EOT
  type = object({
    # Not v1.1.1: that release pins the juju provider to ~> 1.0.0, which
    # cannot be combined with cos-lite's >= 1.4.0 in one root module. The
    # pin was relaxed on main in 1630c7f670 ("fix: fix terraform provider
    # version mismatch"); until a release carries that, the default is the
    # commit itself. Point `ref` at the next release tag once it exists.
    ref                                   = optional(string, "1630c7f670")
    enable_kratos_external_idp_integrator = optional(bool, false)
    hydra = optional(object({
      name        = optional(string)
      units       = optional(number)
      channel     = optional(string)
      base        = optional(string)
      trust       = optional(bool)
      config      = optional(map(string), {})
      constraints = optional(string)
      revision    = optional(number)
    }), {})
    kratos = optional(object({
      name        = optional(string)
      units       = optional(number)
      channel     = optional(string)
      base        = optional(string)
      trust       = optional(bool)
      config      = optional(map(string), {})
      constraints = optional(string)
      revision    = optional(number)
    }), {})
    login_ui = optional(object({
      name        = optional(string)
      units       = optional(number)
      channel     = optional(string)
      base        = optional(string)
      trust       = optional(bool)
      config      = optional(map(string), {})
      constraints = optional(string)
      revision    = optional(number)
    }), {})
    kratos_external_idp_integrator = optional(object({
      name    = optional(string)
      units   = optional(number)
      channel = optional(string)
      base    = optional(string)
      trust   = optional(bool)
      config = optional(object({
        client_id            = string
        client_secret        = string
        issuer_url           = optional(string)
        provider             = string
        provider_id          = string
        scope                = optional(string)
        microsoft_tenant_id  = optional(string)
        apple_team_id        = optional(string)
        apple_private_key_id = optional(string)
        apple_private_key    = optional(string)
      }))
      constraints = optional(string)
      revision    = optional(number)
    }), {})
  })
  default = {}
  const   = true
}

variable "observability" {
  description = <<-EOT
    Composition of the Canonical Observability Stack's cos-lite edition,
    deployed by the published observability-stack module into the `cos_lite`
    model: Prometheus, Loki, Grafana, Alertmanager, Catalogue, Traefik and a
    CA.

    `ref` pins the module to a revision. It names a module source, so
    Terraform has to resolve it at init time: the whole variable is const and
    must be set from static values (a variables file or a literal), and
    changing it needs a fresh `terraform init`.

    The component blocks are forwarded to the module as they are; unset
    fields keep the module's own defaults. See
    https://github.com/canonical/observability-stack
  EOT
  type = object({
    ref  = optional(string, "tf-cos-lite-3.0.2")
    risk = optional(string, "stable")

    alertmanager = optional(object({
      app_name           = optional(string)
      config             = optional(map(string), {})
      constraints        = optional(string)
      resources          = optional(map(string), {})
      revision           = optional(number)
      storage_directives = optional(map(string), {})
      units              = optional(number)
    }), {})
    catalogue = optional(object({
      app_name           = optional(string)
      config             = optional(map(string), {})
      constraints        = optional(string)
      resources          = optional(map(string), {})
      revision           = optional(number)
      storage_directives = optional(map(string), {})
      units              = optional(number)
    }), {})
    grafana = optional(object({
      app_name           = optional(string)
      config             = optional(map(string), {})
      constraints        = optional(string)
      resources          = optional(map(string), {})
      revision           = optional(number)
      storage_directives = optional(map(string), {})
      units              = optional(number)
    }), {})
    loki = optional(object({
      app_name           = optional(string)
      config             = optional(map(string), {})
      constraints        = optional(string)
      resources          = optional(map(string), {})
      revision           = optional(number)
      storage_directives = optional(map(string), {})
      units              = optional(number)
    }), {})
    prometheus = optional(object({
      app_name           = optional(string)
      config             = optional(map(string), {})
      constraints        = optional(string)
      resources          = optional(map(string), {})
      revision           = optional(number)
      storage_directives = optional(map(string), {})
      units              = optional(number)
    }), {})
    ssc = optional(object({
      app_name           = optional(string)
      config             = optional(map(string), {})
      constraints        = optional(string)
      revision           = optional(number)
      storage_directives = optional(map(string), {})
      units              = optional(number)
    }), {})
    traefik = optional(object({
      app_name           = optional(string)
      config             = optional(map(string), {})
      constraints        = optional(string)
      resources          = optional(map(string), {})
      revision           = optional(number)
      storage_directives = optional(map(string), {})
      units              = optional(number)
    }), {})
  })
  default = {}
  const   = true

  validation {
    condition     = contains(["stable", "candidate", "beta", "edge"], var.observability.risk)
    error_message = "Allowed values are: stable, candidate, beta, edge."
  }
}

variable "openshell" {
  description = <<-EOT
    Everything the `terraform/openshell` module takes, except what this stack
    computes or wires itself: the model is `models.openshell`, the oauth offer
    comes from the identity platform, and the gateway's remaining cross-pillar
    integrations (the identity CA, remote-write, dashboards) are declared by
    this module, because the product module's conditional integrations cannot
    plan on offer URLs that only exist at apply time. The OpenTelemetry
    collector is enabled by default, because this stack always deploys the
    downstream it forwards to; set `opentelemetry_collector.enabled = false`
    to opt out of gateway metrics.
  EOT
  type = object({
    risk              = optional(string, "stable")
    ha                = optional(bool, false)
    external_hostname = optional(string)

    oidc = optional(object({
      admin_role  = optional(string)
      user_role   = optional(string)
      audience    = optional(string)
      roles_claim = optional(string)
    }), {})

    gateway = optional(object({
      app_name    = optional(string)
      base        = optional(string, "ubuntu@24.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
      resources   = optional(map(string), {})
    }), {})

    integrator = optional(object({
      app_name    = optional(string)
      base        = optional(string, "ubuntu@24.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
    }), {})

    postgresql = optional(object({
      gateway_app_name = optional(string)
      base             = optional(string, "ubuntu@22.04")
      channel          = optional(string)
      revision         = optional(number)
      units            = optional(number)
      constraints      = optional(string, "arch=amd64")
      config           = optional(map(string), {})
    }), {})

    traefik = optional(object({
      app_name    = optional(string)
      base        = optional(string, "ubuntu@20.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
    }), {})

    self_signed_certificates = optional(object({
      app_name    = optional(string)
      base        = optional(string, "ubuntu@24.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
    }), {})

    vault = optional(object({
      enabled     = optional(bool)
      app_name    = optional(string)
      base        = optional(string, "ubuntu@22.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
    }), {})

    opentelemetry_collector = optional(object({
      enabled     = optional(bool)
      app_name    = optional(string)
      base        = optional(string, "ubuntu@24.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
    }), {})
  })
  default = {}
}

variable "core" {
  description = <<-EOT
    Applications of the `core` model: the PostgreSQL, Traefik and certificate
    authority the identity platform consumes offers from. This model is
    dependency infrastructure rather than a product, so it is declared here
    instead of coming from a published module.

    The Traefik publishes the identity platform's issuer on
    `identity_hostname`; do not point it at the gateway's ingress.
  EOT
  type = object({
    risk = optional(string, "stable")

    postgresql = optional(object({
      app_name    = optional(string, "postgresql")
      base        = optional(string, "ubuntu@22.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number, 1)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
    }), {})

    traefik = optional(object({
      app_name    = optional(string, "traefik")
      base        = optional(string, "ubuntu@20.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number, 1)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
    }), {})

    self_signed_certificates = optional(object({
      app_name    = optional(string, "self-signed-certificates")
      base        = optional(string, "ubuntu@24.04")
      channel     = optional(string)
      revision    = optional(number)
      units       = optional(number, 1)
      constraints = optional(string, "arch=amd64")
      config      = optional(map(string), {})
    }), {})
  })
  default = {}

  validation {
    condition     = contains(["stable", "candidate", "beta", "edge"], var.core.risk)
    error_message = "Allowed values are: stable, candidate, beta, edge."
  }
}

variable "identity_hostname" {
  description = <<-EOT
    Hostname or address the identity platform's issuer is published on, as
    the core model's Traefik `external_hostname`. The gateway's OIDC
    discovery has to reach it, and so do the browsers driving the login flow;
    sandboxes have no business with it. That is why it is separate from the
    forwarded `openshell.external_hostname`: the two are different ingress
    points with different addresses.
  EOT
  type        = string
}
