# Terraform module for OpenShell Gateway K8s

This module deploys the `openshell-gateway-k8s` Juju charm as a single
`juju_application`. It wraps only the gateway charm; callers are responsible for
wiring the required integrations through the exposed endpoint outputs:

- `requires`: `database`, `certificates`, `oauth`, `ingress`, `lxd`
- `provides`: `send-ca-cert`

The `lxd` endpoint is mandatory: the gateway remains blocked until it is wired
 to an `lxd-https` provider such as `lxd-integrator-k8s`.

## Inputs

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `model_uuid` | `string` | | UUID of the Juju model in which to deploy the gateway. |
| `app_name` | `string` | `openshell-gateway-k8s` | Name of the Juju application for the gateway. |
| `channel` | `string` | `latest/edge` | Charm channel from which to deploy the gateway. |
| `revision` | `number` | `null` | Charm revision to deploy. If unset, the latest revision from the channel is used. |
| `base` | `string` | `ubuntu@24.04` | Base (OS series) on which to deploy the gateway. |
| `units` | `number` | `1` | Number of gateway units to deploy. |
| `constraints` | `string` | `null` | Juju constraints to apply to each gateway unit. |
| `config` | `map(string)` | `{}` | Charm configuration options for the gateway. |
| `resources` | `map(string)` | `{}` | Charm resources for the gateway, keyed by resource name. |

## Outputs

| Name | Type | Description |
|------|------|-------------|
| `app_name` | `string` | Name of the deployed gateway Juju application. |
| `provides` | `map(string)` | Map of relation names provided by the gateway. |
| `requires` | `map(string)` | Map of relation names required by the gateway. |

## Usage

```hcl
module "openshell_gateway" {
  source     = "./charms/openshell-gateway-k8s/terraform"
  model_uuid = var.model_uuid
  channel    = var.channel

  config = {
    oidc-admin-role = var.oidc_admin_role
    oidc-user-role  = var.oidc_user_role
  }
}

resource "juju_integration" "database" {
  model = var.model_name

  application {
    name     = module.openshell_gateway.app_name
    endpoint = module.openshell_gateway.requires.database
  }

  application {
    name     = module.postgresql.app_name
    endpoint = module.postgresql.provides.database
  }
}
```
