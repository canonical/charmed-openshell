# Charmed OpenShell Terraform stack

Deploys the whole of Charmed OpenShell into one Juju model: the gateway, the
LXD integrator, PostgreSQL, Hydra and the login UI, Traefik and a certificate
authority, and optionally Vault and an OpenTelemetry collector.

The layout follows the [COS product
module](https://github.com/canonical/observability-stack/tree/track/3.0/terraform/cos),
so the two can be driven the same way and integrated across models.

## Usage

```hcl
module "openshell" {
  source = "git::https://github.com/canonical/charmed-openshell//terraform/openshell"

  model = { name = "openshell" }
  risk  = "edge"

  external_hostname = "10.221.97.2"

  integrator = {
    config = {
      "lxd-endpoints"   = "192.168.1.166:8443"
      "lxd-credentials" = "secret:d6mlp2o0p26r50dt2sd0"
      "project"         = "openshell"
    }
  }
}
```

```console
terraform init
terraform apply -var='model={name="openshell"}'
```

## What you have to do yourself

- **Create the LXD credentials secret.** `integrator.config.lxd-credentials`
  names a Juju secret holding `client-cert`, `client-key` and `server-cert`.
  Terraform does not create it: the secret carries an administrative LXD client
  key, which should not pass through Terraform state.

  ```console
  juju add-secret lxd-credentials \
      client-cert#file=client.crt client-key#file=client.key server-cert#file=server.crt
  juju grant-secret lxd-credentials lxd-integrator-k8s
  ```

- **Create the LXD project** named in `integrator.config.project`, with a
  `default` profile that names a network and a storage pool. The driver reads
  sandbox placement from that profile and never creates the project itself.

- **Initialise, unseal and authorise Vault** when `vault.enabled` is true.
  Vault serves nothing until then, and the gateway waits rather than falling
  back to its Juju secret.

## High availability

`ha = true` raises the default unit count for every component that can
genuinely run more than one unit — gateway 3, PostgreSQL 3, Vault 3, Hydra 2,
Traefik 2, integrator 2, collector 2. A component's own `units` still wins, so
the switch is a floor rather than a constraint:

```hcl
module "openshell" {
  # ...
  ha         = true
  postgresql = { units = 5 }
}
```

It does not make a single-node Kubernetes highly available. On one node the
extra units land on the same machine and buy process-level redundancy only.

## Integrating with COS

Deploy COS in its own model, then pass its offer URLs:

```hcl
module "openshell" {
  # ...
  opentelemetry_collector = { enabled = true }

  cos = {
    # prometheus-receive-remote-write on COS Lite; mimir-… on COS 3.0.
    remote_write_offer_url       = "rhea-k8s-controller:admin/cos.prometheus-receive-remote-write"
    grafana_dashboards_offer_url = "rhea-k8s-controller:admin/cos.grafana-dashboards"
  }
}
```

The collector refuses to scrape until it has somewhere to forward to, so
enabling it without a downstream leaves it blocked and no metrics flow.

## A note on `external_hostname`

It is applied to both Traefik and the gateway, because the gateway's TLS SAN,
its OIDC redirect URI and the dial-back address handed to sandboxes all have to
agree with what Traefik serves. It must be routable **from the sandbox
network**, which is not the Kubernetes cluster network — sandboxes run on LXD,
so an in-cluster address will not reach them.
