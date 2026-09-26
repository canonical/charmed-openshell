# Charmed OpenShell stack Terraform module

Deploys Charmed OpenShell together with the Canonical Identity Platform and
the Canonical Observability Stack in one `terraform apply`. The gateway,
its SSO and its telemetry come up wired to each other, each pillar behind
its published module and in its own model:

| Model | What it runs | Where it comes from |
|---|---|---|
| `openshell` | the gateway, its integrator, PostgreSQL, Traefik and CA, optionally Vault and the collector | the in-repo [`terraform/openshell`](../openshell) module, unchanged |
| `iam` | Hydra, Kratos and the login UI | [canonical/iam-bundle-integration](https://github.com/canonical/iam-bundle-integration), pinned and overridable |
| `core` | PostgreSQL, Traefik and a CA the identity platform consumes offers from | declared by this module |
| `cos-lite` | Prometheus, Loki, Grafana and friends | [canonical/observability-stack](https://github.com/canonical/observability-stack) `cos-lite`, pinned and overridable |

The module owns the glue: the four models, the core model's applications and
offers, and the cross-pillar integrations. Hydra's `oauth` offer and the core
CA's `send-ca-cert` offer feed the gateway; cos-lite's remote-write and
dashboard offers feed the gateway's collector and dashboard; cos-lite's
metrics, logging and dashboard offers feed the identity platform.

The composed pillars would wire those offers from their own variables, but
they decide per URL with `count`, which Terraform has to know at plan, while
an offer this stack creates only exists at apply. So the integrations over
composed offers are declared by this module, unconditionally; only the oauth
offer flows through the product module, whose integration is unconditional.
The issuer itself is published by the iam module on the core Traefik, at
`identity_hostname`.

## Usage

```hcl
module "openshell-stack" {
  source = "git::https://github.com/canonical/charmed-openshell//terraform/openshell-stack"

  models = {
    # Created beforehand, so the LXD credentials secret can live in it.
    openshell = { uuid = "744c5ae5-0183-4375-8b0f-aea59268f8f3" }
  }

  identity_hostname = "10.20.202.201"

  openshell = {
    external_hostname = "192.168.1.233"

    # Both OpenShell charms publish to latest/edge only.
    gateway = { channel = "latest/edge" }

    integrator = {
      channel = "latest/edge"
      config = {
        "lxd-endpoints"   = "192.168.1.166:8443"
        "lxd-credentials" = "secret:d6mlp2o0p26r50dt2sd0"
        "project"         = "openshell"
      }
    }
  }
}
```

```console
terraform init
terraform apply
```

## Pinned module revisions

`identity_platform.ref` and `observability.ref` name the module sources, so
Terraform resolves them at init time. Both variables are const: set them from
static values only (a variables file or a literal), and re-run
`terraform init` after changing them.

The identity platform defaults to the commit that relaxed its juju provider
pin (`1630c7f670`): the latest release at the time of writing, `v1.1.1`, pins
the provider to `~> 1.0.0`, which cos-lite's `>= 1.4.0` rules out. Point
`identity_platform.ref` at the next release tag once it carries that change.

Per-component configuration forwards to each pillar as it is; unset fields
keep the published module's own defaults.

## OIDC roles and claims

The gateway publishes its `oidc-audience` (default `openshell-cli`) over the
`oauth` relation, and Hydra registers the CLI client with that audience. No
identity-side configuration is needed for it.

The gateway's `oidc-roles-claim` (default `groups`) names the token claim the
gateway maps to its RBAC roles. The identity platform issues no `groups`
claim by default, so either configure the identity side to issue one — the
[custom claims
example](https://github.com/canonical/iam-bundle-integration/tree/main/examples/custom-claims)
shows the pattern — or override `openshell.oidc.roles_claim` to name a claim
the identity side actually issues. Until the two sides agree on a claim,
logins fail at authorization.

## What you have to do yourself

- **Create the `openshell` model and the LXD credentials secret.**
  `openshell.integrator.config.lxd-credentials` names a Juju secret holding
  `client-cert`, `client-key` and `server-cert`. Terraform does not create it:
  the secret carries an administrative LXD client key, which should not pass
  through Terraform state. A secret lives in a model and its URI has to be in
  the configuration before the apply, so create the model first and hand it to
  the stack as `models.openshell.uuid`:

  ```console
  juju add-model openshell
  juju add-secret lxd-credentials -m openshell \
      client-cert#file=client.crt client-key#file=client.key server-cert#file=server.crt
  ```

  Grant it after the apply, once the integrator exists. The grant fires no
  hook; the integrator reads the secret at a later `update-status` (every
  five minutes by default, though close to 13 minutes passed in testing) and
  stays blocked until then.

  ```console
  juju grant-secret lxd-credentials lxd-integrator-k8s -m openshell
  ```

- **Create the LXD project** named in `openshell.integrator.config.project`,
  with a `default` profile that names an OVN network and a storage pool. The
  driver reads sandbox placement from that profile and never creates the
  project itself. Create the project with `features.networks=true` when the
  network is to live inside it; otherwise `lxc network create --project`
  silently creates the network in the `default` project. Sandbox images are
  OCI references the driver pulls itself, so the project needs no image
  alias.

- **Make both hostnames routable.** `openshell.external_hostname` has to be
  routable from the sandbox network, as the existing module documents.
  `identity_hostname` has two audiences of its own: the gateway's pods, for
  OIDC discovery, and the machines of the users who log in, for the login
  flow. Sandboxes never talk to it. On MicroCloud, an LXD network forward on
  the Kubernetes nodes' own OVN network does not hairpin back to them, so
  `identity_hostname` has to be the core Traefik's load-balancer address
  itself. Pin each Traefik's load-balancer address with its
  `loadbalancer_annotations` option (`core.traefik.config`,
  `openshell.traefik.config`), because the load balancer otherwise assigns
  addresses in service-creation order. The
  [deploy how-to](../../docs/how-to/deploy.rst) walks through a MicroCloud
  layout.

- **Initialise, unseal and authorise Vault** when
  `openshell.vault.enabled` is true. Vault serves nothing until then, and the
  gateway waits rather than falling back to its Juju secret.

- **Create a Kratos admin account** for identity administration:

  ```console
  juju run -m iam kratos/0 create-admin-account email=admin@example.com password=...
  ```

- **Configure external identity providers** (GitHub, Microsoft Entra ID, and
  similar) when you want them: set
  `identity_platform.enable_kratos_external_idp_integrator = true` and fill
  its config. The platform ships its local IdP; this module does not wire
  upstream ones.

Grafana keeps its own authentication; routing it through the identity
platform is out of scope for this module.

## Integrating further applications

`offers` carries every offer URL the composed stack exposes — Hydra's
`oauth`, the core model's `send-ca-cert`, `postgresql` and `traefik-route`,
and cos-lite's four telemetry offers — for wiring additional applications
without another deployment of a pillar:

```console
terraform output -json offers
```

## High availability

`openshell.ha` raises the gateway stack's unit counts exactly as the existing
module describes. The identity and observability pillars scale through their
own forwarded blocks (`identity_platform.hydra.units`,
`observability.prometheus.units`, and so on); the core model's units are set
on `core.*.units`.
