# Charmed OpenShell

> [!WARNING]
> Charmed OpenShell is alpha software. Its implementation details are subject to
> change.

Charmed OpenShell runs the [NVIDIA OpenShell](https://docs.nvidia.com/openshell/)
gateway on Canonical Kubernetes with Juju, and creates its sandboxes as LXD
instances on a [MicroCloud](https://canonical.com/microcloud).

## Get started

- [Deploy Charmed OpenShell](https://ubuntu.com/docs/charmed-openshell/how-to/deploy/)
- [Connect the `openshell` CLI](https://ubuntu.com/docs/charmed-openshell/how-to/connect/)

The [documentation](https://ubuntu.com/docs/charmed-openshell/) covers the rest of
operating the gateway. For OpenShell itself, see the
[OpenShell documentation](https://docs.nvidia.com/openshell/).

## In this repository

- [`charms/openshell-gateway-k8s/`](charms/openshell-gateway-k8s/): the gateway charm
- [`terraform/`](terraform/): Terraform modules that deploy it
- [`docs/`](docs/): the documentation

## Build and test

```bash
just build-charm
just test-charm
```

Integration tests need a Juju controller on Kubernetes; `concierge.yaml` prepares
one with [Concierge](https://github.com/canonical/concierge).

## Contributing

See [Contribute](https://ubuntu.com/docs/charmed-openshell/contribute/). Report
security issues privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
