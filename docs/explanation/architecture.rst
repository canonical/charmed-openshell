.. meta::
   :description: How Charmed OpenShell runs the OpenShell gateway on Kubernetes, where sandboxes run, and how the addresses it publishes fit together.

.. _explanation-architecture:

Architecture
============

Charmed OpenShell runs the `OpenShell
<https://docs.nvidia.com/openshell/v0.0.116/about/how-it-works>`_ gateway on
Canonical Kubernetes, operated by Juju, and runs the sandboxes it creates as
LXD instances on a MicroCloud. This page covers that arrangement. For what a
gateway, a sandbox or a policy is, see the OpenShell documentation.

The gateway pod
---------------

The ``openshell-gateway-k8s`` charm runs one workload container with two
services in it:

``gateway``
    The OpenShell gateway: the API the ``openshell`` CLI talks to, on port
    8443.

``driver-lxd``
    The ``openshell-driver-lxd`` compute driver. The gateway hands it every
    sandbox operation over a Unix socket inside the container, and the driver
    carries them out against the LXD API.

The charm writes both services' configuration, TLS material and keys into
the container, and restarts the workload when any of them change. With more
than one unit, it restarts them one at a time.

What the gateway is related to
------------------------------

.. list-table::
    :header-rows: 1

    * - Relation
      - Provided by
      - What it gives the gateway
    * - ``database``
      - PostgreSQL
      - Persistence for sandboxes, policies and providers
    * - ``certificates``
      - A TLS certificates provider
      - The gateway's server certificate
    * - ``oauth``
      - Hydra, from the Canonical Identity Platform
      - The OIDC issuer that authenticates users
    * - ``ingress``
      - Traefik
      - A route to port 8443 in TLS passthrough, so the gateway terminates
        TLS itself

The charm stays blocked until all four exist and it has joined LXD, as
described below. The remaining relations are
optional: ``receive-ca-cert`` for issuers the workload has to trust,
``vault-kv`` to keep the token-signing key in Vault, and
``metrics-endpoint`` and ``grafana-dashboard`` for observability.

Where sandboxes run
-------------------

Sandboxes are LXD instances, not Kubernetes pods. The driver creates them in
the LXD project named by the ``lxd-project`` option, and takes their network
and storage pool from that project's ``default`` profile. It never creates
the project or the profile: the LXD administrator does.

The gateway reaches LXD as a TLS identity of its own. The LXD administrator
creates the identity in a group that has access to the sandbox project, and
hands the operator the single-use trust token LXD prints for it. The operator
puts the token in a Juju secret, grants the secret to the gateway, and names
it in the ``lxd-join-secret`` option. The charm's leader unit redeems the
token with a client certificate the charm generated, so LXD binds the
identity to that certificate, and the certificate's private key never leaves
the charm. The token also carries the LXD server's addresses and certificate
fingerprint, which is how the driver finds and verifies the server.

By default, the charm puts every sandbox NIC behind an LXD network ACL that
lets it reach the gateway and the public internet and nothing else. LXD
applies ACLs to single NICs on OVN networks only, which is why the profile
must name an OVN network. A MicroCloud provides one.

The addresses the deployment publishes
--------------------------------------

A deployment with the ``openshell-stack`` Terraform module publishes two
addresses. They have different audiences, and the audience decides where
each one can live.

``external_hostname``
    Where the gateway is served, on port 8443. The ``openshell`` CLI connects
    to it, and so does every sandbox: the gateway hands each sandbox this
    address to dial back and register on. Sandboxes run on an LXD network,
    not the Kubernetes network, so the address must be routable from the
    sandbox network. A Kubernetes cluster IP does not work.

``identity_hostname``
    Where the identity platform serves its OIDC issuer. The gateway's pods
    fetch the issuer's discovery document from it, and so does the CLI of
    everyone who logs in. Sandboxes never use it.

On a MicroCloud, both Traefik instances get load-balancer addresses on the
Kubernetes VM's OVN network. The two addresses then diverge:

- ``identity_hostname`` has to be the core Traefik's load-balancer address
  itself. An LXD network forward does not work for it: the gateway's pods
  run on the Kubernetes VM, which is also where the forward would point,
  and OVN does not route an instance's traffic to a forward's address back
  to that same instance. The gateway's OIDC discovery would time out, and
  the gateway would never start.
- ``external_hostname`` has to reach a different OVN network, the
  sandboxes', from which the Kubernetes network is not routable. It is an
  address on the MicroCloud's uplink, forwarded to the ``openshell``
  Traefik's load-balancer address.

The Kubernetes load balancer assigns addresses in the order services are
created, which changes between deployments. The deploy guide pins each
Traefik to its planned address for that reason.

The stack's models
------------------

The ``openshell-stack`` Terraform module deploys four models on one Juju
controller:

.. list-table::
    :header-rows: 1

    * - Model
      - What it runs
    * - ``openshell``
      - The gateway, PostgreSQL, Traefik and a
        certificate authority, and optionally Vault and an OpenTelemetry
        collector
    * - ``iam``
      - Hydra, Kratos and the login UI
    * - ``core``
      - PostgreSQL, Traefik and a certificate authority for the identity
        platform
    * - ``cos-lite``
      - Prometheus, Loki, Grafana and the rest of COS Lite

Cross-model relations connect them: Hydra's ``oauth`` offer and the core
certificate authority feed the gateway, and COS Lite receives metrics and
dashboards from the gateway's collector and from the identity platform.
The ``openshell`` model can also be deployed on its own with the
``openshell`` module.
