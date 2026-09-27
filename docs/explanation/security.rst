.. meta::
   :description: The security model of Charmed OpenShell: TLS, OIDC and roles, how sandboxes authenticate, and where credentials are kept.

.. _explanation-security:

Security model
==============

Sandboxes run untrusted agent workloads, and the charm's defaults are
chosen for that. Several of them cannot be turned off.

TLS and user authentication
---------------------------

The gateway always serves TLS; the charm has no option to disable it.
Traefik passes connections through without terminating them, so the gateway
holds its own certificate and private key.

Every user authenticates with OIDC against the issuer on the ``oauth``
relation. There is no way to configure unauthenticated access. The gateway
maps a claim in the user's token to one of two roles: ``oidc-roles-claim``
names the claim, and ``oidc-admin-role`` and ``oidc-user-role`` name the
values that grant each role. The charm stays blocked until both roles are
set. What each role may do is defined by OpenShell; see `Gateway
authentication
<https://docs.nvidia.com/openshell/v0.0.116/reference/gateway-auth>`_.

How sandboxes authenticate
--------------------------

A sandbox proves two things to the gateway, with two different credentials.

A client certificate proves the connection comes from a sandbox of this
deployment. Every sandbox gets the same one, so it says nothing about which
sandbox is calling. The gateway verifies it against a certificate authority
the charm creates for this purpose only. That authority's private key stays
in a Juju secret and never reaches the workload.

A JSON Web Token proves which sandbox it is. The gateway mints one per
sandbox, and the driver places it in the instance, readable by root only,
before the sandbox starts. The gateway signs these tokens with an
Ed25519 key that the charm keeps in a Juju secret, or in Vault when
``vault-kv`` is related.

Users are not affected by the client certificate. The gateway demands one
only when no OIDC issuer is configured, and the charm always configures
one. The CLI presents no certificate and authenticates with OIDC.

The deployment uses two certificate authorities, for opposite directions:

.. list-table::
    :header-rows: 1

    * - Authority
      - Who trusts it
      - For what
    * - The gateway's TLS issuer, from the ``certificates`` relation
      - Sandboxes
      - Verifying the gateway's server certificate
    * - The sandbox client authority, created by the charm
      - The gateway
      - Verifying a sandbox's client certificate

The charm does not request the sandbox certificate over the
``certificates`` relation, because that relation keeps one private key per
relation: a second request would hand every sandbox the gateway's own
server key.

What the gateway can do in LXD
------------------------------

The integrator registers the gateway's LXD client certificate restricted to
the sandbox project, so LXD refuses the gateway anything outside it. Inside
the project, the gateway can do whatever the project allows. In an
unrestricted project that includes creating a privileged container or
attaching the host's root file system, which amounts to control of the
host. The deploy guide therefore sets ``restricted=true`` on the project,
together with limits on its networks, snapshots and backups; see
:ref:`how-to-deploy-sandbox-project`.

What a sandbox can reach
------------------------

With ``restrict-sandbox-egress`` on, the default, every sandbox NIC sits
behind an LXD network ACL that allows the gateway's address and public
internet addresses. Everything else is blocked, including the LAN the
sandbox network is attached to, the LXD host and the LXD API. LXD enforces
these ACLs on OVN networks only. Turning the option off lets a sandbox reach
whatever its network reaches.

OpenShell's own policies then govern what the sandboxed process may do on
the filesystem, on the network and with credentials. See `Customize sandbox
policies <https://docs.nvidia.com/openshell/v0.0.116/sandboxes/policies>`_.

Where credentials live
----------------------

LXD credentials
    ``lxd-integrator-k8s`` reads an LXD administrator credential from a Juju
    secret that the operator creates. It needs one: adding and removing
    trust entries is an administrator's operation in LXD. The Terraform
    modules take the secret's URI, never the key, so the key does not end
    up in Terraform state.

The token-signing key
    A Juju application secret, shared by every gateway unit. Relating
    ``vault-kv`` moves it into Vault: the leader copies the current key
    across, so tokens already issued keep verifying.

The sandbox client authority
    A Juju secret that only the charm reads.

Two exceptions
--------------

The workload's metrics endpoint serves plain HTTP without authentication,
because the gateway offers nothing else for it. The charm never routes it
through ingress, so only the pod network reaches it.

``insecure-registries`` turns off TLS verification for the registries it
names, for plain HTTP and HTTPS alike. Anything on the path to such a
registry can then substitute an image, including the supervisor image,
which runs as the process that enforces the sandbox boundary. Prefer
relating the registry's certificate authority over ``receive-ca-cert``.
