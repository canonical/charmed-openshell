.. meta::
   :description: Connect the OpenShell CLI to a Charmed OpenShell gateway with an OIDC client-credentials registration.

.. _how-to-connect-with-openshell-snap:

How to connect to the gateway with the openshell snap
=====================================================

This guide connects the ``openshell`` CLI to a deployed gateway with an
OIDC client-credentials registration, a service account that needs no
browser. It suits automation and an administrator's first session.

This guide does not cover a human operator's interactive browser sign-in
(``openshell gateway login``). The only Hydra client a deployment registers
on its own is the gateway's: a confidential authorization-code client,
created over the ``oauth`` relation, whose secret stays with the gateway. A
browser sign-in from the CLI needs a client of its own on Hydra.

Prerequisites
-------------

- An active Charmed OpenShell deployment, for example from
  :ref:`how-to-deploy-charmed-openshell`.
- Juju CLI access to the model running the gateway, and to the model
  running the identity platform's Hydra (the ``iam`` model, when deployed
  with the ``openshell-stack`` Terraform module).
- A network path from this machine to the gateway's ``external_hostname``
  and to the identity platform's ``identity_hostname``. The admin VM from
  the deploy guide has both, as does any instance on the Kubernetes VM's
  network. A machine outside the MicroCloud reaches ``external_hostname``
  on the uplink, but ``identity_hostname`` only if its network routes the
  Kubernetes network through that network's OVN router.
- ``sudo``, to add certificates to the host's trust store, and ``jq``.

The commands below run in the admin VM from the deploy guide.

Install the openshell snap
--------------------------

The CLI has to come from the same OpenShell release as the gateway; a newer
CLI cannot decode its responses. Install the revision that
:ref:`reference-requirements` lists for your architecture, and hold it:

.. code-block:: bash

    sudo snap install openshell --revision=1041
    sudo snap refresh --hold openshell

On a machine that already has the snap, use
``sudo snap refresh openshell --revision=1041`` instead of the install.

Trust the gateway's and the identity issuer's certificates
----------------------------------------------------------

The CLI dials two TLS endpoints: the gateway's, and the OIDC issuer's. Each
is signed by its own ``self-signed-certificates`` application unless your
deployment uses publicly trusted certificates. Fetch and install both CAs:

.. code-block:: bash

    juju run self-signed-certificates/0 get-ca-certificate -m openshell --format=json \
      | jq -r '.[].results."ca-certificate"' \
      | sudo tee /usr/local/share/ca-certificates/openshell-gateway-ca.crt > /dev/null

    juju run self-signed-certificates/0 get-ca-certificate -m core --format=json \
      | jq -r '.[].results."ca-certificate"' \
      | sudo tee /usr/local/share/ca-certificates/openshell-identity-ca.crt > /dev/null

    sudo update-ca-certificates

Skip the ``core`` model command when the gateway and the identity issuer
share one certificate authority, or use a different model name if your
identity platform runs elsewhere.

Read the gateway's OIDC configuration
-------------------------------------

.. code-block:: bash

    juju run openshell-gateway-k8s/0 get-oidc-client-config -m openshell

Note the ``issuer`` and ``audience`` values from the result; both are needed
below. The ``issuer`` is ``https://`` followed by the stack's
``identity_hostname``. The result's ``client-id`` is the gateway's own
audience name, not a client you can authenticate as; the next step creates
that client.

Create an OAuth2 client on Hydra
--------------------------------

Register a client-credentials client scoped to one of the gateway's RBAC
roles. The Terraform modules name them ``openshell-admin`` and
``openshell-user`` unless configured otherwise; ``juju config
openshell-gateway-k8s oidc-admin-role -m openshell`` shows yours.
``grant-types``, ``scope`` and ``audience`` take lists, so pass them in YAML
list syntax; a plain value fails the action's validation with ``must be of
type array``:

.. code-block:: bash

    juju run hydra/0 create-oauth-client -m iam --format=json \
      name=openshell-cli \
      'grant-types=[client_credentials]' \
      'scope=[openshell-admin]' \
      'audience=[openshell-cli]' \
      token-endpoint-auth-method=client_secret_post \
      > openshell-cli-client.json

Replace ``openshell-admin`` with ``openshell-user`` for a non-admin
principal, ``openshell-cli`` in ``audience`` with the ``audience`` read
above, and ``iam`` with the model your Hydra unit runs in. The result holds a
``client-id`` and a ``client-secret``. Hydra does not show the secret again,
so keep the file, and keep it private:

.. code-block:: bash

    chmod 600 openshell-cli-client.json
    jq -r '.[].results."client-id"' openshell-cli-client.json

Hydra places a client-credentials client's granted scopes in the token's
``scp`` claim, never in ``groups``. The gateway's ``oidc-roles-claim``
config defaults to ``groups``, which suits a human's browser login but
not this service-account path. The deploy guide sets
``openshell.oidc.roles_claim = "scp"``; on a deployment that did not, run
``juju config openshell-gateway-k8s oidc-roles-claim=scp -m openshell``
before the principal you register here can pass the gateway's RBAC
checks, for example to create a sandbox.

Register the gateway with the CLI
---------------------------------

The gateway listens on port 8443, behind Traefik in TLS passthrough. Name
the port: without it the CLI reaches Traefik's HTTPS router on port 443,
which answers ``404 Not Found``, and ``openshell status`` reports
``invalid compression flag``.

.. code-block:: bash

    export OPENSHELL_OIDC_CLIENT_SECRET="$(jq -r '.[].results."client-secret"' openshell-cli-client.json)"
    openshell gateway add https://<external-hostname>:8443 \
      --name production \
      --oidc-issuer <issuer-url> \
      --oidc-client-id <client-id> \
      --oidc-audience openshell-cli \
      --oidc-scopes openshell-admin

Replace ``<external-hostname>``, ``<issuer-url>`` and ``<client-id>`` with
the values from the previous steps, and ``openshell-admin`` with the scope
you granted. Keep ``OPENSHELL_OIDC_CLIENT_SECRET`` set in the environment of
later ``openshell`` commands, which use it to request fresh tokens.

Verify the connection
---------------------

.. code-block:: bash

    openshell status -g production

Expect ``Status: Connected``, ``Authentication: Authenticated (OIDC)`` and a
``Version`` that matches ``openshell --version``.

Create a first sandbox
----------------------

.. code-block:: bash

    openshell -g production sandbox create --name first
    openshell -g production sandbox list
    openshell -g production sandbox exec -n first -- id
    openshell -g production sandbox delete first

The driver pulls the default sandbox image and converts it into an LXD image
as soon as it starts, which takes several minutes; a create issued before
that finishes waits for it. Once it is ready, a create takes seconds. A
sandbox from another image takes minutes the first time that image is
used. The sandbox lists as ``Ready`` once its supervisor
has registered with the gateway over ``external_hostname``, and it shows up
as an LXD instance in the gateway's project, as a MicroCloud member lists:

.. code-block:: bash

    lxc list --project openshell

Remove the registration
-----------------------

.. code-block:: bash

    openshell gateway remove production
