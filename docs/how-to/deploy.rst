.. meta::
   :description: Deploy Charmed OpenShell with the Canonical Identity Platform and COS Lite on a MicroCloud, using the openshell-stack Terraform module.

.. _how-to-deploy-charmed-openshell:

How to deploy Charmed OpenShell
===============================

This guide deploys Charmed OpenShell with the Canonical Identity Platform
and COS Lite on a MicroCloud, using the ``openshell-stack`` Terraform module.
Canonical Kubernetes runs in a virtual machine on the MicroCloud, the Juju
controller runs on that Kubernetes, and sandboxes run as LXD instances next
to it. An admin VM on the Kubernetes VM's network runs Juju and Terraform.
:ref:`explanation-architecture` describes the result.

Every step says where it runs: **on a MicroCloud member** (any machine with
the ``lxc`` client configured against the MicroCloud), or **in the admin
VM**.

Prerequisites
-------------

- A `MicroCloud <https://canonical.com/microcloud>`_ cluster with OVN
  networking, that is, with an uplink network (``UPLINK`` by default) and a
  storage pool (``local`` by default).
- Shell access to a MicroCloud member, with ``jq`` and ``openssl``.

Plan the network
----------------

Choose the addresses before you start. The examples in this guide use these:

.. list-table::
    :header-rows: 1

    * - What
      - Where
      - In the examples
    * - Kubernetes VM and admin VM
      - An OVN network, here the MicroCloud's ``default`` network
      - ``10.20.202.0/24``
    * - Load-balancer pool
      - Four addresses of the same subnet: the Juju controller's, and one
        each for the Traefik of the ``core``, ``openshell`` and ``cos-lite``
        models
      - ``10.20.202.200/29``
    * - ``identity_hostname``
      - The ``core`` Traefik's load-balancer address
      - ``10.20.202.201``
    * - ``openshell.external_hostname``
      - A free uplink address, forwarded to the ``openshell`` Traefik's
        load-balancer address (``10.20.202.202``)
      - ``192.168.1.233``
    * - Sandboxes
      - An OVN network of their own in the ``openshell`` LXD project
      - ``openshell-sandboxes``

``identity_hostname`` has to be reachable from the gateway's pods and from
the machines of users who log in. ``openshell.external_hostname`` has to be
reachable from the sandbox network and from the machines running the
``openshell`` CLI. :ref:`explanation-architecture` explains why the first is
a load-balancer address and the second an uplink address.

A machine outside the MicroCloud reaches ``identity_hostname`` only if its
network routes ``10.20.202.0/24`` through that network's OVN router. The
admin VM reaches both addresses directly.

Create the Kubernetes VM
------------------------

On a MicroCloud member, launch an Ubuntu 24.04 LTS VM. The stack's four models
need about 14 GiB of memory; the sizes below are the ones this guide was
tested with:

.. code-block:: bash

    lxc launch ubuntu:24.04 k8s-vm --vm \
      -c limits.cpu=6 -c limits.memory=14GiB -d root,size=120GiB

``lxc exec`` fails until the VM's agent is up; retry it until it answers,
then install and bootstrap Canonical Kubernetes:

.. code-block:: bash

    lxc exec k8s-vm -- cloud-init status --wait
    lxc exec k8s-vm -- snap install k8s --classic --channel=1.32-classic/stable
    lxc exec k8s-vm -- k8s bootstrap
    lxc exec k8s-vm -- k8s status --wait-ready

Enable the cluster's load balancer with the planned pool:

.. code-block:: bash

    lxc exec k8s-vm -- k8s set load-balancer.cidrs=10.20.202.200/29 load-balancer.l2-mode=true
    lxc exec k8s-vm -- k8s enable load-balancer

OVN port security drops traffic for addresses a NIC does not own, so route
the pool to the VM's NIC:

.. code-block:: bash

    lxc config device override k8s-vm eth0 ipv4.routes=10.20.202.200/29

Create the admin VM
-------------------

On a MicroCloud member, launch a small VM on the same network, and install
the tools the rest of the guide runs there:

.. code-block:: bash

    lxc launch ubuntu:24.04 openshell-admin --vm -c limits.cpu=2 -c limits.memory=4GiB
    lxc exec openshell-admin -- cloud-init status --wait
    lxc exec openshell-admin -- snap install juju --channel=3.6/stable
    lxc exec openshell-admin -- snap install terraform --classic
    lxc exec openshell-admin -- snap install jq
    lxc exec openshell-admin -- sudo -u ubuntu mkdir -p /home/ubuntu/.local/share/juju

The rest of the guide works in the admin VM as its ``ubuntu`` user. The
``juju`` snap is strictly confined: it reads only files under that user's
home directory and its own dotfile locations, not ``/root``, and it cannot
create its data directory itself, so the last command creates it. The
``terraform`` snap tracks the current release, which satisfies the
``openshell-stack`` module's requirement of Terraform 1.15 or newer.

Hand the admin VM the Kubernetes cluster's kubeconfig, which names the
Kubernetes VM's address, at the path ``juju`` looks for it:

.. code-block:: bash

    lxc exec k8s-vm -- k8s config > k8s-vm.kubeconfig
    lxc file push --create-dirs --uid 1000 --gid 1000 --mode 0600 \
      k8s-vm.kubeconfig openshell-admin/home/ubuntu/.kube/config

Open a shell in the admin VM for the steps marked "in the admin VM":

.. code-block:: bash

    lxc exec openshell-admin -- sudo -iu ubuntu

Bootstrap Juju
--------------

In the admin VM, register the cluster with Juju and bootstrap a controller
with a load-balanced API service. The Juju Terraform provider cannot use the
Kubernetes API proxy the ``juju`` CLI otherwise falls back to:

.. code-block:: bash

    juju add-k8s microcloud-k8s --client
    juju bootstrap microcloud-k8s --config controller-service-type=loadbalancer

The controller takes the pool's first address, ``10.20.202.200``.

Publish the gateway address
---------------------------

On a MicroCloud member, allow the gateway's uplink address on the uplink
network, then forward it to the address the ``openshell`` Traefik will be
pinned to:

.. code-block:: bash

    lxc network set UPLINK ipv4.routes=192.168.1.233/32
    lxc network forward create default 192.168.1.233 target_address=10.20.202.202

``ipv4.routes`` replaces the uplink's existing list; append to it if it
already holds routes. The forward answers once the Traefik exists.

The Terraform configuration below pins each Traefik to its planned address
with the ``loadbalancer_annotations`` option; without it, the load balancer
assigns addresses in the order services are created. Canonical Kubernetes'
load balancer uses the ``metallb.io/loadBalancerIPs`` annotation.

.. _how-to-deploy-sandbox-project:

Create the LXD project
----------------------

The driver creates sandboxes in one LXD project and takes their network and
storage pool from the project's ``default`` profile. The network has to be
an OVN network for sandbox egress restriction to work.

Create the project with ``features.networks=true``, so that it can hold a
network of its own; without it, ``lxc network create --project`` creates the
network in the ``default`` project instead. On a MicroCloud member:

.. code-block:: bash

    lxc project create openshell -c features.networks=true
    lxc network create openshell-sandboxes --type=ovn network=UPLINK --project openshell
    lxc profile device add default eth0 nic network=openshell-sandboxes --project openshell
    lxc profile device add default root disk path=/ pool=local --project openshell

Replace ``UPLINK`` with your MicroCloud's uplink network and ``local`` with
an existing storage pool if yours differ. Confirm that the network belongs
to the project:

.. code-block:: bash

    lxc network list --project openshell

Then restrict the project. The gateway's LXD certificate is limited to this
project, and these restrictions limit what it can do inside it. Without
them, anything that can create an instance in the project can create a
privileged container or attach the host's root file system:

.. code-block:: bash

    lxc project set openshell \
      restricted=true \
      restricted.networks.uplinks=UPLINK \
      restricted.networks.access=openshell-sandboxes \
      limits.networks=1 \
      restricted.snapshots=block \
      restricted.backups=block

``restricted=true`` refuses privileged and nested containers, low-level
options such as ``raw.lxc``, host paths and passthrough devices. LXD refuses
the setting unless the uplink the sandbox network uses is allowed, and
``limits.networks=1`` stops the project from creating a second network on
that uplink. ``restricted.networks.access`` keeps instances on the sandbox
network. The driver uses neither snapshots nor backups.

Sandbox images are OCI references that the driver pulls and converts on
first use, so the project needs no images of its own.

Create the integrator's client certificate
-------------------------------------------

The integrator authenticates to the MicroCloud with a client certificate of
its own, and verifies the MicroCloud's server certificate. It uses its
certificate to add the gateway's certificate to LXD's trust store,
restricted to the ``openshell`` project, and to remove it again.

That makes the integrator's certificate an LXD administrator credential.
LXD has no narrower permission for managing trust entries: a certificate
restricted to a project cannot add any, and an identity allowed to create
them can create unrestricted ones. Keep it only in the Juju secret below.

On a MicroCloud member, create the certificate, fetch the server's, and hand
both to the admin VM:

.. code-block:: bash

    openssl req -x509 -newkey rsa:4096 -keyout lxd-client.key -out lxd-client.crt \
      -days 365 -nodes -subj "/CN=lxd-integrator-k8s"
    lxc config trust add lxd-client.crt --name lxd-integrator-k8s
    lxc query /1.0 | jq -r '.environment.certificate' > lxd-server.crt
    lxc query /1.0 | jq -r '.environment.addresses[0]'
    for f in lxd-client.crt lxd-client.key lxd-server.crt; do
      lxc file push --uid 1000 --gid 1000 --mode 0600 "$f" openshell-admin/home/ubuntu/
    done

The ``addresses`` query prints the MicroCloud's API address, for example
``192.168.1.166:8443``; the integrator's ``lxd-endpoints`` below takes it.
The client key is an administrative LXD credential: remove the local copies
once the secret below holds them.

Create the gateway's model
--------------------------

The LXD credentials secret has to exist before the stack is applied, because
its URI is part of the integrator's configuration, and a Juju secret lives
in a model. In the admin VM, create the ``openshell`` model yourself and hand
it to the stack by UUID:

.. code-block:: bash

    juju add-model openshell
    juju show-model openshell --format=json | jq -r '.openshell."model-uuid"'

Keep the UUID for the Terraform configuration below. The stack creates the
``iam``, ``core`` and ``cos-lite`` models itself.

Store the LXD credentials in a Juju secret
------------------------------------------

The integrator reads the client certificate, its key, and the server
certificate from a Juju secret, not from Terraform state. In the admin VM:

.. code-block:: bash

    cd ~
    juju add-secret lxd-credentials -m openshell \
      client-cert#file=lxd-client.crt \
      client-key#file=lxd-client.key \
      server-cert#file=lxd-server.crt

The command prints the secret's URI (for example, ``secret:d6mlp2o0p26r50dt2sd0``);
keep it for the Terraform configuration below.

Write the Terraform configuration
---------------------------------

In the admin VM, create a working directory and a ``main.tf`` that calls the
``openshell-stack`` module:

.. code-block:: terraform

    terraform {
      required_version = ">= 1.15"

      required_providers {
        juju = {
          source  = "juju/juju"
          version = ">= 1.4"
        }
      }
    }

    provider "juju" {}

    module "openshell-stack" {
      source = "git::https://github.com/canonical/charmed-openshell//terraform/openshell-stack"

      models = {
        openshell = { uuid = "<openshell-model-uuid>" }
      }

      # The core Traefik's load-balancer address: reachable from the
      # gateway's pods and from the machines that log in.
      identity_hostname = "10.20.202.201"

      core = {
        traefik = {
          config = {
            loadbalancer_annotations = "metallb.io/loadBalancerIPs=10.20.202.201"
          }
        }
      }

      openshell = {
        # Reachable from the sandbox network as well as from clients:
        # sandboxes dial back to this address to register with the gateway.
        external_hostname = "192.168.1.233"

        # Hydra puts a client-credentials token's scopes in `scp`; see the
        # connect guide.
        oidc = {
          roles_claim = "scp"
        }

        traefik = {
          config = {
            loadbalancer_annotations = "metallb.io/loadBalancerIPs=10.20.202.202"
          }
        }

        gateway = {
          # Both OpenShell charms publish to latest/edge only.
          channel = "latest/edge"

          # The gateway and supervisor images of one build; see below.
          config = {
            "supervisor-image" = "ghcr.io/canonical/openshell-supervisor:6861f7e0b5f6e05c72478ada33486d536a834d6a"
          }
          resources = {
            "gateway-image" = "ghcr.io/canonical/openshell-gateway:6861f7e0b5f6e05c72478ada33486d536a834d6a"
          }
        }

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

Replace ``<openshell-model-uuid>``, the planned addresses, ``lxd-endpoints``
(the MicroCloud API address printed earlier) and ``lxd-credentials`` with the
values from the previous steps.

Set both images as shown until the charm's ``latest/edge`` revision
ships them as its defaults. The revision published today bundles an
older gateway image, whose driver ignores the project's ``default``
profile, and defaults to a supervisor image from a newer OpenShell
release. With either, every sandbox create fails.
:ref:`reference-requirements` lists the pinned build.

Deploy the stack
----------------

In the admin VM, initialize the working directory, then review and apply the
plan:

.. code-block:: bash

    terraform init
    terraform plan -out=stack.tfplan
    terraform apply stack.tfplan

Terraform creates the ``iam``, ``core`` and ``cos-lite`` models and deploys
every application into them and into ``openshell``.

Grant the secret
----------------

In the admin VM, grant the integrator access to the secret you created
earlier:

.. code-block:: bash

    juju grant-secret lxd-credentials lxd-integrator-k8s -m openshell

The integrator reads the secret at its next ``update-status`` hook, and
stays blocked with ``exactly one of server-cert or lxd-server-fingerprint
must be set`` until then. Allow up to 15 minutes on a fresh deployment.

Watch the deployment converge across all four models:

.. code-block:: bash

    juju status --watch 5s -m openshell
    juju status --watch 5s -m iam
    juju status --watch 5s -m core
    juju status --watch 5s -m cos-lite

Wait until every unit in every model is ``active`` and ``idle``. With an IP
address as ``external_hostname``, the gateway reports ``ingress: wildcard
SNI active``; use a DNS name to scope the route.

Verify the gateway
------------------

An ``active`` unit does not prove the workload is serving, so check it:

.. code-block:: bash

    juju run openshell-gateway-k8s/0 get-gateway-status -m openshell

In the result:

- ``workload-checks`` should read ``driver-ready=up, gateway-ready=up``.
- ``lxd-project`` should read ``openshell``.
- ``sandbox-egress-restricted`` should read ``True``.
- ``gateway-endpoint`` should name ``external_hostname`` on port 8443.

If a check is ``down``, read the workload's logs from a MicroCloud member:

.. code-block:: bash

    lxc exec k8s-vm -- k8s kubectl -n openshell exec openshell-gateway-k8s-0 -c gateway -- pebble logs -n 20

``OIDC discovery request failed`` means the pods cannot reach
``identity_hostname``. A ``driver-lxd`` error about the project's
``default`` profile means the profile lacks the network or root disk from
:ref:`Create the LXD project <how-to-deploy-sandbox-project>`.

To create a first sandbox, connect the CLI as described in
:ref:`how-to-connect-with-openshell-snap`.
