.. meta::
   :description: Software versions Charmed OpenShell needs and has been tested with, including the OpenShell release and the matching CLI.

.. _reference-requirements:

Requirements and versions
=========================

Platform
--------

.. list-table::
    :header-rows: 1

    * - Component
      - Requirement
      - Tested with
    * - Juju
      - 3.4 or newer
      - 3.6
    * - Kubernetes
      - Any Kubernetes that Juju supports
      - Canonical Kubernetes 1.32
    * - LXD, for sandboxes
      - 5.21 or newer, for TLS identities in groups. An OVN network in the
        sandbox project, for sandbox egress restriction
      - MicroCloud 3, with LXD 6 and MicroOVN 24.03; LXD 5.21
    * - Architecture
      - ``amd64`` or ``arm64``
      - ``amd64``

Terraform
---------

.. list-table::
    :header-rows: 1

    * - Module
      - Terraform
      - Juju provider
    * - ``terraform/openshell``
      - 1.5 or newer
      - 1.0 or newer
    * - ``terraform/openshell-stack``
      - 1.15 or newer
      - 1.4 or newer

The stack module needs Terraform 1.15 for constant variables in module
sources, and the Juju provider 1.4 because COS Lite requires it.

OpenShell
---------

The charm runs OpenShell 0.0.116. Its gateway and supervisor images come
from one build and are pinned to that build's commit tag:

.. list-table::
    :header-rows: 1

    * - Image
      - Reference
    * - Gateway, the ``gateway-image`` resource
      - ``ghcr.io/canonical/openshell-gateway:6861f7e0b5f6e05c72478ada33486d536a834d6a``
    * - Supervisor, the ``supervisor-image`` option
      - ``ghcr.io/canonical/openshell-supervisor:6861f7e0b5f6e05c72478ada33486d536a834d6a``

Keep the two on the same tag. A supervisor from another OpenShell release
fails to sync policy with the gateway and exits.

The OpenShell documentation for this release is at
`docs.nvidia.com/openshell/v0.0.116
<https://docs.nvidia.com/openshell/v0.0.116/about/how-it-works>`_. Pages
without the version in their address describe a newer release.

The ``openshell`` CLI
---------------------

The CLI has to come from the same OpenShell release as the gateway. A 0.1.x
CLI cannot decode a 0.0.116 gateway's responses: ``sandbox list`` reports
``workspace 'default' not found``. No snap channel carries 0.0.116 any more,
so install it by revision and hold it:

.. list-table::
    :header-rows: 1

    * - Architecture
      - Snap revision
    * - ``amd64``
      - 1041

On ``amd64``:

.. code-block:: bash

    sudo snap install openshell --revision=1041
    sudo snap refresh --hold openshell
