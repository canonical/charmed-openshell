.. meta::
   :description: Charmed OpenShell documentation home page

.. _charmed-openshell-homepage:

Charmed OpenShell
=================

Charmed OpenShell runs the `NVIDIA OpenShell
<https://docs.nvidia.com/openshell/>`_ gateway
on Canonical Kubernetes with Juju, and creates its sandboxes as LXD
instances on a MicroCloud.

Charmed OpenShell is alpha software. Its implementation details are subject
to change.

OpenShell runs AI agents in sandboxes whose file, network and credential
access is governed by policy. Charmed OpenShell deploys and operates the
gateway that manages them: it connects the gateway to PostgreSQL, to the
Canonical Identity Platform for sign-in and to the Canonical Observability
Stack, keeps its certificates and keys, and enforces TLS and role-based
access.

This documentation covers deploying and operating the gateway. For using
OpenShell itself, such as creating sandboxes, writing policies and
configuring providers, see the `OpenShell documentation
<https://docs.nvidia.com/openshell/>`_.

In this documentation
---------------------

:ref:`How-to guides <how-to-guides>`
    Deploy Charmed OpenShell on a MicroCloud, connect the ``openshell`` CLI,
    and rotate the gateway's credentials.

:ref:`Reference <reference>`
    Supported versions, the charm's relations and actions, and the
    Terraform modules.

:ref:`Explanation <explanation>`
    How the deployment fits together, and its security model.

Project and community
---------------------

Charmed OpenShell is a member of the `Canonical <https://canonical.com>`_
family. It's an open source project that welcomes community contributions,
suggestions, fixes and constructive feedback.

* :ref:`Contribute <contribute>`
* `Code of conduct <https://ubuntu.com/community/docs/ethos/code-of-conduct>`_

.. toctree::
    :hidden:
    :maxdepth: 1

    how-to/index
    reference/index
    explanation/index

.. toctree::
    :hidden:
    :maxdepth: 1

    release-notes/index
    contribute/index
