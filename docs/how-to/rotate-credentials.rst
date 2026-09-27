.. meta::
   :description: Rotate the gateway's token-signing key and the sandbox client certificate of a Charmed OpenShell deployment.

.. _how-to-rotate-credentials:

How to rotate the gateway's credentials
=======================================

The gateway holds two credentials that sandboxes depend on: the key that
signs each sandbox's token, and the client certificate every sandbox
presents, together with the authority that issues it. This guide rotates
each of them. :ref:`explanation-security` describes what each one protects.

Both rotations restart the workload, and sandboxes that were running before
it stop being able to talk to the gateway. Plan for recreating them.

Prerequisites
-------------

- Juju access to the model running the gateway, ``openshell`` in the
  commands below.
- The ``openshell`` CLI registered with the gateway, to recreate sandboxes;
  see :ref:`how-to-connect-with-openshell-snap`.

List the running sandboxes
--------------------------

Record the sandboxes you will need to recreate:

.. code-block:: bash

    openshell -g production sandbox list

Rotate the token-signing key
----------------------------

Run the action on the leader unit:

.. code-block:: bash

    juju run openshell-gateway-k8s/leader rotate-jwt-signing-key -m openshell

The result shows the new key's ID in ``kid``, and ``store`` shows where the
key lives: ``juju-secret``, or ``vault`` when the gateway is related to
Vault. The charm then restarts the workload with the new key, one unit at a
time.

The gateway verifies sandbox tokens against the current key only, so tokens
signed with the previous key stop verifying after the restart.

Rotate the sandbox client certificate
-------------------------------------

Run the action on the leader unit:

.. code-block:: bash

    juju run openshell-gateway-k8s/leader rotate-sandbox-client-identity -m openshell

The action replaces the certificate and the authority that issued it. The
result shows the new ``ca-fingerprint`` and ``certificate-fingerprint``.
Rotating the certificate alone would not help: the gateway trusts the
authority, so a leaked certificate would stay valid until the authority is
replaced.

The charm restarts the workload with the new authority. Running sandboxes
keep the previous certificate, which the gateway no longer accepts.

Check the gateway
-----------------

Wait for the unit to return to ``active`` and ``idle``, then check the
workload:

.. code-block:: bash

    juju run openshell-gateway-k8s/0 get-gateway-status -m openshell

``workload-running`` should read ``True``, both entries in
``workload-checks`` should read ``up``, and after a key rotation ``jwt-kid``
should match the ``kid`` from the action.

Recreate the sandboxes
----------------------

After a rotation, sandboxes created before it drop from ``Ready`` to
``Provisioning`` in ``sandbox list``, and ``sandbox exec`` fails with
``supervisor session not connected``. They do not recover on their own.

Delete each sandbox you recorded and create it again, with the same options
you created it with originally:

.. code-block:: bash

    openshell -g production sandbox delete <name>
    openshell -g production sandbox create --name <name>

See `Manage sandboxes
<https://docs.nvidia.com/openshell/v0.0.116/sandboxes/manage-sandboxes>`_
for the options ``sandbox create`` takes.
