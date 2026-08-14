"""Unit tests for the integrator charm entrypoint."""

from __future__ import annotations

from ops.testing import Context, Secret, State

from charm import LxdIntegratorCharm


def test_charm_starts():
    secret = Secret(
        id="secret:0123456789abcdef0123",
        tracked_content={
            "client-cert": "CLIENT_CERT",
            "client-key": "CLIENT_KEY",
            "server-cert": "SERVER_CERT",
        },
    )
    ctx = Context(LxdIntegratorCharm)
    state = State(
        config={
            "lxd-endpoints": "localhost",
            "lxd-credentials": secret.id,
        },
        secrets={secret},
    )
    with ctx._run(ctx.on.start(), state) as ops:
        ops.run()
        charm = ops.charm

    assert charm._model is not None
    assert charm._config_error is None
    assert charm._model.client_cert == "CLIENT_CERT"
    assert charm._model.client_key == "CLIENT_KEY"
    assert charm._model.server_cert == "SERVER_CERT"


def test_missing_secret_is_config_error():
    ctx = Context(LxdIntegratorCharm)
    state = State(config={"lxd-endpoints": "localhost"})
    with ctx._run(ctx.on.start(), state) as ops:
        ops.run()
        charm = ops.charm

    assert charm._model is None
    assert charm._config_error is not None
    assert not charm._config_error.startswith("Value error")
