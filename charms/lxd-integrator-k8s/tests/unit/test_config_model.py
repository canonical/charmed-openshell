"""Unit tests for the pure configuration model."""

from __future__ import annotations

from config_model import (
    DEFAULT_LXD_PORT,
    IntegratorConfig,
    LxdConnectionParams,
    VerificationMode,
    load_config,
    parse_endpoints,
)


def test_minimal_valid_config():
    cfg = IntegratorConfig.model_validate(
        {
            "lxd-endpoints": "localhost",
            "client-cert": "CERT",
            "client-key": "KEY",
            "server-cert": "SERVER_CERT",
        }
    )
    assert cfg.trust_name_prefix == "juju-relation"
    assert cfg.verification_mode == VerificationMode.CERTIFICATE
    assert cfg.default_projects is None


def test_endpoint_normalisation():
    assert parse_endpoints("localhost") == (("localhost", DEFAULT_LXD_PORT),)
    assert parse_endpoints("host:8444") == (("host", 8444),)
    assert parse_endpoints("[::1]:8443") == (("::1", 8443),)
    assert parse_endpoints("a:1, b:2 ,[::3]") == (
        ("a", 1),
        ("b", 2),
        ("::3", DEFAULT_LXD_PORT),
    )


def test_credential_completeness():
    _, err = load_config(
        {
            "lxd-endpoints": "localhost",
            "client-cert": "C",
            "client-key": "K",
        }
    )
    assert "server-cert" in err
    assert "lxd-server-fingerprint" in err

    _, err = load_config(
        {
            "lxd-endpoints": "localhost",
            "client-cert": "C",
            "client-key": "K",
            "server-cert": "S",
            "lxd-server-fingerprint": "F",
        }
    )
    assert "only one" in err.lower()

    _, err = load_config(
        {
            "lxd-endpoints": "localhost",
            "client-cert": "C",
            "server-cert": "S",
        }
    )
    assert "client-cert and client-key must be set together" in err


def test_to_connection_params():
    cfg = IntegratorConfig.model_validate(
        {
            "lxd-endpoints": "localhost:8444, [2001:db8::1]",
            "lxd-server-fingerprint": "AB:CD:EF",
            "client-cert": "CERT",
            "client-key": "KEY",
        }
    )
    params = cfg.to_connection_params()
    assert params == LxdConnectionParams(
        endpoints=(("localhost", 8444), ("2001:db8::1", DEFAULT_LXD_PORT)),
        verification_mode=VerificationMode.FINGERPRINT,
        server_pin="ab:cd:ef",
        client_cert="CERT",
        client_key="KEY",
    )


def test_load_config_error():
    model, err = load_config({"lxd-endpoints": "localhost"})
    assert model is None
    assert err is not None
    assert not err.startswith("Value error")


def test_empty_trust_name_prefix_rejected():
    _, err = load_config(
        {
            "lxd-endpoints": "localhost",
            "client-cert": "C",
            "client-key": "K",
            "server-cert": "S",
            "trust-name-prefix": "   ",
        }
    )
    assert "trust-name-prefix cannot be empty" in err


def test_parsed_projects():
    cfg = IntegratorConfig.model_validate(
        {
            "lxd-endpoints": "localhost",
            "client-cert": "C",
            "client-key": "K",
            "server-cert": "S",
            "default-projects": "a, b ,",
        }
    )
    assert cfg.parsed_projects == ["a", "b"]

    cfg_empty = IntegratorConfig.model_validate(
        {
            "lxd-endpoints": "localhost",
            "client-cert": "C",
            "client-key": "K",
            "server-cert": "S",
            "default-projects": "",
        }
    )
    assert cfg_empty.parsed_projects == []
