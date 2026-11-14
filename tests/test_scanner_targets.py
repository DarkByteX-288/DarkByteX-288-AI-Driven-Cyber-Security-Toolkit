import ipaddress
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from scanners.target_validation import (
    TargetValidationError,
    parse_approved_networks,
    validate_scan_request,
    validate_target,
)


APPROVED = parse_approved_networks("192.168.10.0/24,fc00::/7")


@pytest.mark.parametrize(
    "target",
    ["192.168.10.2", "192.168.10.0/30", "fc00::1"],
)
def test_private_asset_targets_are_allowed(target):
    validated = validate_target(target, APPROVED, max_hosts=8)
    assert validated.addresses


@pytest.mark.parametrize(
    "target",
    ["8.8.8.8", "192.168.11.0/24", "127.0.0.1", "169.254.1.2", ""],
)
def test_public_or_out_of_scope_targets_are_rejected(target):
    with pytest.raises(TargetValidationError):
        validate_target(target, APPROVED, max_hosts=64)


def test_loopback_requires_explicit_opt_in_and_approved_cidr():
    loopback_scope = parse_approved_networks("127.0.0.1/32")
    with pytest.raises(TargetValidationError):
        validate_target("127.0.0.1", loopback_scope)
    target = validate_target("127.0.0.1", loopback_scope, allow_loopback=True)
    assert target.addresses == ("127.0.0.1",)


def test_large_cidr_is_rejected():
    with pytest.raises(TargetValidationError, match="scan limit"):
        validate_target("192.168.10.0/24", APPROVED, max_hosts=16)


def test_dns_results_are_pinned_and_all_must_be_in_scope(monkeypatch):
    class MixedResolver:
        def resolve(self, hostname, record_type, **kwargs):
            if record_type == "A":
                return [
                    SimpleNamespace(address="192.168.10.9"),
                    SimpleNamespace(address="8.8.8.8"),
                ]
            raise dns.resolver.NoAnswer()

    monkeypatch.setattr(
        "scanners.target_validation.dns.resolver.Resolver", MixedResolver
    )
    with pytest.raises(TargetValidationError, match="resolves outside"):
        validate_target("assets.example.test", APPROVED)

    class PrivateResolver:
        def resolve(self, hostname, record_type, **kwargs):
            if record_type == "A":
                return [SimpleNamespace(address="192.168.10.9")]
            raise dns.resolver.NoAnswer()

    monkeypatch.setattr(
        "scanners.target_validation.dns.resolver.Resolver", PrivateResolver
    )
    result = validate_target("assets.example.test", APPROVED)
    assert result.addresses == ("192.168.10.9",)


def test_dns_timeout_fails_closed(monkeypatch):
    class TimeoutResolver:
        def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout("DNS query timed out")

    monkeypatch.setattr(
        "scanners.target_validation.dns.resolver.Resolver", TimeoutResolver
    )
    with pytest.raises(TargetValidationError, match="timed out"):
        validate_target("assets.example.test", APPROVED)


def test_authorization_and_safe_profile_are_required():
    with pytest.raises(TargetValidationError, match="authorization"):
        validate_scan_request(
            {"target": "192.168.10.2", "authorization_confirmed": False}, APPROVED
        )
    with pytest.raises(TargetValidationError, match="safe scan profile"):
        validate_scan_request(
            {
                "target": "192.168.10.2",
                "authorization_confirmed": True,
                "profile": "stealth",
            },
            APPROVED,
        )


def test_arbitrary_scanner_arguments_are_rejected():
    with pytest.raises(TargetValidationError, match="Unsupported"):
        validate_scan_request(
            {
                "target": "192.168.10.2",
                "authorization_confirmed": True,
                "arguments": "--script=vuln",
            },
            APPROVED,
        )


def test_port_limits_and_input_types():
    with pytest.raises(TargetValidationError):
        validate_scan_request(
            {
                "target": "192.168.10.2",
                "authorization_confirmed": True,
                "ports": [0],
            },
            APPROVED,
        )
    with pytest.raises(TargetValidationError):
        validate_scan_request(
            {
                "target": "192.168.10.2",
                "authorization_confirmed": True,
                "ports": [22, 22],
            },
            APPROVED,
        )
    assert ipaddress.ip_address(
        validate_target("192.168.10.2", APPROVED).addresses[0]
    ).is_private
