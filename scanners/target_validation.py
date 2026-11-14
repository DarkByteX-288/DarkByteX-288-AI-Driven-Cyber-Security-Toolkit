"""Strict target, scope, authorization, and port validation."""

import ipaddress
import re
import time
from dataclasses import dataclass

import dns.exception
import dns.resolver

DEFAULT_PORTS = (22, 53, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017)
MAX_PORTS = 100
DNS_TIMEOUT_SECONDS = 3
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class TargetValidationError(ValueError):
    """Raised when a requested assessment target is invalid or out of scope."""


@dataclass(frozen=True)
class ValidatedTarget:
    submitted: str
    addresses: tuple
    networks: tuple


def parse_approved_networks(value):
    """Parse configured asset networks; defaults to RFC1918 and IPv6 ULA."""
    if not value:
        value = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
    networks = []
    for item in value.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=True)
        except ValueError as exc:
            raise RuntimeError(f"Invalid approved scanner network: {candidate}") from exc
        networks.append(network)
    if not networks:
        raise RuntimeError("At least one approved scanner network must be configured.")
    return tuple(networks)


def _address_is_approved(address, networks, allow_loopback=False):
    if address.is_multicast or address.is_unspecified:
        return False
    if address.is_loopback and not allow_loopback:
        return False
    if address.is_link_local or address.is_reserved:
        return False
    return any(address.version == network.version and address in network for network in networks)


def _resolve_hostname(hostname):
    try:
        ascii_hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError("Target hostname is not valid IDNA.") from exc
    if len(ascii_hostname) > 253 or not ascii_hostname:
        raise TargetValidationError("Target hostname is invalid.")
    labels = ascii_hostname.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise TargetValidationError("Target hostname is invalid.")
    addresses = set()
    resolver = dns.resolver.Resolver()
    deadline = time.monotonic() + DNS_TIMEOUT_SECONDS
    for record_type in ("A", "AAAA"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TargetValidationError("DNS resolution exceeded its timeout.")
        try:
            records = resolver.resolve(
                ascii_hostname,
                record_type,
                search=False,
                lifetime=remaining,
            )
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN as exc:
            raise TargetValidationError("Target hostname could not be resolved.") from exc
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise TargetValidationError("DNS resolution failed or timed out.") from exc
        for record in records:
            try:
                addresses.add(ipaddress.ip_address(record.address))
            except ValueError as exc:
                raise TargetValidationError("DNS returned an invalid address.") from exc
    if not addresses:
        raise TargetValidationError("Target hostname has no address records.")
    return ascii_hostname, tuple(sorted(addresses, key=lambda item: (item.version, int(item))))


def validate_target(target, approved_networks, max_hosts=64, allow_loopback=False):
    """Resolve and pin a single IP, CIDR, or hostname to approved addresses."""
    if not isinstance(target, str):
        raise TargetValidationError("Target must be a string.")
    submitted = target.strip()
    if not submitted or len(submitted) > 253 or any(char.isspace() for char in submitted):
        raise TargetValidationError("Target is empty or exceeds the supported length.")
    try:
        network = ipaddress.ip_network(submitted, strict=True)
    except ValueError:
        network = None

    if network is not None:
        count = network.num_addresses
        if network.version == 4 and network.prefixlen < 31:
            count -= 2
        if count < 1 or count > max_hosts:
            raise TargetValidationError(f"Target exceeds the {max_hosts}-host scan limit.")
        if not any(
            network.version == approved.version and network.subnet_of(approved)
            for approved in approved_networks
        ):
            raise TargetValidationError("Target network is outside the configured approved asset ranges.")
        addresses = tuple(network.hosts())
        if not addresses:
            addresses = (network.network_address,)
        if any(
            not _address_is_approved(address, approved_networks, allow_loopback)
            for address in addresses
        ):
            raise TargetValidationError("Target includes addresses outside the approved scan scope.")
        return ValidatedTarget(submitted, tuple(str(address) for address in addresses), (str(network),))

    if any(char in submitted for char in (",", ";", "/", "\\", "@", "%", "\x00")):
        raise TargetValidationError("Target contains unsupported characters.")
    try:
        address = ipaddress.ip_address(submitted)
        addresses = (address,)
        hostname = str(address)
    except ValueError:
        hostname, addresses = _resolve_hostname(submitted)

    if any(
        not _address_is_approved(address, approved_networks, allow_loopback)
        for address in addresses
    ):
        raise TargetValidationError("Target resolves outside the configured approved asset ranges.")
    return ValidatedTarget(
        hostname,
        tuple(str(address) for address in addresses),
        tuple(str(address) for address in addresses),
    )


def validate_ports(ports):
    """Return a bounded unique list of valid TCP ports."""
    if ports is None:
        return list(DEFAULT_PORTS)
    if not isinstance(ports, list) or not ports or len(ports) > MAX_PORTS:
        raise TargetValidationError(f"Select between 1 and {MAX_PORTS} TCP ports.")
    parsed = []
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise TargetValidationError("Ports must be integers between 1 and 65535.")
        parsed.append(port)
    if len(set(parsed)) != len(parsed):
        raise TargetValidationError("Duplicate ports are not allowed.")
    return sorted(parsed)


def validate_scan_request(data, approved_networks, max_hosts=64, allow_loopback=False):
    if not isinstance(data, dict):
        raise TargetValidationError("A JSON object is required.")
    unexpected = set(data) - {"target", "ports", "profile", "authorization_confirmed"}
    if unexpected:
        raise TargetValidationError("Unsupported scan options were supplied.")
    if data.get("authorization_confirmed") is not True:
        raise TargetValidationError("Explicit authorization confirmation is required.")
    if data.get("profile", "safe") != "safe":
        raise TargetValidationError("Only the safe scan profile is supported.")
    target = validate_target(
        data.get("target"),
        approved_networks,
        max_hosts=max_hosts,
        allow_loopback=allow_loopback,
    )
    ports = validate_ports(data.get("ports"))
    return target, ports
