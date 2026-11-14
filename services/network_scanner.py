"""Safe-profile Nmap orchestration and scan-result normalization."""

import logging
import ipaddress
import os
import re
import shutil
import subprocess
import time
from importlib.metadata import PackageNotFoundError, version

try:
    import nmap
except ImportError:  # Keep the Flask app available so health reports the missing adapter.
    nmap = None

from services.nvd_service import lookup_cves

logger = logging.getLogger("bastionix.network_scanner")
SCAN_TIMEOUT_SECONDS = 180
NMAP_ARGUMENTS = "-n -sT -sV --version-light -T3 --max-retries 1 --host-timeout 60s"
MAX_NVD_LOOKUPS_PER_SCAN = 10
INTELLIGENCE_TIMEOUT_SECONDS = 60
NMAP_VERSION_TIMEOUT_SECONDS = 5
_NMAP_VERSION = re.compile(r"^Nmap version ([\w.+-]+)")
NMAP_INSTALL_MESSAGE = (
    "Nmap executable was not found. Install Nmap from https://nmap.org/download.html "
    "and ensure it is available on PATH or set the NMAP_PATH environment variable."
)


class ScanCancelled(Exception):
    """Raised when a user cancels a running scan."""


class ScannerUnavailable(RuntimeError):
    """Raised when the Nmap executable or Python integration is unavailable."""


def _python_integration():
    if nmap is None:
        return {"status": "not_installed", "version": None}
    try:
        integration_version = version("python-nmap")
    except PackageNotFoundError:
        integration_version = "unknown"
    return {"status": "ready", "version": integration_version}


def _windows_install_candidates():
    if os.name != "nt":
        return []
    roots = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")]
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        roots.append(os.path.join(local_app_data, "Programs"))
    roots.append(r"C:\Nmap")
    return [
        os.path.join(root, "Nmap", "nmap.exe") if root != r"C:\Nmap"
        else os.path.join(root, "nmap.exe")
        for root in roots if root
    ]


def _locate_nmap(nmap_path=None):
    configured_path = nmap_path if nmap_path is not None else os.environ.get("NMAP_PATH")
    if configured_path:
        candidate = shutil.which(configured_path)
        if candidate is None:
            candidate = os.path.expandvars(os.path.expanduser(configured_path))
            candidate = os.path.abspath(candidate)
        if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
            return None, "inaccessible"
        return candidate, None

    candidates = [shutil.which("nmap"), shutil.which("nmap.exe")]
    candidates.extend(_windows_install_candidates())
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate), None
    return None, "not_installed"


def _inspect_nmap(nmap_path=None):
    integration = _python_integration()
    executable, location_error = _locate_nmap(nmap_path)
    if executable is None:
        nmap_status = location_error or "not_installed"
        return {
            "status": "unavailable",
            "nmap": {"status": nmap_status, "version": None},
            "python_integration": integration,
            "executable": None,
        }

    try:
        result = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=NMAP_VERSION_TIMEOUT_SECONDS,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {
            "status": "unavailable",
            "nmap": {"status": "execution_failed", "version": None},
            "python_integration": integration,
            "executable": executable,
        }

    version_match = None
    for line in result.stdout.splitlines():
        version_match = _NMAP_VERSION.match(line)
        if version_match:
            break
    if result.returncode != 0 or version_match is None:
        return {
            "status": "unavailable",
            "nmap": {"status": "execution_failed", "version": None},
            "python_integration": integration,
            "executable": executable,
        }
    nmap_version = version_match.group(1)

    if nmap is None:
        integration = {"status": "not_installed", "version": None}
    else:
        try:
            nmap.PortScanner(nmap_search_path=(executable,))
        except Exception as exc:
            logger.warning(
                "Python Nmap integration probe failed (%s).",
                type(exc).__name__,
            )
            integration = {"status": "execution_failed", "version": integration["version"]}

    ready = integration["status"] == "ready"
    return {
        "status": "operational" if ready else "unavailable",
        "nmap": {"status": "ready", "version": nmap_version},
        "python_integration": integration,
        "executable": executable,
    }


def nmap_status(nmap_path=None):
    """Return user-safe health details without disclosing local executable paths."""
    details = _inspect_nmap(nmap_path)
    return {
        "status": details["status"],
        "nmap": details["nmap"],
        "python_integration": details["python_integration"],
    }


def require_nmap(nmap_path=None):
    details = _inspect_nmap(nmap_path)
    if details["status"] != "operational":
        nmap_state = details["nmap"]["status"]
        adapter_state = details["python_integration"]["status"]
        if nmap_state == "not_installed":
            message = NMAP_INSTALL_MESSAGE
        elif nmap_state == "inaccessible":
            message = "The configured Nmap executable is inaccessible. Check NMAP_PATH and file permissions."
        elif nmap_state == "execution_failed":
            message = "Nmap was found but could not be executed or did not return a valid version."
        elif adapter_state == "not_installed":
            message = "The Nmap executable is ready, but the python-nmap integration is not installed."
        else:
            message = "Nmap is installed, but the Python integration could not invoke it successfully."
        raise ScannerUnavailable(message)
    return details["executable"]


def run_nmap_scan(addresses, ports, progress_callback, cancel_event, nmap_path=None):
    """Run only fixed safe-profile arguments against pre-resolved IP addresses."""
    if cancel_event.is_set():
        raise ScanCancelled()
    if not addresses:
        raise ValueError("At least one validated IP address is required.")
    if not ports or any(
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
        for port in ports
    ):
        raise ValueError("Nmap requires validated TCP port numbers.")
    parsed_addresses = []
    try:
        parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
    except ValueError as exc:
        raise ValueError("Nmap targets must be validated IP addresses.") from exc
    loopback_targets = all(address.is_loopback for address in parsed_addresses)
    executable = require_nmap() if nmap_path is None else require_nmap(nmap_path)
    parser = nmap.PortScanner(nmap_search_path=(executable,))
    command = [
        executable,
        "-oX", "-",
        "-p", ",".join(str(port) for port in ports),
        *NMAP_ARGUMENTS.split(),
        *(["-Pn"] if loopback_targets else []),
        *addresses,
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    started = time.monotonic()
    while True:
        if cancel_event.is_set():
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            raise ScanCancelled()
        elapsed = time.monotonic() - started
        if elapsed >= SCAN_TIMEOUT_SECONDS:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            raise TimeoutError("Network scan exceeded its configured timeout.")
        try:
            stdout, stderr = process.communicate(timeout=1)
            break
        except subprocess.TimeoutExpired:
            progress_callback(int(elapsed), SCAN_TIMEOUT_SECONDS)
    if cancel_event.is_set():
        raise ScanCancelled()
    if process.returncode:
        logger.warning("Nmap exited with status %s.", process.returncode)
        raise RuntimeError(f"Nmap returned an error (exit code {process.returncode}).")
    try:
        result = parser.analyse_nmap_xml_scan(stdout)
    except nmap.PortScannerError as exc:
        raise RuntimeError("Nmap returned invalid XML scan output.") from exc
    for completed in range(1, len(addresses) + 1):
        progress_callback(completed, len(addresses))
    return result


def normalize_results(records, progress_callback, cancel_event):
    """Extract host/service data and attach potential NVD matches."""
    normalized = []
    all_services = []
    scan_records = records.get("scan", records)
    for address, host_data in scan_records.items():
        hostnames = [
            item.get("name") for item in host_data.get("hostnames", [])
            if item.get("name")
        ]
        host = {
            "address": address,
            "hostname": hostnames[0] if hostnames else None,
            "state": host_data.get("status", {}).get("state", "unknown"),
            "ports": [],
        }
        for port, details in (host_data.get("tcp", {}) or {}).items():
            if details.get("state") != "open":
                continue
            service = {
                "port": int(port),
                "protocol": "tcp",
                "state": details.get("state", "open"),
                "reason": details.get("reason"),
                "name": details.get("name"),
                "product": details.get("product"),
                "version": details.get("version"),
                "confidence": details.get("conf"),
                "extra_info": details.get("extrainfo"),
                "cpe": (details.get("cpe") or [None])[0] if isinstance(details.get("cpe"), list) else details.get("cpe"),
                "vulnerabilities": [],
                "vulnerability_intelligence_status": "not_applicable",
            }
            host["ports"].append(service)
            all_services.append((host, service))
        normalized.append(host)

    total = max(1, len(all_services))
    lookup_count = 0
    deadline = time.monotonic() + INTELLIGENCE_TIMEOUT_SECONDS
    lookups = {}
    rate_limited = False
    for index, (host, service) in enumerate(all_services, start=1):
        if cancel_event.is_set():
            raise ScanCancelled()
        if service["product"] and service["version"]:
            key = (service["product"], service["version"])
            if key not in lookups:
                if lookup_count >= MAX_NVD_LOOKUPS_PER_SCAN or time.monotonic() >= deadline:
                    lookups[key] = {"status": "lookup_limit_reached", "findings": []}
                elif rate_limited:
                    lookups[key] = {"status": "rate_limited", "findings": []}
                else:
                    lookup_count += 1
                    lookups[key] = lookup_cves(*key)
                    rate_limited = lookups[key].get("status") == "rate_limited"
            lookup = lookups[key]
            service["vulnerability_intelligence_status"] = lookup.get("status", "unavailable")
            for match in lookup.get("findings", []):
                service["vulnerabilities"].append({
                    **match,
                    "classification": "potential",
                    "source": "NVD keyword match",
                    "remediation": (
                        "Validate applicability against the vendor advisory and exact product build; "
                        "upgrade to a vendor-supported release containing the fix when applicable."
                    ),
                    "port": service["port"],
                    "host": host["address"],
                })
        progress_callback(index, total)
    return normalized
