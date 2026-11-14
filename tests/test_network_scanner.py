import threading
import subprocess

import pytest

from services import network_scanner
from services.network_scanner import ScanCancelled, ScannerUnavailable


def test_nmap_executable_absence_is_reported(monkeypatch):
    monkeypatch.setattr(
        network_scanner, "_locate_nmap", lambda _path=None: (None, "not_installed")
    )
    with pytest.raises(ScannerUnavailable, match="Nmap executable"):
        network_scanner.require_nmap()


def test_invalid_explicit_path_is_reported_without_leaking_it():
    status = network_scanner.nmap_status(r"C:\missing-private-path\nmap.exe")
    assert status["status"] == "unavailable"
    assert status["nmap"]["status"] == "inaccessible"
    assert "missing-private-path" not in repr(status)


def test_nmap_status_probes_version_and_hides_executable_path(monkeypatch):
    executable = r"C:\Program Files\Nmap\nmap.exe"

    class Integration:
        @staticmethod
        def PortScanner(nmap_search_path):
            assert nmap_search_path == (executable,)

    monkeypatch.setattr(network_scanner, "_locate_nmap", lambda _path=None: (executable, None))
    monkeypatch.setattr(network_scanner, "_python_integration", lambda: {
        "status": "ready", "version": "0.7.1"
    })
    monkeypatch.setattr(network_scanner, "nmap", Integration)
    monkeypatch.setattr(
        network_scanner.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout="Nmap version 7.99 ( https://nmap.org )", stderr=""
        ),
    )
    status = network_scanner.nmap_status()
    assert status == {
        "status": "operational",
        "nmap": {"status": "ready", "version": "7.99"},
        "python_integration": {"status": "ready", "version": "0.7.1"},
    }


def test_nmap_execution_failure_is_distinguished(monkeypatch):
    monkeypatch.setattr(network_scanner, "_locate_nmap", lambda _path=None: ("nmap.exe", None))
    monkeypatch.setattr(
        network_scanner, "nmap", type("Integration", (), {"PortScanner": lambda **_: None})
    )
    monkeypatch.setattr(
        network_scanner, "_python_integration",
        lambda: {"status": "ready", "version": "0.7.1"},
    )

    def fail(*_args, **_kwargs):
        raise OSError("private executable path")

    monkeypatch.setattr(network_scanner.subprocess, "run", fail)
    status = network_scanner.nmap_status()
    assert status["nmap"]["status"] == "execution_failed"
    assert "private executable path" not in repr(status)


def test_missing_python_adapter_is_distinguished_from_nmap(monkeypatch):
    executable = r"C:\Nmap\nmap.exe"
    monkeypatch.setattr(network_scanner, "_locate_nmap", lambda _path=None: (executable, None))
    monkeypatch.setattr(network_scanner, "nmap", None)
    monkeypatch.setattr(network_scanner, "_python_integration", lambda: {
        "status": "not_installed", "version": None
    })
    monkeypatch.setattr(
        network_scanner.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout="Nmap version 7.99", stderr=""
        ),
    )
    status = network_scanner.nmap_status()
    assert status["nmap"] == {"status": "ready", "version": "7.99"}
    assert status["python_integration"]["status"] == "not_installed"
    assert status["status"] == "unavailable"


def test_scan_uses_fixed_arguments_and_parses_python_nmap_xml(monkeypatch):
    captured = {}
    xml = "<nmaprun></nmaprun>"

    class Process:
        returncode = 0

        def __init__(self, command, **kwargs):
            captured["command"] = command
            captured["kwargs"] = kwargs

        def communicate(self, timeout=None):
            return xml, ""

    class Parser:
        def __init__(self, nmap_search_path):
            captured["parser_path"] = nmap_search_path

        def analyse_nmap_xml_scan(self, output):
            assert output == xml
            return {"scan": {}}

    monkeypatch.setattr(network_scanner, "require_nmap", lambda: "C:\\Nmap\\nmap.exe")
    monkeypatch.setattr(network_scanner.nmap, "PortScanner", Parser)
    monkeypatch.setattr(network_scanner.subprocess, "Popen", Process)
    progress = []
    result = network_scanner.run_nmap_scan(
        ["192.168.10.2"], [22, 443], lambda done, total: progress.append((done, total)),
        threading.Event(),
    )
    command = captured["command"]
    assert command[0] == "C:\\Nmap\\nmap.exe"
    assert command[-1] == "192.168.10.2"
    assert "shell" in captured["kwargs"] and captured["kwargs"]["shell"] is False
    assert "-sT" in command
    assert "-sV" in command
    assert result == {"scan": {}}
    assert progress[-1] == (1, 1)


def test_loopback_scan_uses_a_bounded_connect_scan(monkeypatch):
    captured = {}

    class Process:
        returncode = 0

        def __init__(self, command, **kwargs):
            captured["command"] = command

        def communicate(self, timeout=None):
            return "<nmaprun></nmaprun>", ""

    class Parser:
        def __init__(self, nmap_search_path):
            pass

        def analyse_nmap_xml_scan(self, output):
            return {"scan": {}}

    monkeypatch.setattr(network_scanner, "require_nmap", lambda: "nmap.exe")
    monkeypatch.setattr(network_scanner.nmap, "PortScanner", Parser)
    monkeypatch.setattr(network_scanner.subprocess, "Popen", Process)
    network_scanner.run_nmap_scan(
        ["127.0.0.1"], [1], lambda *_: None, threading.Event()
    )
    assert "-sT" in captured["command"]
    assert "-Pn" in captured["command"]
    assert captured["command"][-1] == "127.0.0.1"


def test_invalid_unvalidated_address_never_invokes_nmap(monkeypatch):
    monkeypatch.setattr(
        network_scanner, "require_nmap",
        lambda: pytest.fail("Nmap must not run for an invalid target"),
    )
    with pytest.raises(ValueError, match="validated IP"):
        network_scanner.run_nmap_scan(
            ["-oX"], [80], lambda *_: None, threading.Event()
        )


def test_nmap_timeout_terminates_process(monkeypatch):
    class Process:
        returncode = None

        def __init__(self, *args, **kwargs):
            self.terminated = False

        def terminate(self):
            self.terminated = True

        def communicate(self, timeout=None):
            if self.terminated:
                return "", ""
            raise subprocess.TimeoutExpired("nmap", timeout)

    process = Process()
    monkeypatch.setattr(network_scanner, "SCAN_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(network_scanner, "require_nmap", lambda: "nmap.exe")
    monkeypatch.setattr(network_scanner.nmap, "PortScanner", lambda **kwargs: object())
    monkeypatch.setattr(network_scanner.subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(TimeoutError, match="configured timeout"):
        network_scanner.run_nmap_scan(
            ["192.168.10.2"], [80], lambda *_: None, threading.Event()
        )
    assert process.terminated


def test_nmap_nonzero_exit_returns_safe_error(monkeypatch):
    class Process:
        returncode = 2

        def __init__(self, *args, **kwargs):
            pass

        def communicate(self, timeout=None):
            return "", "secret path in stderr"

    monkeypatch.setattr(network_scanner, "require_nmap", lambda: "nmap.exe")
    monkeypatch.setattr(network_scanner.nmap, "PortScanner", lambda **kwargs: object())
    monkeypatch.setattr(network_scanner.subprocess, "Popen", Process)
    with pytest.raises(RuntimeError, match="exit code 2") as error:
        network_scanner.run_nmap_scan(
            ["192.168.10.2"], [80], lambda *_: None, threading.Event()
        )
    assert "secret path" not in str(error.value)


def test_scan_cancellation_terminates_process(monkeypatch):
    event = threading.Event()

    class Process:
        returncode = None

        def __init__(self, *args, **kwargs):
            self.terminated = False

        def terminate(self):
            self.terminated = True

        def communicate(self, timeout=None):
            if not self.terminated:
                event.set()
                raise network_scanner.subprocess.TimeoutExpired("nmap", timeout)
            return "", ""

    process = Process("nmap")
    monkeypatch.setattr(network_scanner, "require_nmap", lambda: "nmap.exe")
    monkeypatch.setattr(network_scanner.nmap, "PortScanner", lambda **kwargs: object())
    monkeypatch.setattr(network_scanner.subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(ScanCancelled):
        network_scanner.run_nmap_scan(
            ["192.168.10.2"], [22], lambda *_: None, event
        )
    assert process.terminated


def test_normalization_accepts_a_host_with_no_open_ports():
    result = network_scanner.normalize_results(
        {"scan": {
            "127.0.0.1": {
                "status": {"state": "up"},
                "tcp": {1: {"state": "closed"}},
            }
        }},
        lambda *_: None,
        threading.Event(),
    )
    assert result == [{
        "address": "127.0.0.1",
        "hostname": None,
        "state": "up",
        "ports": [],
    }]


def test_normalized_service_records_include_only_open_ports(monkeypatch):
    monkeypatch.setattr(
        network_scanner,
        "lookup_cves",
        lambda product, version: {
            "status": "available",
            "findings": [{"cve_id": "CVE-2099-1234", "references": []}],
        },
    )
    result = network_scanner.normalize_results(
        {
            "scan": {
                "192.168.10.2": {
                    "status": {"state": "up"},
                    "hostnames": [{"name": "asset.example.test"}],
                    "tcp": {
                        443: {
                            "state": "open",
                            "name": "https",
                            "product": "Example Server",
                            "version": "1.2",
                            "cpe": [],
                        },
                        80: {"state": "closed"},
                    },
                }
            }
        },
        lambda *_: None,
        threading.Event(),
    )
    assert len(result[0]["ports"]) == 1
    assert result[0]["ports"][0]["vulnerabilities"][0]["classification"] == "potential"
