# Nmap Blocker Analysis

## Initial environment inspection

Inspection was performed before changing the scanner or installing Nmap.

| Item | Observed state |
|---|---|
| Operating system | Windows 11 Pro, 64-bit |
| Project Python | Python 3.11.7 in the existing `.venv` and `venv` directories |
| `NMAP_PATH` | Unset |
| `nmap` in PATH | Not found |
| Common Windows install paths | `C:\Program Files\Nmap\nmap.exe`, `C:\Program Files (x86)\Nmap\nmap.exe`, and `C:\Nmap\nmap.exe` absent |
| Python Nmap integration in existing environments | `import nmap` fails with `ModuleNotFoundError` |
| `py`, `python`, `winget` on PATH | Not available |
| Local Git checkout | None at the workspace root or project directory |
| Remote repository branch | GitHub `main`, observed head `52e5c6ec687fd142836e225ab9bb3d060bcaa2e6` |

## Root cause

The earlier verification established that the Python dependency declaration and mocked tests existed, but did not establish that the current application environment contained the Python integration module or an Nmap operating-system executable. The active project virtual environments have neither `python-nmap` installed nor an Nmap executable available to the process. The application also only searched `PATH` with `shutil.which("nmap")`; it had no `NMAP_PATH` override, version probe, or health endpoint.

There was a second independent blocker for the requested test: loopback targets were unconditionally rejected by target validation, regardless of explicit authorization and approved CIDRs. A test-only, opt-in loopback scope is required; normal scanner defaults must continue to reject loopback.

The official Nmap installation guide documents the Windows self-installer. Windows loopback/raw packet support normally uses Npcap; the official guide documents `-sT -Pn` as a TCP-connect alternative when Npcap is not installed. No Npcap driver or Windows registry performance changes will be installed without an explicit need and transparent reporting.

## Implementation changes

- The scan subprocess is invoked with an argument list and `shell=False`; it accepts only resolved IP literals and fixed scanner options.
- Authorization, target range checks, DNS pinning/revalidation, scan limits, cancellation, audit records, ownership checks, result persistence, and report routes are present.
- `NMAP_PATH` now overrides auto-discovery; fallback discovery checks PATH and common Windows install locations. A bounded `--version` probe and Python integration check report `not_installed`, `inaccessible`, `execution_failed`, or `operational`.
- Authenticated `GET /api/scans/health` reports executable and integration state without returning the local executable path. User-facing scan errors do not include local paths or stack traces.
- Loopback remains disallowed by default and requires both an explicit approved CIDR and `BASTIONIX_SCANNER_ALLOW_LOOPBACK=true`. Only loopback receives `-Pn`; all scans use explicit TCP connect mode `-sT`.
- CVE matching uses the NVD 2.0 API, a process-local bounded cache, five-second request timeouts, CVSS version/score persistence, version-appropriate severity classification, and potential-only matching. Automated tests mock NVD; live enrichment is not necessary for a loopback host with no identified service.

## Resolution and verification record

The signed official Windows installer was downloaded from `https://nmap.org/dist/nmap-7.993-setup.exe`. Authenticode verification returned **Valid**, publisher **Nmap Software LLC**, and SHA-256 `22E5928D1738A1B94FFD3643014F52CB87D467DBEC4CFF9E5F721FE0B3782F1B`, matching the digest published by Nmap. The installer was not executed: the current account `DBX\adibs` is not an administrator, and completing a system installation/Npcap driver setup would require elevation. No system PATH, registry, or driver settings were changed.

A fresh Python 3.11.7 environment was created from `requirements-lock.txt` and `requirements-dev.txt`; `python-nmap` 0.7.1 is installed and importable there. Actual Nmap preflight reports `nmap.status=not_installed` and `python_integration.status=ready`. The configured PATH and common Program Files locations remain without Nmap. The authenticated Flask preflight returned HTTP 503 for health and scan start, HTTP 200 for the scanner page and empty history, and persisted no scan record. This was a safe failure-path test, **not** a real scan.

The actual scanner executable path, Nmap version, Python-to-executable invocation, loopback scan output, persisted live results, live history, and live reports remain **NOT VERIFIED** because Nmap could not be installed under the current account.

The expanded test suite passed **97 tests**; compile, dependency consistency, dependency audits, and migration upgrade/downgrade/re-upgrade checks passed. These checks cover mocked scanner execution and do not substitute for the missing real Nmap scan.

### Manual installation needed

1. From an administrator account, run the signed installer linked above and install Nmap. For this application's TCP connect profile, Npcap and registry performance changes are not required; do not install them unless separately approved.
2. Set `NMAP_PATH` to the installed `nmap.exe` (commonly `C:\Program Files (x86)\Nmap\nmap.exe`) or add it to the Flask service account's PATH. Confirm `& $env:NMAP_PATH --version` and authenticated `GET /api/scans/health` report the version and `operational`.
3. In a disposable test database only, set `BASTIONIX_APPROVED_NETWORKS=127.0.0.1/32` and `BASTIONIX_SCANNER_ALLOW_LOOPBACK=true`, then start Flask and submit an explicitly authorized scan for `127.0.0.1` with a small TCP port list. Remove the loopback settings afterward.

## Repository publication limitation

The source project workspace contains no `.git` directory. A clean clone of the verified repository URL was used for publication; commit `2e8fc3b0e5163e77ebc5d0446b5121c8e670b92a` is pushed to `main`. The source project directory itself remains a non-Git workspace.
