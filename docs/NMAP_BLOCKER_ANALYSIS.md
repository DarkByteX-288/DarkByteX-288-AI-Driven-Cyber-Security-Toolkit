# Nmap Blocker Analysis

## Initial environment inspection

Inspection was performed before changing the scanner or installing Nmap.

| Item | Observed state |
|---|---|
| Operating system | Windows 11 Pro, version 10.0.26200, 64-bit |
| Project Python | Python 3.11.7; test/runtime venv is `.phase1-nmap-venv` |
| `NMAP_PATH` | Unset |
| `nmap` in PATH | Not found |
| Common Windows install paths | `C:\Program Files\Nmap\nmap.exe`, `C:\Program Files (x86)\Nmap\nmap.exe`, and `C:\Nmap\nmap.exe` absent |
| Npcap | No service, registry key, or common installation directory found; not required for TCP connect scanning |
| Python Nmap integration | `python-nmap` 0.7.1 imports in `.phase1-nmap-venv`; absent from `.venv` |
| `py`, `python`, `winget` on PATH | Not available |
| Administrator permissions | Current account is not an administrator |
| Local Git checkout | None at the workspace root or project directory; publication uses a clean clone |
| Remote repository branch | GitHub `main`, observed head `e54d8ea15062b12aa83d5422812ff0ad02de5ef1` before this security update |

## Root cause

At the initial verification, the existing virtual environments lacked `python-nmap`, the Nmap operating-system executable was not discoverable from the current shell, and the application only searched `PATH` with `shutil.which("nmap")`; it had no `NMAP_PATH` override, version probe, or health endpoint. The adapter, override, discovery, version probe, and health endpoint have since been implemented. A later Windows inspection found Nmap installed in a directory present in the user's PATH, which the current shell had not inherited.

There was a second independent blocker for the requested test: loopback targets were initially rejected regardless of explicit authorization and approved CIDRs. The implementation now has a default-off loopback opt-in requiring both authorization and an approved loopback CIDR; normal scanner defaults continue to reject loopback.

The official Nmap installation guide documents the Windows self-installer. Windows loopback/raw packet support normally uses Npcap; the official guide documents `-sT -Pn` as a TCP-connect alternative when Npcap is not installed. No Npcap driver or Windows registry performance changes will be installed without an explicit need and transparent reporting.

## Implementation changes

- The scan subprocess is invoked with an argument list and `shell=False`; it accepts only resolved IP literals and fixed scanner options.
- Authorization, target range checks, DNS pinning/revalidation, scan limits, cancellation, audit records, ownership checks, result persistence, and report routes are present.
- `NMAP_PATH` now overrides auto-discovery; fallback discovery checks PATH and common Windows install locations. A bounded `--version` probe and Python integration check report `not_installed`, `inaccessible`, `execution_failed`, or `operational`.
- Authenticated `GET /api/scans/health` reports executable and integration state without returning the local executable path. User-facing scan errors do not include local paths or stack traces.
- Loopback remains disallowed by default and requires both an explicit approved CIDR and `BASTIONIX_SCANNER_ALLOW_LOOPBACK=true`. Only loopback receives `-Pn`; all scans use explicit TCP connect mode `-sT`.
- CVE matching uses the NVD 2.0 API, a process-local bounded cache, five-second request timeouts, CVSS version/score persistence, version-appropriate severity classification, and potential-only matching. Automated tests mock NVD; live enrichment is not necessary for a loopback host with no identified service.
- An unset `FLASK_ENV` now selects production, which requires an environment-provided key at least 32 characters long. Known development/test keys and `FLASK_DEBUG` overrides are rejected in production. Development uses an ephemeral random key. `.env.example` replaces the tracked local Flask environment file.

## Resolution and verification record

During the initial blocker investigation, the official Windows installer was downloaded and verified: Authenticode **Valid**, publisher **Nmap Software LLC**, SHA-256 `22E5928D1738A1B94FFD3643014F52CB87D467DBEC4CFF9E5F721FE0B3782F1B`. It was not executed during that investigation. Later inspection found an already-installed executable and did not require an installer, elevation, or system configuration changes.

The dedicated Python 3.11.7 environment contains `python-nmap` 0.7.1 and the pinned project dependencies. The initial Nmap absence report above is historical; a later inspection found Nmap on the current Windows user's PATH.

## Resolution and live acceptance (2026-11-14)

- Nmap was found through the Windows user's PATH; `nmap --version` returned **7.993** (32-bit Windows binary on Windows 11 Pro x64). The executable is installed and runs successfully.
- The current agent shell had an older inherited PATH, so `NMAP_PATH` was explicitly set to the discovered executable at the Windows user environment scope and in the test process. No PATH, registry, driver, or security setting was changed. The machine-specific executable path is intentionally omitted from the public report.
- The Npcap service is running; Nmap reports build support for Npcap 1.90, but the installed driver version was not independently identified. Npcap was not required by the TCP-connect scan profile (`-sT`).
- The application Python environment imports `python-nmap` 0.7.1. Authenticated `GET /api/scans/health` returned HTTP 200 with Nmap 7.993 and integration 0.7.1, without disclosing the executable path.
- An authenticated Flask HTTP workflow ran a real scan of only `127.0.0.1`, limited to TCP ports 22, 80, and 443 with the safe connect profile. Nmap reported the host up and all three ports closed (`conn-refused`); no open service or CVE finding was invented.
- The application parsed and persisted all three closed port states, completed at 100%, wrote authorization/start/completion audit events, and returned the scan in history. CSV and PDF exports returned valid files and included the scan observations.
- Existing scanner tests now retain closed/filtered port observations while creating vulnerability findings only for open ports. Hostname DNS answer counts are capped at `max_hosts`; the worker revalidates the same cap before execution.
- Full suite: **104 passed**. Compilation, pip consistency, dependency audits, and disposable migration upgrade/downgrade/re-upgrade passed. Original application database was not used for the live test or migration test.

No live NVD request was made because the authorized localhost scan found no open, versioned service requiring enrichment. NVD parsing, caching, rate-limit, and offline behavior remain covered by automated tests.

## Repository publication limitation

The source project workspace contains no `.git` directory. A clean clone of the verified repository URL is used for publication. The source project directory itself remains a non-Git workspace.
