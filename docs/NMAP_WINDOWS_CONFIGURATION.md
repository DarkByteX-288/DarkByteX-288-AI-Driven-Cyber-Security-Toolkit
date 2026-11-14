# Nmap Windows Configuration

## Verified environment

Verified on 2026-11-14 using Windows 11 Pro x64, build 26200. Nmap **7.993** is installed and executable. Its directory was present in the current user's PATH, although the long-lived agent PowerShell process did not inherit that updated PATH. The discovered full executable path is configured in the Windows user's `NMAP_PATH`; the machine-specific value is intentionally not committed to this public repository.

The application environment is Python **3.11.7** at `.phase1-nmap-venv\Scripts\python.exe`, with `python-nmap==0.7.1`. The other existing virtual environments were left untouched. All 46 directly pinned packages across runtime, lock, and development requirements were present at matching versions; `pip check` reported no broken requirements.

The Npcap service is running. Nmap reports that this build was compiled with Npcap 1.90 support, but the installed driver version was not independently identified. Npcap is not required for BastionIX's TCP Connect profile (`-sT`); the scanner does not silently switch to raw-packet scanning.

## Detect and configure the executable

Do not assume a fixed installation directory. Inspect the active account and its environment:

```powershell
Get-Command nmap -ErrorAction SilentlyContinue
where.exe nmap
$env:NMAP_PATH
[Environment]::GetEnvironmentVariable("NMAP_PATH", "User")
```

If `nmap` is on PATH, configure the current process and persist the detected path for the current Windows user:

```powershell
$nmap = (Get-Command nmap.exe -ErrorAction Stop).Source
$env:NMAP_PATH = $nmap
[Environment]::SetEnvironmentVariable("NMAP_PATH", $nmap, "User")
& $env:NMAP_PATH --version
```

If PATH lookup fails, inspect the Nmap install directory identified by the administrator or package installer, verify that the candidate `nmap.exe` exists, and set `NMAP_PATH` to that exact path. Reopen the terminal or set the variable in the Flask service account's environment. Do not write a machine-specific path into application source or the committed `.env.example`.

The Flask configuration reads `NMAP_PATH` from the process environment. An explicit path takes precedence; otherwise, BastionIX checks PATH and supported Windows install locations. The executable is validated and probed with a bounded `--version` invocation. Authenticated `GET /api/scans/health` reports Nmap and Python-integration readiness without disclosing the local path. Scan execution uses a fixed TCP Connect profile, argument lists, `shell=False`, bounded ports/hosts, and timeouts.

## Localhost acceptance run

The live workflow used an isolated in-memory test database, a temporary test account, and a test-only loopback approval for `127.0.0.1/32`. No loopback exception was enabled globally. The scan was explicitly authorized and limited to TCP ports 22, 80, and 443.

Nmap 7.993 reported the host up and all three ports closed (`conn-refused`). BastionIX parsed and persisted the host and the three closed port states; the scan completed at 100%, with authorization, start, and completion audit events. No open service or CVE finding was fabricated. The authenticated API returned the scan in history, and CSV/PDF exports were generated from those real results. No external target was scanned.

The Nmap health API returned `operational` with `python-nmap` 0.7.1. The actual executable path was not returned by the API. NVD live enrichment was not invoked because the scan found no open, versioned service; NVD behavior is covered by automated tests. Real process cancellation was not needed for this sub-second localhost scan; cancellation and ownership behavior are covered by regression tests.

## Verification commands

Run commands from the project directory using the intended environment:

```powershell
..\.phase1-nmap-venv\Scripts\python.exe --version
..\.phase1-nmap-venv\Scripts\python.exe -m pip show python-nmap
..\.phase1-nmap-venv\Scripts\python.exe -c "import nmap; print('Python Nmap integration: OK')"
& $env:NMAP_PATH --version
..\.phase1-nmap-venv\Scripts\python.exe -m pytest -q
```

The final suite passed **104 tests**. Compilation, dependency consistency and audits, and disposable migration upgrade/downgrade/re-upgrade checks passed. Automated scanner tests use mocked Nmap/NVD data; the separate localhost acceptance run above used the real executable. Interactive browser/mobile testing was not performed.
