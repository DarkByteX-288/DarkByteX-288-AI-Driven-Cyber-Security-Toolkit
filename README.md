# BastionIX

**AI-Powered Cybersecurity & Network Intelligence Platform**

**Intelligent Security. Continuous Visibility. Stronger Defense.**

BastionIX builds on the existing Flask application to provide password-strength analysis, phishing URL analysis, defensive network assessment, owner-scoped history, analytics, and reports. The network scanner is restricted to configured approved asset ranges (private ranges by default), requires an explicit authorization confirmation, and does not perform exploitation, credential attacks, stealth, or denial-of-service testing.

## Features

- Authentication, per-user settings, CSRF-protected forms, and owner-scoped data.
- Password strength analysis, transparent heuristic scoring, ML inference, simulated attack estimates, and recommendations; the raw password is not persisted.
- Phishing URL analysis with local structural checks and optional bounded TLS/redirect and configured threat-intelligence checks.
- Dashboard analytics, analysis history, CSV/PDF reports, and ML model management.
- Authorized network discovery, bounded TCP port/service identification, potential NVD CVE matches with CVSS severity, progress/cancellation, audit history, and scan reports.
- Existing AI artifacts are trained on synthetic data. Their results are not a substitute for real-world validation.

## Technology and supported Python

The verified runtime is Python 3.11.7. Dependencies are directly pinned in `requirements.txt`; the complete tested environment is captured by `requirements-lock.txt`. Development/testing tools and dependency auditing are in `requirements-dev.txt`.

The backend uses Flask, Flask-SQLAlchemy, Flask-Migrate, Flask-Login, Flask-WTF, Flask-Limiter, SQLAlchemy, scikit-learn, pandas, NumPy, Joblib, ReportLab, and `python-nmap`. `python-nmap` is a Python integration package, not the Nmap executable.

## Installation

Create and activate a virtual environment, then install pinned packages:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-lock.txt
Copy-Item .env.example .env
```

On Unix-like shells, activate with `source .venv/bin/activate`.

### Install Nmap separately

Nmap is an operating-system executable; installing `python-nmap` alone is not enough.

- **Windows:** Download the signed self-installer from [nmap.org/download.html](https://nmap.org/download.html), verify its Nmap Software LLC signature, and install it. Npcap and Windows network-driver changes are optional for BastionIX's TCP connect scans; do not install them unless raw-packet scans are separately required. Set `NMAP_PATH` to the installed `nmap.exe` when it is not on PATH.
- **Debian/Ubuntu:** `sudo apt install nmap`.
- **Fedora/RHEL-family:** `sudo dnf install nmap` (or use the distribution's supported package manager).
- **macOS:** Download the official `.dmg` from [nmap.org/download.html](https://nmap.org/download.html) and run its installer; alternatively install the distribution package through a trusted package manager.

Verify installation with `nmap --version` and the authenticated `GET /api/scans/health` endpoint. BastionIX also discovers common Windows install locations and supports an explicit `NMAP_PATH` path without changing system PATH.

Loopback is rejected by default. For a disposable local-only verification environment, explicitly set both `BASTIONIX_APPROVED_NETWORKS=127.0.0.1/32` and `BASTIONIX_SCANNER_ALLOW_LOOPBACK=true`; do not enable this on a general deployment. Loopback smoke scans use TCP connect mode and skip host discovery only for the explicitly allowed loopback target.

### Configure and migrate the database

Copy `.env.example` to `.env` for local development. The example uses `FLASK_ENV=development`; the app generates an ephemeral, unpredictable development key if `SECRET_KEY` is blank. The app defaults to production when no environment is selected. Production startup requires `FLASK_ENV=production` and an environment-provided random `SECRET_KEY` of at least 32 characters; there is no production fallback.

Generate a production key and set production configuration in PowerShell:

```powershell
$env:FLASK_ENV = "production"
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

Keep the key in the deployment's secret manager, not in source control. Use `flask run` only for local development; production must use a production WSGI server with debug disabled. The scanner defaults to RFC1918 IPv4 and IPv6 unique-local ranges only. To narrow or extend asset scope, set `BASTIONIX_APPROVED_NETWORKS` to a comma-separated list of strict CIDRs that the deployment owner is authorized to assess. Public ranges are never included by default. Scanner limits can be adjusted with `BASTIONIX_SCANNER_MAX_HOSTS`, `BASTIONIX_SCANNER_MAX_ACTIVE`, and `BASTIONIX_SCANNER_WORKERS`; host count is capped at 256.

Apply migrations before starting the app:

```powershell
python -m flask db upgrade
```

For local development only:

```powershell
$env:FLASK_ENV = "development"
python -m flask run
```

The checked-in existing SQLite database is upgraded additively; migrations preserve existing accounts and analysis records. Back up the database before applying migrations. Do not copy production data into a test database.

## Run tests and audit dependencies

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
pip-audit -r requirements.txt
pip-audit -r requirements-lock.txt
```

Automated scanner tests use mocked Nmap/NVD data and do not initiate network scans. Run the tests on Python versions that the project claims to support before deploying.

## Network scanner operation

Scans require authentication and a JSON request with `authorization_confirmed: true`. Targets must be a single IP, CIDR, or DNS hostname that resolves entirely inside configured approved ranges. DNS results are validated and pinned to resolved IP addresses before Nmap is run. The only supported profile uses bounded Nmap host discovery and light TCP service/version detection; raw Nmap arguments are never accepted.

NVD matches are marked **potential**. A product/version keyword match does not establish that a specific build is affected or exploitable. Open-port records are informational. The scanner does not execute vulnerability scripts, exploit code, credential checks, stealth options, or denial-of-service tests. CVE checks are best effort and scans continue when NVD is unavailable or rate-limited.

See [Network Scanner](docs/NETWORK_SCANNER.md), [Security Design](docs/SECURITY_DESIGN.md), and [Installation](docs/INSTALLATION.md) for deployment details and limitations.

## Repository and deployment

The source project is currently named `DarkByteX-288-AI-Driven-Cyber-Security-Toolkit` on GitHub. Application rebranding does not rename the repository; repository renaming is a separate owner-controlled GitHub operation.

This application should be deployed behind a trusted TLS-terminating reverse proxy with a production WSGI server and shared rate-limit storage. The current background scan executor is in-process; deployments using multiple web workers need a shared task queue and coordination mechanism before scaling scanner concurrency across workers.
