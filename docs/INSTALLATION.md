# Installation

## Requirements

- Python 3.11 (verified runtime).
- A supported relational database; SQLite remains the default.
- Nmap system executable installed separately from Python packages.
- A production `SECRET_KEY` and a database backup before schema upgrade.

## Install

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-lock.txt
Copy-Item .env.example .env
```

### Install the Nmap executable separately

- **Windows:** Use the signed self-installer linked from [the official Nmap download page](https://nmap.org/download.html). Verify the publisher is Nmap Software LLC. If Nmap is not added to PATH, set `NMAP_PATH` to the installed `nmap.exe` path (commonly `C:\Program Files (x86)\Nmap\nmap.exe`). Npcap and registry performance changes are not required for BastionIX's unprivileged TCP connect scans.
- **Debian/Ubuntu:** `sudo apt install nmap`.
- **Fedora/RHEL-family:** `sudo dnf install nmap`.
- **macOS:** Install the official `.dmg` linked from [nmap.org/download.html](https://nmap.org/download.html), or use a trusted platform package manager.

Verify the executable in the same account/environment that runs Flask:

```powershell
nmap --version
# If it is not on PATH:
$env:NMAP_PATH = 'C:\Program Files (x86)\Nmap\nmap.exe'
```

`python-nmap` is the Python integration/parser and does not install the Nmap executable. The authenticated `GET /api/scans/health` endpoint reports the executable version and Python integration status without disclosing local paths.

Loopback remains disabled by default. Only for an isolated local verification database, set `BASTIONIX_APPROVED_NETWORKS=127.0.0.1/32` and `BASTIONIX_SCANNER_ALLOW_LOOPBACK=true`; remove these settings afterward. That restricted loopback profile uses `-sT -Pn` so no Npcap driver or system network setting is needed.

## Configure and run

Copy `.env.example` to `.env`. Without an explicit `FLASK_ENV`, BastionIX defaults to production and refuses to start without a strong environment-provided key. For local development, set `FLASK_ENV=development`; an ephemeral random key is used if no development key is supplied.

Generate and set a production secret using the deployment's secret manager:

```powershell
$env:FLASK_ENV = "production"
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
# Optional: replace private defaults with explicitly authorized asset CIDRs.
$env:BASTIONIX_APPROVED_NETWORKS = "10.20.0.0/16,192.168.10.0/24"
python -m flask db upgrade
```

Use `flask run` only for local development after setting `FLASK_ENV=development`; never use the Flask development server in production. Production has `DEBUG=False` and secure session cookies. `.env` and `.flaskenv` are local-only and ignored by Git; commit only the empty-value `.env.example`. `BASTIONIX_SCANNER_MAX_HOSTS` defaults to 64 and cannot exceed 256. Scanner worker and active-scan limits are configured with `BASTIONIX_SCANNER_WORKERS` and `BASTIONIX_SCANNER_MAX_ACTIVE`.

The migration baseline is additive and idempotent for the current legacy schema. Back up existing `instance/database.db` before upgrading. Development no longer creates production schema changes implicitly; use migrations. Unit tests use a separate in-memory database.

## Tests and dependency check

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m pip_audit -r requirements.txt
```

The scanner suite uses fake Nmap/NVD results and does not perform live network access.
