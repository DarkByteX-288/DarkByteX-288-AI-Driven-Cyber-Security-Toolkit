# BastionIX Architecture

## Application layout

The existing Flask application factory remains the entry point (`app.py`). `config.py` separates development, testing, and production configuration; Flask extensions are initialized by the factory. Production requires an explicit secret and migrations are applied with Flask-Migrate rather than implicitly changing the schema at startup.

| Area | Responsibility |
|---|---|
| `routes/` | HTTP validation, authentication, user ownership, API responses, downloads |
| `models/` | SQLAlchemy persistence, relationships, indexes, and scan ownership |
| `services/` | Password and URL analysis, NVD lookup, scanner orchestration, reports |
| `scanners/` | Target scope, DNS, authorization, and port validation |
| `ml/` | Existing model loading, training, and evaluation |
| `tasks/` | Bounded in-process scan execution and persisted task lifecycle |
| `utils/` | Forms, audit helpers, and PDF/CSV generation |
| `migrations/` | Additive Alembic revisions |
| `tests/` | Unit and Flask-client tests using mocked external scanner/intelligence responses |

## Network scan flow

1. The authenticated request must confirm authorization and select the supported safe profile.
2. The controller validates the IP/CIDR/hostname, resolves DNS, rejects disallowed addresses, checks approved ranges, validates ports, and checks rate/active-scan limits.
3. BastionIX persists the scan, configuration, and authorization audit event before submitting bounded background work.
4. The worker re-resolves the submitted target and verifies the result still matches the pinned authorized addresses.
5. Nmap is invoked with fixed argument tokens and no shell. `python-nmap` verifies/normalizes Nmap XML output; arbitrary arguments are never accepted.
6. Host/service observations and informational findings are saved. NVD matches are marked potential, cached in process, and linked to references.
7. Status/progress/results are accessible only to the scan owner; cancellation signals the worker and terminates the Nmap process.

The background executor is in-process and bounded. It is suitable for a single application process with the current deployment model. It is not a distributed queue: multiple WSGI workers can race active-scan checks, and queued/running work is not resumed after a process restart. Use a shared task queue and distributed locking before scaling the scanner across workers.

The authenticated scanner health endpoint probes the actual Nmap executable and Python integration separately. `NMAP_PATH` can explicitly identify the executable; automatic PATH and common Windows installation-path discovery remain enabled. Loopback is opt-in and requires both an explicit approved CIDR and `BASTIONIX_SCANNER_ALLOW_LOOPBACK=true`.

## Existing capabilities

Authentication, per-user settings, password evaluation/attack estimates, URL risk analysis, dashboard analytics, analysis history, reports, and ML model management remain in their existing modules. Existing tables are preserved by the baseline migration; scanner storage is additive.

## Configuration and dependencies

Runtime packages are pinned in `requirements.txt`; the complete tested Python 3.11 environment is `requirements-lock.txt`. Development/audit tools are separated into `requirements-dev.txt`. Nmap's Python adapter does not install the operating-system Nmap executable.
