# BastionIX Initial Technical Audit

**Audit scope:** existing workspace at `D:\project\attaullah-main\project`

**Audit date:** 2026-11-14

**Baseline:** existing application files and the checked-in SQLite schema were reviewed before implementation changes.

## Current architecture

The application is a single Flask package with an application factory in `app.py`. It initializes Flask-SQLAlchemy, Flask-Migrate, Flask-WTF CSRF, Flask-Limiter, and Flask-Login, then registers seven blueprints. However, the factory calls `db.create_all()` on every startup, so the migration extension is initialized without an actual migration workflow. Routes currently perform much of the persistence and orchestration themselves. Password and URL analysis logic lives in `services/`, model training/loading in `ml/`, and form, security logging, and report helpers in `utils/`.

The browser UI is server-rendered Jinja with Bootstrap, Chart.js, Font Awesome, a single stylesheet, and two JavaScript files. The runtime database is SQLite under `instance/database.db`; generated datasets and two Joblib model bundles are stored under `datasets/` and `trained_models/`.

The workspace has an outer directory with `.idea`, `.venv`, `venv`, and `project`; the actual source is in `project`. Neither the workspace root nor `project` contains a `.git` directory, so branch status and a Git diff cannot be inspected here. The project includes a persistent SQLite database and trained binary model files.

## Existing functionality

- Registration, login/logout, remember-me, profile, and per-user settings.
- Password analysis using deterministic features, a heuristic score, a lazily loaded RandomForest model, attack-time estimates, and recommendations. The raw password is not part of the persisted schema.
- URL analysis using local structural/domain heuristics and a calibrated model. Optional TLS and redirect checks are off by default; optional threat-intelligence providers require environment credentials.
- Per-user dashboard analytics, analysis history/search/filter/delete, CSV exports, a summary PDF, theme selection, history deletion, and model retraining.
- Synthetic data generation and training/evaluation pipelines for password and phishing-URL models.
- Two existing test modules cover password service behavior and URL parsing/inference boundaries.

## Technology stack

Python 3.12 is stated in the README, while the available workspace `.venv` reports Python 3.11.7. The application uses Flask 3.0.3, Flask-SQLAlchemy 3.1.1, Flask-Login 0.6.3, Flask-Migrate 4.0.7, Flask-WTF 1.2.1, Flask-Limiter 3.8.0, WTForms 3.1.2, Werkzeug 3.0.3, SQLAlchemy 2.0.31, scikit-learn 1.5.1, pandas 2.2.2, NumPy 1.26.4, Joblib 1.4.2, ReportLab 4.2.2, and python-dotenv 1.0.1, all pinned in `requirements.txt`. There is no Nmap dependency or scanner implementation.

## Dependency audit

The requirements are exact pins rather than a resolved transitive lock. The selected direct versions are broadly compatible with Python 3.11 and 3.12; scikit-learn's compatible NumPy/SciPy requirements are left to dependency resolution. No dependency vulnerability audit command or reproducible constraints/lock artifact is configured. The listed versions have not yet been installed and exercised in a clean environment during this audit. The workspace environments are incomplete for baseline testing: pytest and the Flask extensions are missing from the checked environments. Flask-Limiter's memory backend is unsuitable for coordinated multi-worker production rate limiting. The optional XGBoost import is not declared as a dependency and is not required by the training pipeline.

## Security findings (initial pre-implementation baseline)

1. **Production secret fallback:** `config.py` falls back to the publicly predictable `dev-secret-key-change-in-production`; the application can start in production without a configured secret.
2. **Unsafe redirect destination:** login redirects to the raw `next` query parameter without validating that it is local, enabling open redirects.
3. **State-changing logout via GET:** the logout endpoint is a GET route, so it is not protected by form CSRF.
4. **Proxy header trust:** `utils/security.py` trusts the first `X-Forwarded-For` value from any client, allowing forged audit IP addresses unless a trusted-proxy boundary is enforced.
5. **Overbroad retraining access and request cost:** every authenticated account may trigger expensive model training synchronously through a settings POST; the target value is not validated and the endpoint can tie up request workers.
6. **Silent security-log failures:** `log_event` catches every exception and suppresses it, so audit-event persistence failure is invisible.
7. **Pickle trust boundary:** Joblib model loading uses pickle-backed artifacts. Write access to model files can become code execution when the application loads a tampered artifact; artifacts need provenance and filesystem controls.
8. **CSV formula injection risk:** exported user-controlled URL values are written directly to CSV without neutralizing spreadsheet formula prefixes.
9. **Operational protections are incomplete:** rate limiting uses in-memory storage; production cookie flags are configured but there is no trusted-proxy/TLS enforcement or Content-Security-Policy header. Third-party frontend assets are loaded from CDNs without integrity attributes.
10. **Optional URL checks need ongoing guard review:** URL network checks are disabled by default and implement public-address resolution checks, but they make outbound requests and rely on custom socket/HTTP handling. They remain a potential SSRF boundary and must retain DNS validation/pinning and redirect checks.

No exploit or network scan was performed. Findings above are code/configuration observations.

## Database findings

The existing database contains `users`, `settings`, `password_analysis`, `url_analysis`, `attack_logs`, and `system_logs`. Existing history and account tables have user foreign keys and relevant indexes, and settings are unique per user. The existing records can be preserved by additive migrations.

There is no `migrations/` directory, and startup uses `db.create_all()` rather than applying versioned migrations. Several boolean/default and timestamp columns rely on ORM defaults without database-level constraints. There are no scanner tables, scan ownership concepts, scan status constraints, or scan audit records.

## Performance findings

- The dashboard loads all password and URL histories multiple times for chart counts and averages, so response work grows with total history.
- History queries load all matching rows and have no pagination.
- Model training and retraining run synchronously in web requests. Missing URL models can trigger full dataset preparation, candidate training, and evaluation inside inference.
- Password and URL models are cached in process memory, but multiple app workers each load a copy.
- Rate limit state is process-local; there is no task queue, scan worker, or cancellation mechanism.

## Technical debt and incomplete features

- Branding remains “AI Cyber Security Toolkit” in config, UI, reports, and documentation; no dedicated tagline is present.
- There is no network vulnerability scanner, Nmap integration, background execution, scan progress, CVE intelligence service, or scan report.
- `Flask-Migrate` is initialized but migrations are not authored/applied; no clean-install/upgrade tests are present.
- Existing routes combine request handling, business orchestration, serialization, and persistence.
- Several settings actions are callable by any logged-in user; admin role management is not modeled.
- Existing tests are limited to service-level password and URL tests; there are no Flask route, authentication, report, migration, or settings regression tests.
- Model fallback behavior may silently hide inference failures in password analysis, while URL analysis records them; retraining exceptions are caught at the route.
- README language overstates some behavior (for example automatic database creation/training is uneven: password model auto-generation exists, while URL training expects its source dataset).

## Proposed modifications

1. Preserve existing tables and behavior while adding versioned, additive migrations and regression coverage.
2. Rebrand the app to BastionIX 1.0.0, including page metadata, settings, report headers, and structured logging.
3. Harden authentication/configuration defaults, audit logging, CSV exports, request validation, and production settings.
4. Add a private-scope-by-default scanner that validates authorization, target ranges, DNS results, scan duration, host/port limits, ownership, cancellation, and audit records before any Nmap subprocess invocation. Run it outside request threads using a bounded background mechanism and safe argument arrays.
5. Keep vulnerability matching evidence-based and clearly label version-based CVE matches as potential; cache NVD responses and tolerate offline/rate-limited operation.
6. Add owner-scoped scan APIs/history and CSV/PDF reporting, with mocked scanner tests and no live network scans in the automated suite.
7. Resolve dependencies for the supported Python version, add a tested constraints/lock artifact and a dependency audit workflow, and document external Nmap installation independently from Python packages.
8. Deliver architecture, scanner, security, database, installation, dependency, and phase completion documentation, reporting unverified checks and remaining limitations honestly.

## Final follow-up audit — 2026-11-14

This section records the final review against the current Phase 1 implementation; it does not rewrite the historical baseline above.

### Environment and synchronization

- Windows 11 Pro 64-bit, build 26200; PowerShell 5.1.
- The selected application/test interpreter is `.phase1-nmap-venv\Scripts\python.exe`, Python 3.11.7, with `python-nmap` 0.7.1 and all pinned runtime/development requirements. The other existing virtual environments were left untouched.
- Nmap 7.993 was detected through the current user's PATH, though not in the long-running agent shell's inherited PATH. `NMAP_PATH` is now set in the current Windows user's environment to the detected executable. The Npcap service is running; the Nmap binary reports it was compiled with Npcap 1.90, but the installed driver version was not independently identified. Npcap is not needed by TCP connect mode. No machine PATH, registry, driver, or security settings were changed.
- The project source directory has no `.git` metadata. GitHub `main` was inspected and the Phase 1 implementation was published from a clean clone of the verified remote; see the final acceptance report for the current SHA.

### Current implementation and security disposition

- Authentication, owner-scoped analysis/history, CSRF, POST-only logout, local-only login redirects, safe CSV exports, scanner authorization/ownership, scoped target validation, bounded subprocess execution, scan cancellation, and report access have regression coverage.
- A security review found that an unset `FLASK_ENV` selected development with a known signing key. The current fix defaults to production, rejects missing/short/known weak production keys, rejects `FLASK_DEBUG` overrides in production, forces production debug off, and uses an ephemeral random development key. Regression tests cover these cases.
- `.env.example` contains placeholders only. `.env`, `.flaskenv`, databases, virtual environments, caches, and logs are ignored. The pre-existing tracked `.flaskenv` and `app_start.log` are removed from Git tracking; local source copies are not deleted.
- The Nmap integration review found a missing maximum-host check for multi-address DNS answers. The validator now caps unique resolved addresses at `max_hosts`; the worker revalidates the target before execution. Closed/filtered port states are persisted without generating vulnerability findings for non-open ports.
- Remaining deployment risks include the in-process scan executor and cache, in-memory default rate-limit storage, synchronous model retraining available to authenticated users, and the need for TLS and trusted production WSGI deployment.
- The authenticated scanner health endpoint returned operational on the real Nmap executable without disclosing its path. An actual local HTTP workflow completed a real scan of only `127.0.0.1` TCP 22, 80, and 443; all were closed, and all three states were parsed, persisted, returned in history, and included in CSV/PDF reports. No NVD request was necessary because no open, versioned service was found.
- The complete suite passes 104 tests; compile, dependency consistency and audits, and disposable migration upgrade/downgrade/re-upgrade checks passed. Live NVD and interactive browser/mobile testing were not performed; automated NVD tests are mocked.
