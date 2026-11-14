# Security Design

## Authentication and ownership

Existing Flask-Login sessions and CSRF protection remain enabled. Production startup fails without `SECRET_KEY`; development and testing use environment-specific non-production secrets. The login redirect accepts local paths only. Logout is POST-only. Scanner APIs require authentication, explicit authorization confirmation, and scan ownership for status, findings, cancellation, and report access.

## Target and process controls

- Private RFC1918 IPv4 and IPv6 ULA ranges are the default allowlist; additional networks must be explicitly configured by the operator. Loopback is separately rejected unless the operator both approves a loopback CIDR and enables `BASTIONIX_SCANNER_ALLOW_LOOPBACK`.
- Hostname DNS answers are validated against the allowlist and revalidated in the background worker; the worker uses pinned IP literals, preventing a later DNS answer from redirecting the scan.
- Loopback, link-local, reserved, unspecified, and multicast addresses are rejected.
- Host, port, concurrency, user start rate, per-host timeout, total timeout, retry, and scanner argument sets are bounded.
- Nmap's executable is verified separately. Commands use an argument list, fixed options, and `shell=False`; user-supplied command-line flags are not accepted.
- The authenticated health endpoint independently reports Nmap executable and Python integration states, without returning the local executable path. The Windows-compatible TCP connect mode does not require raw packet privileges; loopback alone adds `-Pn`.
- Nmap output is parsed with `python-nmap`. Cancellation terminates the active process.
- No exploit scripts, credential attacks, password cracking, stealth scanning, destructive checks, or denial-of-service profiles are implemented.

## Vulnerability intelligence

NVD results are potential keyword matches only. CVSS metric version and score are persisted; severity bands use CVSS 2.0's High ceiling (no Critical category) or the applicable CVSS 3.x/4.0 bands. An unavailable API does not block the scan and is not reported as absence of vulnerabilities. Open services are informational; scanner output does not establish exploitability.

## Audit and report safety

Scan creation, authorization, cancellation, completion, and failure events are persisted. Client IP logging uses the transport peer rather than trusting arbitrary `X-Forwarded-For`. Network CSV values are escaped against spreadsheet formula interpretation; PDF markup is HTML-escaped. Existing URL CSV export receives the same formula-injection defense.

## Deployment constraints and residual risks

The built-in background executor, active-scan lock, and NVD cache are process-local. Multiple WSGI worker processes can race limits and do not share cancellation state; production multi-worker deployments require a shared queue and distributed coordination. The Flask-Limiter default backend remains in-memory unless `RATELIMIT_STORAGE_URI` is set to a shared supported backend. Put production behind TLS, use a hardened WSGI server and filesystem permissions, protect NVD credentials, and keep model pickle artifacts immutable and trusted. The existing model retraining operation is still synchronous and available to any authenticated user; it should be restricted or moved to an administrative task before multi-user production exposure.
