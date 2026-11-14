# Network Vulnerability Assessment

## Authorized-use boundary

The scanner is for assets the operator is authorized to assess. Each request requires `authorization_confirmed: true`; targets are restricted to `BASTIONIX_APPROVED_NETWORKS`, defaulting to RFC1918 IPv4 and IPv6 unique-local ranges. A public range is not approved by default. Operators may explicitly configure asset ranges they control. The scanner has no exploit, NSE script, credential, stealth, or denial-of-service mode.

The `safe` profile uses TCP connect scanning and bounded light TCP service/version detection (`-sT -sV --version-light -T3 --max-retries 1 --host-timeout 60s`). Loopback is rejected by default. If the operator both approves a loopback CIDR and explicitly enables the loopback setting, the app adds `-Pn` for those loopback-only addresses because Windows cannot reliably discover its own loopback without Npcap. Closed/filtered port observations are not persisted, while host state is retained. The app constructs argument tokens itself, passes a list to `subprocess.Popen` with `shell=False`, limits host count, ports, concurrency, retries, and total scan time, and rejects arbitrary Nmap arguments.

Nmap executable discovery checks `NMAP_PATH`, PATH, and common Windows installation paths. `GET /api/scans/health` distinguishes missing/inaccessible Nmap, failed executable probes, missing Python integration, and operational status. The endpoint never returns the executable's local path.

## API

All routes require an authenticated session and remain subject to CSRF protection and request rate limits.

- `POST /api/scans` — authorize and queue one safe-profile scan.
- `GET /api/scans?page=1` — list the current user's scan history.
- `GET /api/scans/<scan_id>` — retrieve status/progress and completed results.
- `GET /api/scans/<scan_id>/findings/<finding_id>` — retrieve an owner-scoped finding.
- `POST /api/scans/<scan_id>/cancel` — request cancellation of a queued/running scan.
- `GET /api/scans/<scan_id>/report.csv` and `/report.pdf` — export completed owner-scoped results.

Example request (replace the target with an authorized address in your configured private asset range):

```json
{
  "target": "192.168.10.8",
  "ports": [22, 80, 443],
  "profile": "safe",
  "authorization_confirmed": true
}
```

Ports are optional (a limited common TCP-port set is used by default), unique, and capped at 100. A target can be one IP, CIDR, or DNS hostname. CIDRs are bounded by `BASTIONIX_SCANNER_MAX_HOSTS` (default 64, hard maximum 256). Hostnames must resolve entirely inside approved ranges; DNS lookups have a three-second deadline, and the worker rechecks DNS and scans only the pinned IP addresses. Lookup errors and timeouts fail closed. Loopback, link-local, reserved, unspecified, and multicast addresses are rejected.

Each user is limited to one active scan and three scan starts per hour. Global active scans and worker count are configurable; the built-in executor is single-process. Queued/running work cannot be recovered after application restart.

## Findings and CVE intelligence

Open ports/services are informational observations, not vulnerabilities. Product/version keyword matches from the NVD API are classified **potential** and include CVE ID, NVD description, references, CVSS score/severity when present, and cautious remediation guidance. BastionIX does not assert confirmed vulnerability findings based only on a banner or keyword result. Validate applicability against the vendor advisory and exact product build.

NVD requests use a fixed NVD endpoint, a short timeout, limited result count, a maximum of ten unique product/version lookups per scan, optional `NVD_API_KEY`, and a six-hour process-local cache. Service records distinguish available, unavailable, rate-limited, and lookup-limit outcomes from no returned CVE matches. Rate-limit, network, malformed-response, or offline conditions do not block scan completion. There is no fabricated fallback CVE data.

## Installation and troubleshooting

Install the Nmap binary separately and confirm `nmap --version` works from the same account/environment that runs Flask. If absent or not launchable, scan creation returns HTTP 503 with an installation diagnostic. DNS, target-scope, host-count, or port validation failures return HTTP 400. Concurrent/rate limits return 409/429. Detailed scan failures are persisted on the owning scan and in audit records.

Automated tests mock Nmap and NVD; they do not scan actual networks. See `docs/SECURITY_DESIGN.md` for limits and remaining deployment constraints.
