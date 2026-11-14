# Database Design

## Existing tables

The existing `users`, `settings`, `password_analysis`, `url_analysis`, `attack_logs`, and `system_logs` tables are retained. The first Alembic revision is an idempotent legacy baseline: existing tables are left intact, while a fresh installation receives the current original schema. The next revision adds scanner tables. Back up the database before applying migrations.

## Scanner entities

| Table | Purpose and relationships |
|---|---|
| `network_scans` | Owner, submitted/pinned target, ports/profile, authorization, lifecycle, progress, timestamps, and failure message |
| `network_hosts` | Per-scan discovered host and state; unique by scan/address |
| `network_ports` | TCP port state/reason; unique by host/protocol/port and constrained to 1–65535 |
| `detected_services` | One service fingerprint per port: name/product/version/CPE |
| `vulnerability_findings` | Informational or potential finding with CVSS version/score; indexed by scan/severity and CVE |
| `cve_references` | NVD CVE description, CVSS version/score, severity, references, and source |
| `scan_configurations` | One stored safe-profile/configuration snapshot per scan, including approved ranges and authorization statement |
| `scan_audit_logs` | Scan/user action history, event, source peer address, and timestamp |

Scans belong to a user and have a cascading ORM relationship. Every API lookup filters by the authenticated owner. Host and port rows cascade from scans; user delete-orphan behavior is consistent with the existing models. CVEs are shared reference data; findings link to their scan, port, and optional CVE.

## Migration procedure

Apply with `python -m flask db upgrade`. The revisions are designed to handle both the legacy database (tables already present and no Alembic version row) and a fresh database. The legacy baseline is intentionally non-destructive on downgrade so existing account and analysis tables are never dropped by rolling back scanner changes. The scanner revision's downgrade removes only the newly added assessment tables.

## Constraints, timestamps, and indexes

Scan/event timestamps use UTC-aware Python defaults; SQLite may store them without timezone metadata. User, scan status, creation time, scan/host state, port, finding severity/CVE, and audit ownership/time columns are indexed where they are used for listing and lookups. Constraints prevent duplicate host/port records and invalid port numbers.

Database checks limit scan states to the lifecycle values, require explicit authorization and the fixed safe profile, bound progress to 0–100, permit TCP ports only, and constrain CVSS scores to 0–10. Finding classifications are limited to informational, potential, or confirmed; current scanner output creates no confirmed findings from version matches.

Migration `20261114_0003` adds nullable `cvss_version` fields to CVE references and findings, preserving all prior rows.
